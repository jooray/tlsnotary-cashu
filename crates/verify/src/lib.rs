//! Verification of tlsnotary-cashu presentations.
//!
//! A presentation proves that some bytes were sent to and received from a
//! TLS server, as attested by a notary. Verifying it means checking three
//! things, all done here:
//!
//! 1. the notary's signature, against keys the relying party chose to trust
//!    (and the time window each key was valid for);
//! 2. the server identity: certificate chain to a Mozilla root, hostname and
//!    the handshake signature, at the time of the connection;
//! 3. the transcript proof: the revealed bytes match the attested commitments.
//!
//! Nothing here talks to the network.

use serde::{Deserialize, Serialize};
use tlsn_attestation::{
    CryptoProvider,
    presentation::{Presentation, PresentationOutput},
};
use tlsn_core::{connection::ServerName, transcript::InvalidTranscriptLength};
pub use tlsnc_protocol::NotaryKeyInfo;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a presentation: {0}")]
    Decode(String),
    #[error("signed by an untrusted notary key {alg}:{key}")]
    UntrustedKey { alg: String, key: String },
    #[error("notary key {key} was not valid at {time} (window {from:?}..{until:?})")]
    KeyOutsideWindow {
        key: String,
        time: u64,
        from: Option<u64>,
        until: Option<u64>,
    },
    #[error("invalid presentation: {0}")]
    Invalid(String),
    #[error("the presentation does not disclose the server identity")]
    NoServerIdentity,
}

/// What a valid presentation proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    pub notary_key: NotaryKeyInfo,
    /// The server the prover talked to (certificate checked).
    pub server_name: String,
    /// Unix seconds when the TLS connection was made, as recorded by the
    /// notary.
    pub time: u64,
    /// Bytes sent, undisclosed bytes replaced by `mask`.
    pub sent: String,
    /// Bytes received, undisclosed bytes replaced by `mask`.
    pub received: String,
    /// Disclosed ranges of `sent` / `received`, as `[start, end)` pairs.
    pub sent_disclosed: Vec<(usize, usize)>,
    pub received_disclosed: Vec<(usize, usize)>,
    pub mask: char,
}

/// Default character for undisclosed bytes.
pub const MASK: u8 = b'X';

/// tlsn names the curve `k256`; `secp256k1` is accepted as an alias.
fn same_alg(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let s = s.to_ascii_lowercase();
        if s == "secp256k1" { "k256".to_string() } else { s }
    };
    norm(a) == norm(b)
}

fn find_trusted<'a>(trusted: &'a [NotaryKeyInfo], alg: &str, key: &str) -> Option<&'a NotaryKeyInfo> {
    trusted
        .iter()
        .find(|k| same_alg(&k.alg, alg) && k.key.eq_ignore_ascii_case(key))
}

/// Verifies a bincode-serialized presentation.
pub fn verify(presentation: &[u8], trusted: &[NotaryKeyInfo]) -> Result<Verified, Error> {
    let presentation: Presentation =
        bincode::deserialize(presentation).map_err(|e| Error::Decode(e.to_string()))?;
    verify_presentation(&presentation, trusted)
}

pub fn verify_presentation(
    presentation: &Presentation,
    trusted: &[NotaryKeyInfo],
) -> Result<Verified, Error> {
    let vk = presentation.verifying_key();
    let alg = vk.alg.to_string();
    let key = hex::encode(&vk.data);
    let pinned = find_trusted(trusted, &alg, &key)
        .ok_or_else(|| Error::UntrustedKey {
            alg: alg.clone(),
            key: key.clone(),
        })?
        .clone();

    let provider = CryptoProvider::default();
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .clone()
        .verify(&provider)
        .map_err(|e| Error::Invalid(e.to_string()))?;

    let time = connection_info.time;
    if pinned.valid_from.is_some_and(|from| time < from)
        || pinned.valid_until.is_some_and(|until| time > until)
    {
        return Err(Error::KeyOutsideWindow {
            key,
            time,
            from: pinned.valid_from,
            until: pinned.valid_until,
        });
    }

    let ServerName::Dns(server_name) = server_name.ok_or(Error::NoServerIdentity)?;

    let (sent, received, sent_disclosed, received_disclosed) = match transcript {
        Some(t) => {
            // Expanded to the lengths the notary signed, never to the
            // lengths the transcript itself claims.
            let len = &connection_info.transcript_length;
            let invalid = |e: InvalidTranscriptLength| Error::Invalid(e.to_string());
            let sent = masked(t.sent_unsafe(len.sent as usize).map_err(invalid)?, t.sent_authed());
            let received = masked(t.received_unsafe(len.received as usize).map_err(invalid)?, t.received_authed());
            (sent, received, ranges(t.sent_authed()), ranges(t.received_authed()))
        }
        None => (String::new(), String::new(), Vec::new(), Vec::new()),
    };

    Ok(Verified {
        notary_key: pinned,
        server_name: server_name.as_str().to_string(),
        time,
        sent,
        received,
        sent_disclosed,
        received_disclosed,
        mask: MASK as char,
    })
}

/// The bytes as text, with every position outside `authed` shown as [`MASK`].
fn masked(mut bytes: Vec<u8>, authed: &rangeset::set::RangeSet<usize>) -> String {
    let mut shown = vec![false; bytes.len()];
    for r in authed.iter() {
        shown[r.start.min(bytes.len())..r.end.min(bytes.len())].fill(true);
    }
    for (b, shown) in bytes.iter_mut().zip(shown) {
        if !shown {
            *b = MASK;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn ranges(set: &rangeset::set::RangeSet<usize>) -> Vec<(usize, usize)> {
    set.iter().map(|r| (r.start, r.end)).collect()
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Verifies a presentation. `trusted_keys` is a JSON array of
    /// `{alg, key, valid_from?, valid_until?}`; returns the JSON of
    /// [`super::Verified`] or throws.
    #[wasm_bindgen(js_name = verifyPresentation)]
    pub fn verify_presentation(presentation: &[u8], trusted_keys: &str) -> Result<String, JsError> {
        let trusted: Vec<super::NotaryKeyInfo> = serde_json::from_str(trusted_keys)
            .map_err(|e| JsError::new(&format!("trusted keys: {e}")))?;
        let verified = super::verify(presentation, &trusted).map_err(|e| JsError::new(&e.to_string()))?;
        serde_json::to_string(&verified).map_err(|e| JsError::new(&e.to_string()))
    }
}
