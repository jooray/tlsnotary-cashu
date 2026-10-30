//! Wire types shared by the notary server and its clients.
//!
//! Everything here is plain serde data plus the small framing used after the
//! tlsn session ends, so it builds for native targets and for wasm alike.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

/// Version of this service's own protocol (tickets, framing, endpoints).
pub const PROTOCOL: &str = "tlsnc/1";

/// The upstream `tlsn` build both sides must run: its version plus the git
/// revision pinned in Cargo.toml. Builds are not wire-compatible, so clients
/// refuse a notary advertising anything else.
pub const TLSN_VERSION: &str = "0.1.0-alpha.16-pre+24b10ba";

/// Largest frame accepted after the tlsn session (attestation request or
/// attestation). Real ones are a few KiB.
pub const MAX_FRAME: usize = 1 << 20;

/// Who opens the TCP connection to the target server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Egress {
    /// The prover connects to the target itself (MPC-TLS). Our IP never
    /// appears at the target.
    Client,
    /// The notary connects to the target: the browser bridge or tlsn proxy
    /// mode. Traffic leaves from our IP.
    Notary,
}

impl Egress {
    /// Whether a ticket bought for `self` may be used for a session that
    /// needs `needed`. A notary-egress ticket is strictly more than a
    /// client-egress one.
    pub fn covers(self, needed: Egress) -> bool {
        self == Egress::Notary || needed == Egress::Client
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Egress::Client => "client",
            Egress::Notary => "notary",
        }
    }
}

impl std::str::FromStr for Egress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "client" => Ok(Egress::Client),
            "notary" => Ok(Egress::Notary),
            other => Err(format!("unknown egress `{other}` (expected client or notary)")),
        }
    }
}

/// Price of one session in each egress class, in the notary's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prices {
    pub client: u64,
    pub notary: u64,
}

impl Prices {
    pub fn for_egress(&self, egress: Egress) -> u64 {
        match egress {
            Egress::Client => self.client,
            Egress::Notary => self.notary,
        }
    }
}

/// A session size class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierInfo {
    pub id: String,
    /// Maximum application data the prover may send (the HTTP request).
    pub max_sent: usize,
    /// Maximum application data the prover may receive (the HTTP response).
    pub max_recv: usize,
    /// Maximum received data that may be decrypted while the connection is
    /// open (online decryption is expensive; responses are normally decrypted
    /// after the connection closes).
    pub max_recv_online: usize,
    pub timeout_secs: u64,
    pub price: Prices,
}

/// A notary signing key as published by the notary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotaryKeyInfo {
    /// Key algorithm as named by tlsn (`k256` for secp256k1).
    pub alg: String,
    /// SEC1-encoded public key, hex.
    pub key: String,
    /// Unix seconds; attestations made before this are not covered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
    /// Unix seconds; attestations made after this must be rejected (rotated
    /// or leaked key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressInfo {
    /// The only port the notary ever connects to.
    pub port: u16,
    /// Sessions per target host per hour that use notary egress.
    pub per_host_per_hour: u32,
}

/// `GET /info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub protocol: String,
    pub tlsn_version: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub unit: String,
    pub mints: Vec<String>,
    pub tiers: Vec<TierInfo>,
    pub notary_key: NotaryKeyInfo,
    #[serde(default)]
    pub previous_keys: Vec<NotaryKeyInfo>,
    pub ticket_ttl_secs: u64,
    pub ticket_attempts: u32,
    pub egress: EgressInfo,
}

impl Info {
    pub fn tier(&self, id: &str) -> Option<&TierInfo> {
        self.tiers.iter().find(|t| t.id == id)
    }

    /// Smallest tier whose limits fit a request of `sent` bytes and an
    /// expected response of `recv` bytes.
    pub fn smallest_tier_for(&self, sent: usize, recv: usize) -> Option<&TierInfo> {
        self.tiers
            .iter()
            .filter(|t| t.max_sent >= sent && t.max_recv >= recv)
            .min_by_key(|t| t.max_sent)
    }

    /// Checks that a client built against this crate can talk to the notary.
    pub fn check_compatible(&self) -> Result<(), String> {
        if self.protocol != PROTOCOL {
            return Err(format!(
                "notary speaks {}, this client speaks {PROTOCOL}",
                self.protocol
            ));
        }
        if self.tlsn_version != TLSN_VERSION {
            return Err(format!(
                "notary runs tlsn {}, this client runs tlsn {TLSN_VERSION}",
                self.tlsn_version
            ));
        }
        Ok(())
    }
}

/// `GET /.well-known/tlsnc-notary.json`: the keys only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnown {
    pub name: String,
    pub keys: Vec<NotaryKeyInfo>,
}

/// `POST /v1/tickets` success body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketResponse {
    pub ticket: String,
    /// Unix seconds.
    pub expires_at: u64,
    pub attempts: u32,
    pub tier: TierInfo,
    pub egress: Egress,
    /// Amount the notary received, net of mint fees.
    pub received: u64,
}

/// JSON body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub error: String,
}

/// Status byte of the notary's final frame.
pub const REPLY_OK: u8 = 0;
pub const REPLY_ERR: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    #[error("empty reply frame")]
    Empty,
}

/// Writes one length-prefixed frame (u32 big-endian length, then payload).
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(payload.len()));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Writes the notary's final reply: status byte, then the attestation or an
/// error message.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    reply: Result<&[u8], &str>,
) -> Result<(), FrameError> {
    let mut buf = Vec::new();
    match reply {
        Ok(bytes) => {
            buf.push(REPLY_OK);
            buf.extend_from_slice(bytes);
        }
        Err(msg) => {
            buf.push(REPLY_ERR);
            buf.extend_from_slice(msg.as_bytes());
        }
    }
    write_frame(w, &buf).await
}

/// Reads the notary's final reply. The outer error is transport, the inner
/// one is the notary's refusal.
pub async fn read_reply<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Result<Vec<u8>, String>, FrameError> {
    let mut frame = read_frame(r).await?;
    if frame.is_empty() {
        return Err(FrameError::Empty);
    }
    let status = frame.remove(0);
    Ok(if status == REPLY_OK {
        Ok(frame)
    } else {
        Err(String::from_utf8_lossy(&frame).into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_coverage() {
        assert!(Egress::Notary.covers(Egress::Client));
        assert!(Egress::Notary.covers(Egress::Notary));
        assert!(Egress::Client.covers(Egress::Client));
        assert!(!Egress::Client.covers(Egress::Notary));
    }

    #[test]
    fn frames_round_trip() {
        futures::executor::block_on(async {
            let mut buf = Vec::new();
            write_reply(&mut buf, Ok(b"attestation")).await.unwrap();
            write_reply(&mut buf, Err("nope")).await.unwrap();
            let mut r = futures::io::Cursor::new(buf);
            assert_eq!(read_reply(&mut r).await.unwrap(), Ok(b"attestation".to_vec()));
            assert_eq!(read_reply(&mut r).await.unwrap(), Err("nope".to_string()));
        });
    }

    #[test]
    fn rejects_oversized_frame() {
        futures::executor::block_on(async {
            let mut r = futures::io::Cursor::new(((MAX_FRAME + 1) as u32).to_be_bytes().to_vec());
            assert!(matches!(read_frame(&mut r).await, Err(FrameError::TooLarge(_))));
        });
    }
}
