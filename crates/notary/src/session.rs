//! One notarization session, notary side.
//!
//! The flow is upstream's `examples/attestation/prove.rs` (the `notary`
//! function), plus enforcement of the ticket: tier limits, and proxy mode
//! only for notary-egress tickets, through the egress policy.

use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite};
use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, request::Request as AttestationRequest,
        signing::Secp256k1Signer,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tlsnc_protocol::{Egress, TierInfo};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info};

use crate::egress::{self, Capped};

/// Extra bytes allowed through a notary-egress connection on top of the
/// tier's application data: TLS handshake, record framing, certificates.
pub const EGRESS_SLACK_UP: usize = 16 * 1024;
pub const EGRESS_SLACK_DOWN: usize = 64 * 1024;

pub struct SessionCtx {
    pub tier: TierInfo,
    pub ticket_egress: Egress,
    pub egress: Arc<egress::Egress>,
    pub signing_key: [u8; 32],
}

/// Which protocol the prover chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Mpc,
    Proxy,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Mpc => "mpc",
            Mode::Proxy => "proxy",
        }
    }
}

/// Record-count caps: four times the upstream default estimate (8 records
/// for the first 4 KiB, then one per 4 KiB).
fn record_cap(bytes: usize) -> usize {
    4 * (8 + bytes / 4096)
}

/// Checks an MPC commit against the tier. `Err` is the message sent to the
/// prover with the rejection.
pub fn check_mpc(cfg: &tlsn::config::tls_commit::mpc::MpcTlsConfig, tier: &TierInfo) -> Result<(), String> {
    if cfg.max_sent_data() > tier.max_sent {
        return Err(format!(
            "max_sent_data {} exceeds tier {} limit {}",
            cfg.max_sent_data(),
            tier.id,
            tier.max_sent
        ));
    }
    if cfg.max_recv_data() > tier.max_recv {
        return Err(format!(
            "max_recv_data {} exceeds tier {} limit {}",
            cfg.max_recv_data(),
            tier.id,
            tier.max_recv
        ));
    }
    if cfg.max_recv_data_online() > tier.max_recv_online {
        return Err(format!(
            "max_recv_data_online {} exceeds tier {} limit {}",
            cfg.max_recv_data_online(),
            tier.id,
            tier.max_recv_online
        ));
    }
    if cfg.max_sent_records().is_some_and(|n| n > record_cap(tier.max_sent)) {
        return Err("max_sent_records too large".into());
    }
    if cfg
        .max_recv_records_online()
        .is_some_and(|n| n > record_cap(tier.max_recv_online))
    {
        return Err("max_recv_records_online too large".into());
    }
    Ok(())
}

pub fn provider(signing_key: &[u8; 32]) -> Result<CryptoProvider, String> {
    let signer = Secp256k1Signer::new(signing_key).map_err(|e| e.to_string())?;
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(Box::new(signer));
    Ok(provider)
}

/// Runs the session to completion. On success the prover holds a signed
/// attestation.
pub async fn run<S>(io: S, ctx: &SessionCtx) -> Result<Mode, String>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(io);
    let (driver, mut handle) = session.split();
    let driver = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .map_err(|e| e.to_string())?;
    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(|e| e.to_string())?;

    let commit = verifier.commit().await.map_err(|e| format!("commit: {e}"))?;
    let (mode, verifier) = match commit {
        VerifierCommitStart::Mpc(v) => {
            if let Err(msg) = check_mpc(v.config(), &ctx.tier) {
                let _ = v.reject(Some(&msg)).await;
                return Err(msg);
            }
            info!(
                tier = %ctx.tier.id,
                max_sent = v.config().max_sent_data(),
                max_recv = v.config().max_recv_data(),
                "accepting MPC-TLS session"
            );
            let v = v
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?
                .run()
                .await
                .map_err(|e| format!("mpc-tls: {e}"))?;
            (Mode::Mpc, v)
        }
        VerifierCommitStart::Proxy(v) => {
            if !ctx.ticket_egress.covers(Egress::Notary) {
                let msg = "proxy mode connects from the notary: it needs an egress=notary ticket";
                let _ = v.reject(Some(msg)).await;
                return Err(msg.into());
            }
            let host = v.config().server_name().as_str().to_string();
            let stream = match ctx.egress.connect(&host).await {
                Ok(s) => s,
                Err(e) => {
                    let msg = e.to_string();
                    let _ = v.reject(Some(&msg)).await;
                    return Err(msg);
                }
            };
            info!(tier = %ctx.tier.id, %host, "accepting proxy-mode session");
            let stream = Capped::new(
                stream,
                ctx.tier.max_sent + EGRESS_SLACK_UP,
                ctx.tier.max_recv + EGRESS_SLACK_DOWN,
            );
            let v = v
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?
                .run(stream.compat())
                .await
                .map_err(|e| format!("proxy: {e}"))?;
            (Mode::Proxy, v)
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier
        .verify()
        .await
        .map_err(|e| format!("verify: {e}"))?
        .accept()
        .await
        .map_err(|e| format!("verify: {e}"))?;
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await.map_err(|e| format!("close: {e}"))?;
    handle.close();
    let mut io = driver
        .await
        .map_err(|e| format!("session task: {e}"))?
        .map_err(|e| format!("session: {e}"))?;

    let app_data_len = |records: &[tlsn::transcript::Record]| -> u32 {
        records
            .iter()
            .filter(|r| matches!(r.typ, ContentType::ApplicationData))
            .map(|r| r.ciphertext.len())
            .sum::<usize>() as u32
    };
    let sent_len = app_data_len(tls_transcript.sent());
    let recv_len = app_data_len(tls_transcript.recv());

    let request_bytes = tlsnc_protocol::read_frame(&mut io)
        .await
        .map_err(|e| format!("attestation request: {e}"))?;
    let result = build_attestation(&request_bytes, &tls_transcript, sent_len, recv_len, transcript_commitments, ctx);
    match &result {
        Ok(bytes) => tlsnc_protocol::write_reply(&mut io, Ok(bytes)).await,
        Err(msg) => tlsnc_protocol::write_reply(&mut io, Err(msg)).await,
    }
    .map_err(|e| format!("sending attestation: {e}"))?;
    let _ = futures::AsyncWriteExt::close(&mut io).await;
    result.map(|_| mode)
}

fn build_attestation(
    request_bytes: &[u8],
    tls_transcript: &tlsn::transcript::TlsTranscript,
    sent_len: u32,
    recv_len: u32,
    transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    ctx: &SessionCtx,
) -> Result<Vec<u8>, String> {
    let request: AttestationRequest =
        bincode::deserialize(request_bytes).map_err(|e| format!("bad attestation request: {e}"))?;
    let provider = provider(&ctx.signing_key)?;

    let mut config = AttestationConfig::builder();
    config.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let config = config.build().map_err(|e| e.to_string())?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        return Err("unsupported certificate binding (TLS 1.2 only)".into());
    };
    let mut builder = Attestation::builder(&config)
        .accept_request(request)
        .map_err(|e| format!("attestation request rejected: {e}"))?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len,
                received: recv_len,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider).map_err(|e| e.to_string())?;
    debug!("attestation signed");
    bincode::serialize(&attestation).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn::config::tls_commit::mpc::MpcTlsConfig;

    fn tier() -> TierInfo {
        TierInfo {
            id: "S".into(),
            max_sent: 4096,
            max_recv: 1 << 20,
            max_recv_online: 16 * 1024,
            timeout_secs: 180,
            price: tlsnc_protocol::Prices { client: 42, notary: 210 },
        }
    }

    #[test]
    fn tier_limits() {
        let ok = MpcTlsConfig::builder().max_sent_data(4096).max_recv_data(1 << 20).build().unwrap();
        assert!(check_mpc(&ok, &tier()).is_ok());
        let big = MpcTlsConfig::builder().max_sent_data(8192).max_recv_data(1024).build().unwrap();
        assert!(check_mpc(&big, &tier()).unwrap_err().contains("max_sent_data"));
        let online = MpcTlsConfig::builder()
            .max_sent_data(1024)
            .max_recv_data(1024)
            .max_recv_data_online(1 << 20)
            .build();
        // The builder itself may refuse online > total; either way it must not pass.
        if let Ok(online) = online {
            assert!(check_mpc(&online, &tier()).is_err());
        }
    }
}
