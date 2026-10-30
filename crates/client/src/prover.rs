//! Notarizing one HTTPS request with a tlsnotary-cashu notary.
//!
//! The flow is upstream's `examples/attestation/prove.rs`, with two changes:
//! the attestation request and reply are length-prefixed frames instead of a
//! TCP half-close (the notary is reached over a WebSocket), and the target
//! may be reached through tlsn proxy mode.

use futures::{AsyncRead, AsyncWrite};
use http_body_util::BodyExt;
use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider, Secrets,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::{DnsName, HandshakeData, ServerName},
    prover::TlsConnection,
    transcript::TranscriptCommitConfig,
    webpki::RootCertStore,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tracing::{debug, info};

use crate::{
    Error,
    io::{EofGate, HoldEof, HyperIo, OpenOnDrop, spawn},
    request::{HttpRequestSpec, HttpResponse},
};

/// Session limits the prover commits to. They must fit the ticket's tier or
/// the notary rejects the session before any preprocessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_sent: usize,
    pub max_recv: usize,
}

impl From<&tlsnc_protocol::TierInfo> for Limits {
    fn from(t: &tlsnc_protocol::TierInfo) -> Self {
        Limits {
            max_sent: t.max_sent,
            max_recv: t.max_recv,
        }
    }
}

/// How the prover reaches the target server.
pub enum Target<S> {
    /// MPC-TLS over a byte stream the caller opened to the target: a TCP
    /// socket natively, a WebSocket bridge in the browser.
    ///
    /// Open it lazily, on first read or write: the prover uses it only after
    /// MPC setup, which takes a minute or more over the internet, and servers
    /// close idle connections. Its end of stream is held back until the TLS
    /// handshake is done (see `io::EofGate`).
    Mpc(S),
    /// tlsn proxy mode: the notary opens the connection to the target.
    Proxy,
}

/// Progress steps, for UIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// MPC preprocessing with the notary (most of the upload).
    Setup,
    /// TLS connection to the target and the HTTP exchange.
    Request,
    /// Commitments and proofs.
    Prove,
    /// Waiting for the signed attestation.
    Attest,
}

impl Step {
    pub fn as_str(self) -> &'static str {
        match self {
            Step::Setup => "setup",
            Step::Request => "request",
            Step::Prove => "prove",
            Step::Attest => "attest",
        }
    }
}

/// Result of a successful notarization.
pub struct Notarized {
    /// Signed by the notary. Safe to share; it contains only commitments.
    pub attestation: Attestation,
    /// The plaintext transcript and commitment openings. Private: whoever has
    /// it can build presentations.
    pub secrets: Secrets,
    pub response: HttpResponse,
}

impl Notarized {
    pub fn attestation_bytes(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self.attestation).map_err(|e| Error::Encoding(e.to_string()))
    }

    pub fn secrets_bytes(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(&self.secrets).map_err(|e| Error::Encoding(e.to_string()))
    }
}

/// A byte stream to the notary or to the target server.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// Notarizes `request`.
///
/// `notary` is a byte stream to the notary's `/v1/notarize` endpoint (already
/// authorised by a ticket). `on_step` is called as the session advances.
pub async fn notarize<N: Io, S: Io>(
    notary: N,
    target: Target<S>,
    request: &HttpRequestSpec,
    limits: Limits,
    mut on_step: impl FnMut(Step),
) -> Result<Notarized, Error> {
    let endpoint = request.endpoint()?;
    let sent = request.wire_len()?;
    if sent > limits.max_sent {
        return Err(Error::Request(format!(
            "request is {sent} bytes, the session allows {}",
            limits.max_sent
        )));
    }
    let hyper_request = request.to_hyper()?;
    let dns_name =
        DnsName::try_from(endpoint.host.as_str()).map_err(|e| Error::Request(e.to_string()))?;

    on_step(Step::Setup);
    let session = Session::new(notary);
    let (driver, mut handle) = session.split();
    let driver = spawn(driver);

    let prover = handle.new_prover(ProverConfig::builder().build().map_err(Error::tlsn)?)?;

    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(dns_name.clone()))
        .root_store(RootCertStore::mozilla())
        .build()
        .map_err(Error::tlsn)?;

    let (response, mut prover) = match target {
        Target::Mpc(server) => {
            let commit = MpcTlsConfig::builder()
                .max_sent_data(limits.max_sent)
                .max_recv_data(limits.max_recv)
                .build()
                .map_err(Error::tlsn)?;
            let prover = prover.commit(commit).await?;
            on_step(Step::Request);
            let gate = EofGate::default();
            let _open = OpenOnDrop(gate.clone());
            let (conn, prover) = prover.connect(tls_config, HoldEof::new(server, gate))?;
            futures::try_join!(send_request(conn, hyper_request), async {
                prover.await.map_err(Error::from)
            })?
        }
        Target::Proxy => {
            let commit = ProxyTlsConfig::builder()
                .server_name(dns_name.clone())
                .build()
                .map_err(Error::tlsn)?;
            let prover = prover.commit(commit).await?;
            on_step(Step::Request);
            let (conn, prover) = prover.connect(tls_config)?;
            futures::try_join!(send_request(conn, hyper_request), async {
                prover.await.map_err(Error::from)
            })?
        }
    };
    info!(status = response.status, "response received");

    on_step(Step::Prove);
    let transcript = HttpTranscript::parse(prover.transcript())
        .map_err(|e| Error::Transcript(e.to_string()))?;
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default()
        .commit_transcript(&mut commit_builder, &transcript)
        .map_err(|e| Error::Transcript(e.to_string()))?;
    let transcript_commit = commit_builder.build().map_err(Error::tlsn)?;

    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(transcript_commit);
    let request_config = request_config.build().map_err(Error::tlsn)?;

    let mut prove_config = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_config.transcript_commit(config.clone());
    }
    let prove_config = prove_config.build().map_err(Error::tlsn)?;

    let output = prover.prove(&prove_config).await?;
    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut att_request = AttestationRequest::builder(&request_config);
    att_request
        .server_name(ServerName::Dns(dns_name))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .ok_or_else(|| Error::Transcript("no server certificate chain".into()))?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .ok_or_else(|| Error::Transcript("no server signature".into()))?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(output.transcript_secrets, output.transcript_commitments);
    let provider = CryptoProvider::default();
    let (att_request, secrets) = att_request.build(&provider).map_err(Error::tlsn)?;

    on_step(Step::Attest);
    handle.close();
    let mut notary = driver.await.map_err(|e| Error::Notary(format!("session: {e}")))?;

    let request_bytes =
        bincode::serialize(&att_request).map_err(|e| Error::Encoding(e.to_string()))?;
    tlsnc_protocol::write_frame(&mut notary, &request_bytes).await?;
    let reply = tlsnc_protocol::read_reply(&mut notary).await?;
    let attestation_bytes = reply.map_err(Error::Notary)?;
    let attestation: Attestation =
        bincode::deserialize(&attestation_bytes).map_err(|e| Error::Encoding(e.to_string()))?;

    // The attestation must commit to exactly what we asked for.
    att_request
        .validate(&attestation, &provider)
        .map_err(|e| Error::Notary(format!("attestation does not match the request: {e}")))?;
    debug!("attestation validated");

    Ok(Notarized {
        attestation,
        secrets,
        response,
    })
}

async fn send_request(
    conn: TlsConnection,
    request: hyper::Request<http_body_util::Full<bytes::Bytes>>,
) -> Result<HttpResponse, Error> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(HyperIo::new(conn))
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    // The connection task ends when the server closes (`Connection: close`).
    spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("http connection ended: {e}");
        }
    })
    .forget();

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
        .to_bytes()
        .to_vec();
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    Ok(HttpResponse {
        status: parts.status.as_u16(),
        headers,
        body,
    })
}
