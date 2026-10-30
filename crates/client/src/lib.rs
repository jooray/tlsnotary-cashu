//! Prover side of tlsnotary-cashu.
//!
//! [`notarize`] runs one HTTPS request through MPC-TLS (or tlsn proxy mode)
//! with a notary and returns its signed attestation; [`present`] turns an
//! attestation into a presentation that reveals only what you choose. Paying
//! for the session (buying a ticket) and opening the streams is left to the
//! caller: the CLI does it natively, `@tlsnc/client` does it in the browser.

mod io;
mod present;
mod prover;
mod request;

pub use present::{
    BodyReveal, CREDENTIAL_HEADERS, RequestReveal, ResponseReveal, RevealSpec, present,
    present_bytes,
};
pub use prover::{Io, Limits, Notarized, Step, Target, notarize};
pub use request::{Endpoint, HttpRequestSpec, HttpResponse, REQUEST_LEN_MARGIN};
pub use tlsn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("request: {0}")]
    Request(String),
    #[error("tlsn: {0}")]
    Tlsn(String),
    #[error("http: {0}")]
    Http(String),
    #[error("transcript: {0}")]
    Transcript(String),
    #[error("reveal: {0}")]
    Reveal(String),
    #[error("notary: {0}")]
    Notary(String),
    #[error("encoding: {0}")]
    Encoding(String),
    #[error("transport: {0}")]
    Transport(String),
}

impl Error {
    pub(crate) fn tlsn(e: impl std::fmt::Display) -> Self {
        Error::Tlsn(e.to_string())
    }
}

impl From<tlsn::Error> for Error {
    fn from(e: tlsn::Error) -> Self {
        Error::Tlsn(e.to_string())
    }
}

impl From<tlsnc_protocol::FrameError> for Error {
    fn from(e: tlsnc_protocol::FrameError) -> Self {
        Error::Transport(e.to_string())
    }
}
