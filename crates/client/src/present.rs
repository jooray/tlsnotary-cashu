//! Building presentations: selective disclosure of a notarized transcript.

use serde::{Deserialize, Serialize};
use tlsn::attestation::{Attestation, CryptoProvider, Secrets, presentation::Presentation};
use tlsn_formats::{
    http::{BodyContent, HttpTranscript},
    json::JsonValue,
};

use crate::Error;

/// Header values that identify or authenticate the user. They are never
/// revealed unless [`RevealSpec::allow_credentials`] is set.
pub const CREDENTIAL_HEADERS: [&str; 5] = [
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
];

/// What to disclose. Anything not listed stays hidden; for headers that are
/// not listed only the name is disclosed, never the value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RevealSpec {
    pub request: RequestReveal,
    pub response: ResponseReveal,
    /// Allow revealing the values of [`CREDENTIAL_HEADERS`].
    pub allow_credentials: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestReveal {
    /// The request target (path and query).
    pub target: bool,
    /// Header names whose values are revealed (case-insensitive).
    pub headers: Vec<String>,
    pub body: bool,
}

impl Default for RequestReveal {
    fn default() -> Self {
        Self {
            target: true,
            headers: vec!["host".into()],
            body: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseReveal {
    /// Header names whose values are revealed (case-insensitive).
    pub headers: Vec<String>,
    pub body: BodyReveal,
}

impl Default for ResponseReveal {
    fn default() -> Self {
        Self {
            headers: vec!["date".into(), "content-type".into()],
            body: BodyReveal::All,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum BodyReveal {
    None,
    #[default]
    All,
    /// Dotted paths into a JSON body, e.g. `data.balance` or `items.0.id`.
    /// Each one reveals the key and its value (array elements: the value).
    JsonPaths(Vec<String>),
}


fn wanted(list: &[String], name: &str) -> bool {
    list.iter().any(|h| h.eq_ignore_ascii_case(name))
}

fn is_credential(name: &str) -> bool {
    CREDENTIAL_HEADERS.iter().any(|c| c.eq_ignore_ascii_case(name))
}

/// Builds a presentation from an attestation and its secrets.
pub fn present(
    attestation: &Attestation,
    secrets: &Secrets,
    spec: &RevealSpec,
) -> Result<Presentation, Error> {
    if !spec.allow_credentials {
        for h in spec.request.headers.iter().chain(&spec.response.headers) {
            if is_credential(h) {
                return Err(Error::Reveal(format!(
                    "refusing to reveal the value of `{h}`; set allow_credentials to do it anyway"
                )));
            }
        }
    }

    let transcript =
        HttpTranscript::parse(secrets.transcript()).map_err(|e| Error::Transcript(e.to_string()))?;
    let mut builder = secrets.transcript_proof_builder();
    let reveal_err = |e: tlsn::transcript::TranscriptProofBuilderError| Error::Reveal(e.to_string());

    let request = transcript
        .requests
        .first()
        .ok_or_else(|| Error::Transcript("no request in the transcript".into()))?;
    builder.reveal_sent(request.without_data()).map_err(reveal_err)?;
    if spec.request.target {
        builder.reveal_sent(&request.request.target).map_err(reveal_err)?;
    }
    for header in &request.headers {
        if wanted(&spec.request.headers, &header.name.as_str()) {
            builder.reveal_sent(header).map_err(reveal_err)?;
        } else {
            builder.reveal_sent(header.without_value()).map_err(reveal_err)?;
        }
    }
    if spec.request.body
        && let Some(body) = &request.body {
            builder.reveal_sent(body).map_err(reveal_err)?;
        }

    let response = transcript
        .responses
        .first()
        .ok_or_else(|| Error::Transcript("no response in the transcript".into()))?;
    builder.reveal_recv(response.without_data()).map_err(reveal_err)?;
    for header in &response.headers {
        if wanted(&spec.response.headers, &header.name.as_str()) {
            builder.reveal_recv(header).map_err(reveal_err)?;
        } else {
            builder.reveal_recv(header.without_value()).map_err(reveal_err)?;
        }
    }
    match (&spec.response.body, &response.body) {
        (BodyReveal::None, _) | (_, None) => {}
        (BodyReveal::All, Some(body)) => {
            builder.reveal_recv(body).map_err(reveal_err)?;
        }
        (BodyReveal::JsonPaths(paths), Some(body)) => {
            let BodyContent::Json(json) = &body.content else {
                return Err(Error::Reveal("the response body is not JSON".into()));
            };
            for path in paths {
                let not_found = || Error::Reveal(format!("JSON path `{path}` not found"));
                // Reveal the key together with the value, so the verifier
                // sees which field it is; array elements have no key.
                let (parent, last) = match path.rsplit_once('.') {
                    Some((parent, last)) => (json.root.get(parent).ok_or_else(not_found)?, last),
                    None => (&json.root, path.as_str()),
                };
                match parent {
                    JsonValue::Object(object) => {
                        let pair = object.elems.iter().find(|kv| kv.key == last).ok_or_else(not_found)?;
                        builder.reveal_recv(pair).map_err(reveal_err)?;
                    }
                    JsonValue::Array(_) => {
                        builder.reveal_recv(parent.get(last).ok_or_else(not_found)?).map_err(reveal_err)?;
                    }
                    _ => return Err(not_found()),
                }
            }
        }
    }

    let transcript_proof = builder.build().map_err(reveal_err)?;
    let provider = CryptoProvider::default();
    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    presentation.build().map_err(|e| Error::Reveal(e.to_string()))
}

/// `present` on serialized inputs, returning a serialized presentation.
pub fn present_bytes(
    attestation: &[u8],
    secrets: &[u8],
    spec: &RevealSpec,
) -> Result<Vec<u8>, Error> {
    let attestation: Attestation =
        bincode::deserialize(attestation).map_err(|e| Error::Encoding(format!("attestation: {e}")))?;
    let secrets: Secrets =
        bincode::deserialize(secrets).map_err(|e| Error::Encoding(format!("secrets: {e}")))?;
    let presentation = present(&attestation, &secrets, spec)?;
    bincode::serialize(&presentation).map_err(|e| Error::Encoding(e.to_string()))
}
