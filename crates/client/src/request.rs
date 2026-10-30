//! The HTTP request a prover sends, and the response it gets back.

use bytes::Bytes;
use http_body_util::Full;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Margin added to [`HttpRequestSpec::wire_len`] when picking a tier, for
/// anything hyper adds or normalises on the wire.
pub const REQUEST_LEN_MARGIN: usize = 64;

/// An HTTPS request to notarize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestSpec {
    /// `https://host[:port]/path?query`
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// UTF-8 body. Use [`HttpRequestSpec::body_bytes`] for binary bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<Vec<u8>>,
}

fn default_method() -> String {
    "GET".into()
}

/// Where a request goes, parsed from its URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// Path and query, at least `/`.
    pub target: String,
}

/// The server's response, as the prover saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Headers the prover always controls. TLSNotary cannot commit to compressed
/// bodies, and the session must end with the response.
const FORCED: [(&str, &str); 2] = [("accept-encoding", "identity"), ("connection", "close")];

impl HttpRequestSpec {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: default_method(),
            headers: Vec::new(),
            body: None,
            body_bytes: None,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn endpoint(&self) -> Result<Endpoint, Error> {
        let url = url::Url::parse(&self.url).map_err(|e| Error::Request(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(Error::Request("only https:// URLs can be notarized".into()));
        }
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
            Some(_) => {
                return Err(Error::Request(
                    "the host must be a DNS name: a TLS server name cannot be an IP address".into(),
                ));
            }
            None => return Err(Error::Request("URL has no host".into())),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::Request("credentials in the URL are not supported".into()));
        }
        let mut target = url.path().to_string();
        if let Some(q) = url.query() {
            target.push('?');
            target.push_str(q);
        }
        Ok(Endpoint {
            host,
            port: url.port().unwrap_or(443),
            target,
        })
    }

    fn body(&self) -> Vec<u8> {
        match (&self.body_bytes, &self.body) {
            (Some(b), _) => b.clone(),
            (None, Some(s)) => s.as_bytes().to_vec(),
            (None, None) => Vec::new(),
        }
    }

    /// The headers as they go on the wire: the caller's, minus the ones the
    /// prover controls, plus `host`, the forced ones and `content-length`.
    fn wire_headers(&self, ep: &Endpoint) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let has_host = self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host"));
        if !has_host {
            let host = if ep.port == 443 {
                ep.host.clone()
            } else {
                format!("{}:{}", ep.host, ep.port)
            };
            out.push(("host".to_string(), host));
        }
        for (k, v) in &self.headers {
            let lk = k.to_ascii_lowercase();
            if FORCED.iter().any(|(f, _)| *f == lk) || lk == "content-length" {
                continue;
            }
            out.push((lk, v.clone()));
        }
        for (k, v) in FORCED {
            out.push((k.to_string(), v.to_string()));
        }
        let body = self.body();
        if !body.is_empty() || !matches!(self.method.as_str(), "GET" | "HEAD") {
            out.push(("content-length".to_string(), body.len().to_string()));
        }
        out
    }

    /// Number of bytes this request occupies on the wire (HTTP/1.1, as hyper
    /// writes it). This is what counts against a tier's `max_sent`.
    pub fn wire_len(&self) -> Result<usize, Error> {
        let ep = self.endpoint()?;
        let mut n = self.method.len() + 1 + ep.target.len() + " HTTP/1.1\r\n".len();
        for (k, v) in self.wire_headers(&ep) {
            n += k.len() + 2 + v.len() + 2;
        }
        n += 2 + self.body().len();
        Ok(n)
    }

    pub(crate) fn to_hyper(&self) -> Result<hyper::Request<Full<Bytes>>, Error> {
        let ep = self.endpoint()?;
        let mut builder = hyper::Request::builder()
            .method(self.method.as_str())
            .uri(ep.target.as_str());
        for (k, v) in self.wire_headers(&ep) {
            builder = builder.header(k, v);
        }
        builder
            .body(Full::new(Bytes::from(self.body())))
            .map_err(|e| Error::Request(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpoint() {
        let r = HttpRequestSpec::get("https://API.Example.com/v1/x?y=1");
        assert_eq!(
            r.endpoint().unwrap(),
            Endpoint {
                host: "api.example.com".into(),
                port: 443,
                target: "/v1/x?y=1".into()
            }
        );
        assert!(HttpRequestSpec::get("http://example.com/").endpoint().is_err());
        assert!(HttpRequestSpec::get("https://1.2.3.4/").endpoint().is_err());
        assert!(HttpRequestSpec::get("https://u:p@example.com/").endpoint().is_err());
    }

    #[test]
    fn forces_identity_and_close() {
        let r = HttpRequestSpec::get("https://example.com/")
            .header("Accept-Encoding", "gzip")
            .header("Connection", "keep-alive")
            .header("Authorization", "Bearer x");
        let h = r.wire_headers(&r.endpoint().unwrap());
        assert!(h.contains(&("accept-encoding".into(), "identity".into())));
        assert!(h.contains(&("connection".into(), "close".into())));
        assert!(!h.iter().any(|(_, v)| v == "gzip" || v == "keep-alive"));
        assert_eq!(h[0], ("host".into(), "example.com".into()));
    }

    #[test]
    fn wire_len_matches_hand_count() {
        let r = HttpRequestSpec::get("https://example.com/a");
        let expected = "GET /a HTTP/1.1\r\nhost: example.com\r\naccept-encoding: identity\r\nconnection: close\r\n\r\n";
        assert_eq!(r.wire_len().unwrap(), expected.len());
    }
}
