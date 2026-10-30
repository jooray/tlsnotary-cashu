//! A WebSocket to the notary as a byte stream (binary messages are chunks).

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

/// Connects and returns the local end of a pipe pumped to the socket. The
/// ticket travels as a WebSocket subprotocol, never in the URL. An HTTP error
/// during the upgrade (bad ticket, busy notary) comes back with its body.
pub async fn connect(url: &str, ticket: &str) -> Result<DuplexStream> {
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!("tlsnc, tlsnc.{ticket}").parse().context("ticket is not a valid header value")?,
    );
    let (socket, _) = match tokio_tungstenite::connect_async(request).await {
        Ok(s) => s,
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            let body = resp
                .body()
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            anyhow::bail!("{}: {body}", resp.status());
        }
        Err(e) => return Err(e).with_context(|| format!("connecting to {url}")),
    };
    let (local, remote) = tokio::io::duplex(1 << 16);
    let (mut from_local, mut to_local) = tokio::io::split(remote);
    let (mut tx, mut rx) = socket.split();
    tokio::spawn(async move {
        while let Some(Ok(msg)) = rx.next().await {
            match msg {
                Message::Binary(b) => {
                    if to_local.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = to_local.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1 << 15];
        loop {
            match from_local.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(Message::Close(None)).await;
    });
    Ok(local)
}

/// `https://x` → `wss://x`, `http://x` → `ws://x`.
pub fn ws_base(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    }
}
