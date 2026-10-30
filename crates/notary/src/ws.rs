//! Turning an axum WebSocket into a byte stream.
//!
//! tlsn wants an `AsyncRead + AsyncWrite`. Binary WebSocket messages are
//! treated as chunks of one stream: incoming ones are written into a tokio
//! duplex pipe, whatever the session writes is sent back as binary messages.

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const PIPE: usize = 1 << 16;
const CHUNK: usize = 1 << 15;

/// Returns the session side of the pipe. The pump tasks end when either side
/// closes.
pub fn into_stream(socket: WebSocket) -> DuplexStream {
    let (session_side, pump_side) = tokio::io::duplex(PIPE);
    let (mut from_session, mut to_session) = tokio::io::split(pump_side);
    let (mut ws_tx, mut ws_rx) = socket.split();

    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if to_session.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                // Text is not part of the protocol; pings are answered by axum.
                Ok(_) => {}
            }
        }
        let _ = to_session.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match from_session.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    });

    session_side
}
