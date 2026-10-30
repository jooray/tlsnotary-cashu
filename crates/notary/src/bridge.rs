//! The browser bridge: WebSocket to TCP, for provers that cannot open TCP.
//!
//! It only ever carries TLS ciphertext between the browser's WASM prover and
//! the target; it has no keys. Each direction is capped at the tier's limit
//! plus handshake slack, and the whole thing at the tier's timeout.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

use crate::egress::Capped;

pub async fn relay(socket: WebSocket, tcp: TcpStream, max_up: usize, max_down: usize, timeout: Duration) {
    let tcp = Capped::new(tcp, max_up, max_down);
    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(tcp);
    let (mut ws_tx, mut ws_rx) = socket.split();

    let up = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(b) => {
                    if tcp_tx.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = tcp_tx.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 1 << 15];
        loop {
            match tcp_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    };

    // The target closes after the response (`Connection: close`); `down`
    // finishing ends the bridge even if the browser keeps its side open.
    let both = async {
        tokio::select! {
            _ = down => {}
            _ = async { up.await; futures::future::pending::<()>().await } => {}
        }
    };
    if tokio::time::timeout(timeout, both).await.is_err() {
        debug!("bridge timed out");
    }
}
