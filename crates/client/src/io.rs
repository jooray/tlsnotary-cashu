//! IO glue: hyper over a `futures` byte stream, and task spawning that works
//! on tokio and in the browser.
//!
//! `HyperIo` follows `tlsn-sdk-core`'s adapter of the same name (MIT OR
//! Apache-2.0, TLSNotary team).

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, FutureExt, future::RemoteHandle};
use pin_project_lite::pin_project;

pin_project! {
    /// Adapts a `futures` AsyncRead/AsyncWrite stream to hyper's IO traits.
    pub(crate) struct HyperIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> HyperIo<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for HyperIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

impl<T: AsyncRead + Unpin> hyper::rt::Read for HyperIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        // SAFETY: AsyncRead implementations only write into the buffer, so
        // exposing the uninitialised tail as `&mut [u8]` is sound here.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf.as_mut().len())
        };
        match self.project().inner.poll_read(cx, slice) {
            Poll::Ready(Ok(n)) => {
                // SAFETY: `n` bytes were just written by poll_read.
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Holds back the server's end of stream until the TLS handshake is done.
///
/// A server that answers `Connection: close` sends its handshake flight, the
/// response and its FIN in a second or two. Over the internet the MPC client
/// is still handshaking by then, and a server close seen while handshaking
/// makes tlsn's `MpcTlsClient::poll` recurse until the stack overflows. The
/// response itself is decrypted only after the close, so the HTTP layer
/// cannot tell when the handshake ended; the wire can: the client sends its
/// first application-data record only after it has verified the server's
/// Finished. [`HoldEof`] opens the gate when it writes that record.
/// Upstream: https://github.com/tlsnotary/tlsn/issues/1205
#[derive(Clone, Default)]
pub(crate) struct EofGate(std::sync::Arc<GateInner>);

#[derive(Default)]
struct GateInner {
    open: std::sync::atomic::AtomicBool,
    waker: futures::task::AtomicWaker,
}

impl EofGate {
    pub(crate) fn open(&self) {
        self.0.open.store(true, std::sync::atomic::Ordering::Release);
        self.0.waker.wake();
    }

    fn poll_open(&self, cx: &mut Context<'_>) -> bool {
        if self.0.open.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }
        self.0.waker.register(cx.waker());
        self.0.open.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Opens the gate when dropped, so a failed or cancelled request never
/// leaves the prover waiting for an end of stream.
pub(crate) struct OpenOnDrop(pub(crate) EofGate);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

pin_project! {
    /// The server stream, with its end of stream held until `gate` opens.
    pub(crate) struct HoldEof<S> {
        #[pin]
        inner: S,
        gate: EofGate,
        eof: bool,
        records: RecordScanner,
    }
}

impl<S> HoldEof<S> {
    pub(crate) fn new(inner: S, gate: EofGate) -> Self {
        Self {
            inner,
            gate,
            eof: false,
            records: RecordScanner::default(),
        }
    }
}

/// Follows TLS record boundaries in the bytes the client sends.
#[derive(Default)]
struct RecordScanner {
    header: [u8; 5],
    have: usize,
    skip: usize,
}

impl RecordScanner {
    const APPLICATION_DATA: u8 = 23;

    /// Returns true once a record header of type application data went by.
    fn saw_application_data(&mut self, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            if self.skip > 0 {
                let n = self.skip.min(bytes.len());
                self.skip -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (5 - self.have).min(bytes.len());
            self.header[self.have..self.have + n].copy_from_slice(&bytes[..n]);
            self.have += n;
            bytes = &bytes[n..];
            if self.have == 5 {
                if self.header[0] == Self::APPLICATION_DATA {
                    return true;
                }
                self.skip = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                self.have = 0;
            }
        }
        false
    }
}

impl<S: AsyncRead> AsyncRead for HoldEof<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        if !*this.eof {
            match this.inner.poll_read(cx, buf) {
                Poll::Ready(Ok(0)) if !buf.is_empty() => {
                    tracing::debug!("server closed; holding the end of stream until the handshake is done");
                    *this.eof = true
                }
                other => return other,
            }
        }
        if this.gate.poll_open(cx) { Poll::Ready(Ok(0)) } else { Poll::Pending }
    }
}

impl<S: AsyncWrite> AsyncWrite for HoldEof<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let written = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = written
            && this.records.saw_application_data(&buf[..n])
        {
            this.gate.open();
        }
        written
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

/// Runs `fut` in the background and returns a handle to its output.
/// Dropping the handle cancels the task.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn spawn<F>(fut: F) -> RemoteHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (remote, handle) = fut.remote_handle();
    tokio::spawn(remote);
    handle
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn<F>(fut: F) -> RemoteHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    let (remote, handle) = fut.remote_handle();
    wasm_bindgen_futures::spawn_local(remote);
    handle
}

#[cfg(test)]
mod tests {
    use super::RecordScanner;

    #[test]
    fn finds_the_first_application_data_record_across_splits() {
        // handshake(3 bytes body), change_cipher_spec(1), application_data
        let wire = [22, 3, 3, 0, 3, 1, 2, 3, 20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 2, 9, 9];
        for split in 0..wire.len() {
            let mut s = RecordScanner::default();
            let (a, b) = wire.split_at(split);
            let seen_a = s.saw_application_data(a);
            let seen = seen_a || s.saw_application_data(b);
            assert!(seen, "split at {split}");
            assert_eq!(seen_a, split >= 19, "split at {split}");
        }
        let mut s = RecordScanner::default();
        assert!(!s.saw_application_data(&wire[..18]));
    }
}
