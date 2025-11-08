/// TcpStream wrapper that replays buffered data before reading from the actual stream.
///
/// This is used to "rewind" a TcpStream after parsing data from it. For example,
/// after parsing a TLS ClientHello for routing decisions, we can replay that
/// ClientHello so that LazyConfigAcceptor can read it again.

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// TcpStream wrapper that replays buffered data (ClientHello + any extra bytes) before
/// reading from the actual stream. The replay buffer is freed after being fully consumed.
pub struct ReplayTcpStream {
    inner: TcpStream,
    replay_buffer: Option<Vec<u8>>,
    replay_pos: usize,
}

impl ReplayTcpStream {
    /// Create a new ReplayTcpStream that will replay the given buffer before reading from the stream
    ///
    /// # Panics
    /// Panics if replay_buffer is empty
    pub fn new(inner: TcpStream, replay_buffer: Vec<u8>) -> Self {
        assert!(
            !replay_buffer.is_empty(),
            "ReplayTcpStream requires non-empty replay buffer"
        );

        Self {
            inner,
            replay_buffer: Some(replay_buffer),
            replay_pos: 0,
        }
    }
}

#[async_trait::async_trait]
impl crate::async_stream::AsyncStream for ReplayTcpStream {
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.inner.shutdown().await
    }
}

impl AsyncRead for ReplayTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // First, replay any buffered data
        if let Some(ref replay_buffer) = self.replay_buffer {
            // Invariant: if replay_buffer is Some, we haven't finished replaying it yet
            debug_assert!(self.replay_pos < replay_buffer.len());

            let remaining = &replay_buffer[self.replay_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            let new_pos = self.replay_pos + to_copy;

            // If we've consumed all the replay buffer, free it
            if new_pos >= replay_buffer.len() {
                self.replay_buffer = None;
            } else {
                self.replay_pos = new_pos;
            }

            return std::task::Poll::Ready(Ok(()));
        }

        // Buffer exhausted or not present, read from inner stream
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
