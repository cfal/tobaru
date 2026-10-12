use std::future::Future;
use std::io;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

pub(super) struct UpstreamIo<T> {
    inner: T,
    seconds: Option<NonZeroU64>,
    read: Option<Pin<Box<Sleep>>>,
    write: Option<Pin<Box<Sleep>>>,
}

impl<T> UpstreamIo<T> {
    pub fn new(inner: T, seconds: Option<NonZeroU64>) -> Self {
        Self {
            inner,
            seconds,
            read: None,
            write: None,
        }
    }
}

fn poll_operation<T>(
    timer: &mut Option<Pin<Box<Sleep>>>,
    seconds: Option<NonZeroU64>,
    operation: &str,
    cx: &mut Context<'_>,
    poll: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
) -> Poll<io::Result<T>> {
    if let Some(seconds) = seconds {
        let sleep = match timer {
            Some(sleep) => sleep,
            None => {
                let Some(deadline) =
                    tokio::time::Instant::now().checked_add(Duration::from_secs(seconds.get()))
                else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Timeout is too large",
                    )));
                };
                timer.insert(Box::pin(tokio::time::sleep_until(deadline)))
            }
        };
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Upstream body {operation} made no progress for {seconds}s"),
            )));
        }
    }
    let result = poll(cx);
    if result.is_ready() {
        *timer = None;
    }
    result
}

impl<T: AsyncRead + Unpin> AsyncRead for UpstreamIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_operation(&mut this.read, this.seconds, "read", cx, |cx| {
            Pin::new(&mut this.inner).poll_read(cx, buffer)
        })
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for UpstreamIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        poll_operation(&mut this.write, this.seconds, "write", cx, |cx| {
            Pin::new(&mut this.inner).poll_write(cx, bytes)
        })
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_operation(&mut this.write, this.seconds, "flush", cx, |cx| {
            Pin::new(&mut this.inner).poll_flush(cx)
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_operation(&mut this.write, this.seconds, "shutdown", cx, |cx| {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn progressing_io_can_outlive_the_budget_and_downstream_pauses() {
        let (mut peer, io) = tokio::io::duplex(1);
        let mut io = UpstreamIo::new(io, NonZeroU64::new(10));
        let (result, ()) = tokio::join!(io.write_all(b"abcde"), async {
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_secs(9)).await;
                peer.read_exact(&mut [0]).await.unwrap();
            }
        });
        result.unwrap();
        tokio::time::advance(Duration::from_secs(100)).await;
        let mut byte = [0];
        let (result, ()) = tokio::join!(io.read_exact(&mut byte), async {
            tokio::time::sleep(Duration::from_secs(9)).await;
            peer.write_all(b"x").await.unwrap();
        });
        result.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn body_budget_covers_stalled_data_trailers_and_eof() {
        use crate::http::{
            body::{forward_body, Framing},
            line_reader::LineReader,
        };
        for (framing, bytes) in [
            (Framing::Length(2), b"x".as_slice()),
            (Framing::Chunked, b"0\r\nX-End: incomplete".as_slice()),
            (Framing::UntilEof, b"x".as_slice()),
        ] {
            let (_peer, io) = tokio::io::duplex(64);
            let mut io = UpstreamIo::new(io, NonZeroU64::new(2));
            let mut sink = tokio::io::sink();
            let result = forward_body(
                &mut io,
                Some(&mut sink),
                LineReader::new_with_data(bytes.to_vec()),
                framing,
            )
            .await;
            assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_reads_and_writes_are_opt_in() {
        for seconds in [None, NonZeroU64::new(2)] {
            let (_peer, io) = tokio::io::duplex(1);
            let mut io = UpstreamIo::new(io, seconds);
            let read = tokio::time::timeout(Duration::from_secs(100), io.read_u8()).await;
            if seconds.is_some() {
                assert_eq!(read.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
            } else {
                assert!(read.is_err());
            }
            let write = tokio::time::timeout(Duration::from_secs(100), io.write_all(b"ab")).await;
            if seconds.is_some() {
                assert_eq!(write.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
            } else {
                assert!(write.is_err());
            }
        }
    }
}
