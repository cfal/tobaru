use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) enum ReadStep {
    Data(Vec<u8>),
    Pending,
    Error(io::ErrorKind),
    Eof,
}

pub(super) struct ScriptedIo {
    reads: VecDeque<ReadStep>,
    offset: usize,
    pub written: Vec<u8>,
    write_limit: usize,
    write_pending: bool,
    fail_after: Option<usize>,
}

impl ScriptedIo {
    pub fn new(reads: impl IntoIterator<Item = ReadStep>) -> Self {
        Self {
            reads: reads.into_iter().collect(),
            offset: 0,
            written: Vec::new(),
            write_limit: usize::MAX,
            write_pending: false,
            fail_after: None,
        }
    }

    pub fn split(bytes: &[u8], at: usize) -> Self {
        Self::new([
            ReadStep::Data(bytes[..at].to_vec()),
            ReadStep::Pending,
            ReadStep::Data(bytes[at..].to_vec()),
        ])
    }

    pub fn short_writes(mut self, limit: usize) -> Self {
        assert!(limit > 0);
        self.write_limit = limit;
        self
    }

    pub fn fail_writes_after(mut self, length: usize) -> Self {
        self.fail_after = Some(length);
        self
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.reads.front() {
                Some(ReadStep::Data(bytes)) => {
                    let length = buffer.remaining().min(bytes.len() - self.offset);
                    buffer.put_slice(&bytes[self.offset..self.offset + length]);
                    let exhausted = self.offset + length == bytes.len();
                    self.offset += length;
                    if exhausted {
                        self.reads.pop_front();
                        self.offset = 0;
                    }
                    if length > 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                Some(ReadStep::Pending) => {
                    self.reads.pop_front();
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(ReadStep::Error(kind)) => {
                    let error = io::Error::new(*kind, "scripted read failure");
                    self.reads.pop_front();
                    return Poll::Ready(Err(error));
                }
                Some(ReadStep::Eof) | None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.write_pending {
            self.write_pending = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.write_pending = false;
        let remaining = self.fail_after.unwrap_or(usize::MAX) - self.written.len();
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "scripted write failure",
            )));
        }
        let length = bytes.len().min(self.write_limit).min(remaining);
        self.written.extend_from_slice(&bytes[..length]);
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait::async_trait]
impl crate::async_stream::AsyncStream for ScriptedIo {
    async fn try_shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}
