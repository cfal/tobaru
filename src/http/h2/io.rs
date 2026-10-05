use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tokio::time::Sleep;

// Observe envelopes only; h2 remains responsible for frame validity and HPACK.
pub(super) struct TimedIo<T> {
    inner: T,
    initial: Bytes,
    preface: usize,
    header: [u8; 9],
    filled: usize,
    remaining: usize,
    header_open: bool,
    encoded: usize,
    limit: usize,
    timeout: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
    deadline_state: watch::Sender<Option<tokio::time::Instant>>,
    sections: Option<Sections>,
    max_streams: usize,
}

pub(super) type Sections = Arc<Mutex<HashMap<u32, u8>>>;

pub(super) struct SectionLease {
    sections: Sections,
    id: u32,
}

impl SectionLease {
    pub fn new(sections: Sections, id: u32) -> Self {
        Self { sections, id }
    }
}

impl Drop for SectionLease {
    fn drop(&mut self) {
        self.sections.lock().remove(&self.id);
    }
}

impl<T> TimedIo<T> {
    pub fn new(
        inner: T,
        initial: Vec<u8>,
        server: bool,
        timeout: Duration,
        limit: usize,
        max_streams: usize,
    ) -> Self {
        let state = Self {
            inner,
            initial: initial.into(),
            preface: if server { 24 } else { 0 },
            header: [0; 9],
            filled: 0,
            remaining: 0,
            header_open: false,
            encoded: 0,
            limit,
            timeout,
            deadline: if server {
                Some(Box::pin(tokio::time::sleep(timeout)))
            } else {
                None
            },
            deadline_state: watch::channel(None).0,
            sections: (!server).then(|| Arc::new(Mutex::new(HashMap::new()))),
            max_streams,
        };
        state.publish_deadline();
        state
    }

    pub fn sections(&self) -> Sections {
        self.sections.as_ref().unwrap().clone()
    }

    fn publish_deadline(&self) {
        let current = self.deadline.as_ref().map(|timer| timer.deadline());
        self.deadline_state.send_if_modified(|old| {
            if *old == current {
                false
            } else {
                *old = current;
                true
            }
        });
    }

    pub fn watchdog(&self) -> Pin<Box<dyn Future<Output = io::Error> + Send>> {
        let mut state = self.deadline_state.subscribe();
        Box::pin(async move {
            loop {
                let deadline = *state.borrow_and_update();
                tokio::select! {
                    result = state.changed() => if result.is_err() { return io::Error::other("HTTP/2 transport closed"); },
                    _ = async { match deadline { Some(deadline) => tokio::time::sleep_until(deadline).await, None => std::future::pending::<()>().await } } => {
                        if *state.borrow() == deadline {
                            return io::Error::new(io::ErrorKind::TimedOut, "Incomplete HTTP/2 frame or header block");
                        }
                    }
                }
            }
        })
    }

    fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.deadline.is_none() {
                self.deadline = Some(Box::pin(tokio::time::sleep(self.timeout)));
            }
            if self.preface != 0 {
                let n = self.preface.min(bytes.len());
                self.preface -= n;
                bytes = &bytes[n..];
                if self.preface == 0 {
                    self.deadline = None;
                }
                continue;
            }
            if self.filled < 9 {
                let n = (9 - self.filled).min(bytes.len());
                self.header[self.filled..self.filled + n].copy_from_slice(&bytes[..n]);
                self.filled += n;
                bytes = &bytes[n..];
                if self.filled < 9 {
                    continue;
                }
                self.remaining = ((self.header[0] as usize) << 16)
                    | ((self.header[1] as usize) << 8)
                    | self.header[2] as usize;
                if let Some(sections) = &self.sections {
                    let mut sections = sections.lock();
                    let stream =
                        u32::from_be_bytes(self.header[5..9].try_into().unwrap()) & 0x7fffffff;
                    if self.header[3] == 1 {
                        if sections.len() > self.max_streams {
                            return Err(io::Error::other(
                                "Too many HTTP/2 response field sections",
                            ));
                        }
                        if let Some(count) = sections.get_mut(&stream) {
                            *count += 1;
                            if *count > 18 {
                                return Err(io::Error::other(
                                    "Too many HTTP/2 response field sections",
                                ));
                            }
                        }
                    }
                    if self.header[3] == 3
                        || matches!(self.header[3], 0 | 1) && self.header[4] & 1 != 0
                    {
                        sections.remove(&stream);
                    }
                }
                if matches!(self.header[3], 1 | 5 | 9) {
                    self.encoded = self
                        .encoded
                        .checked_add(self.remaining)
                        .ok_or_else(|| io::Error::other("Encoded header overflow"))?;
                    if self.encoded > self.limit {
                        return Err(io::Error::other("Encoded HTTP/2 field section too large"));
                    }
                    self.header_open = self.header[4] & 4 == 0;
                }
            }
            let n = self.remaining.min(bytes.len());
            self.remaining -= n;
            bytes = &bytes[n..];
            if self.remaining == 0 {
                self.filled = 0;
                if !self.header_open {
                    self.deadline = None;
                    self.encoded = 0;
                }
            }
        }
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(timer) = &mut this.deadline {
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Incomplete HTTP/2 frame or header block",
                )));
            }
        }
        let before = out.filled().len();
        let result = if !this.initial.is_empty() {
            let n = this.initial.len().min(out.remaining());
            out.put_slice(&this.initial.split_to(n));
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.inner).poll_read(cx, out)
        };
        if let Poll::Ready(Ok(())) = result {
            this.observe(&out.filled()[before..])?;
            this.publish_deadline();
            // Register a freshly created timer even when the engine next stalls on writes.
            if let Some(timer) = &mut this.deadline {
                let _ = timer.as_mut().poll(cx);
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test(start_paused = true)]
    async fn watchdog_expires_without_another_transport_read() {
        let (mut peer, stream) = tokio::io::duplex(256);
        let mut io = TimedIo::new(stream, vec![], false, Duration::from_secs(2), 1024, 64);
        let watchdog = io.watchdog();
        peer.write_all(&[0, 0]).await.unwrap();
        io.read_exact(&mut [0; 2]).await.unwrap();
        assert_eq!(watchdog.await.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn response_sections_are_bounded_before_hpack_or_consumption() {
        let mut io = TimedIo::new(&b""[..], vec![], false, Duration::from_secs(2), 1024, 1);
        io.sections().lock().insert(1, 0);
        let headers = [0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88];
        for _ in 0..18 {
            io.observe(&headers).unwrap();
        }
        assert!(io.observe(&headers).is_err());
        let mut io = TimedIo::new(&b""[..], vec![], false, Duration::from_secs(2), 1024, 1);
        io.sections().lock().insert(1, 0);
        io.observe(&headers).unwrap();
        io.sections().lock().insert(3, 0);
        assert!(io.observe(&[0, 0, 1, 1, 4, 0, 0, 0, 3, 0x88]).is_err());
    }

    #[tokio::test]
    async fn late_retired_sections_do_not_consume_live_accounting() {
        let mut io = TimedIo::new(&b""[..], vec![], false, Duration::from_secs(2), 1024, 1);
        let sections = io.sections();
        sections.lock().insert(1, 0);
        let lease = SectionLease::new(sections.clone(), 1);
        io.observe(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88]).unwrap();
        drop(lease);
        sections.lock().insert(3, 0);
        for _ in 0..32 {
            io.observe(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88]).unwrap();
        }
        assert_eq!(sections.lock().len(), 1);
        io.observe(&[0, 0, 1, 1, 4, 0, 0, 0, 3, 0x88]).unwrap();
        assert_eq!(sections.lock()[&3], 1);
    }
    #[tokio::test(start_paused = true)]
    async fn fragmented_header_deadline_is_absolute() {
        let (mut peer, stream) = tokio::io::duplex(256);
        let mut io = TimedIo::new(stream, vec![], false, Duration::from_secs(2), 1024, 64);
        peer.write_all(&[0, 0, 3, 1, 0, 0, 0, 0, 1, b'a'])
            .await
            .unwrap();
        let mut bytes = [0; 10];
        io.read_exact(&mut bytes).await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        peer.write_all(b"b").await.unwrap();
        io.read_exact(&mut [0]).await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            io.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[tokio::test(start_paused = true)]
    async fn end_headers_requires_the_complete_payload() {
        let (mut peer, stream) = tokio::io::duplex(256);
        let mut io = TimedIo::new(stream, vec![], false, Duration::from_secs(2), 1024, 64);
        peer.write_all(&[0, 0, 2, 1, 4, 0, 0, 0, 1, b'a'])
            .await
            .unwrap();
        io.read_exact(&mut [0; 10]).await.unwrap();
        assert_eq!(
            io.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[tokio::test]
    async fn replay_and_every_envelope_split_are_transparent() {
        let wire = [
            0, 0, 1, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 9, 4, 0, 0, 0, 1, b'b',
        ];
        for split in 0..=wire.len() {
            let mut io = TimedIo::new(
                &wire[split..],
                wire[..split].to_vec(),
                false,
                Duration::from_secs(2),
                1024,
                64,
            );
            let mut output = Vec::new();
            io.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, wire);
            assert!(io.deadline.is_none());
        }
    }
}
