use super::message::{Activity, BodyFrame};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::watch;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    ExpectPending,
    Active,
    Stopped,
}

#[derive(Clone)]
pub(super) struct Upload {
    phase: watch::Sender<Phase>,
    h2_receive: Option<h2::FlowControl>,
}

impl Upload {
    pub fn new(expect: bool) -> Self {
        let phase = if expect {
            Phase::ExpectPending
        } else {
            Phase::Active
        };
        Self {
            phase: watch::channel(phase).0,
            h2_receive: None,
        }
    }

    pub fn watch_h2(&mut self, receive: h2::FlowControl) {
        self.h2_receive = Some(receive);
    }

    pub fn started(&self) {
        self.phase.send_if_modified(|phase| {
            if *phase != Phase::ExpectPending {
                return false;
            }
            *phase = Phase::Active;
            true
        });
    }

    pub fn stop(&self) {
        self.phase.send_replace(Phase::Stopped);
    }

    pub fn stop_if_pending(&self) {
        self.phase.send_if_modified(|phase| {
            if *phase != Phase::ExpectPending {
                return false;
            }
            // H2 DATA can arrive during backend setup, before the upload's first poll.
            let has_buffered_data = self
                .h2_receive
                .as_ref()
                .is_some_and(|receive| receive.used_capacity() > 0);
            *phase = if has_buffered_data {
                Phase::Active
            } else {
                Phase::Stopped
            };
            true
        });
    }

    pub async fn stopped(&self) {
        let mut phase = self.phase.subscribe();
        loop {
            if *phase.borrow_and_update() == Phase::Stopped {
                return;
            }
            if phase.changed().await.is_err() {
                return;
            }
        }
    }

    pub async fn read(
        &self,
        activity: &Activity,
        operation: impl Future<Output = io::Result<Option<BodyFrame>>>,
    ) -> io::Result<Option<BodyFrame>> {
        let mut phase = self.phase.subscribe();
        // H1 reads can consume framing before yielding. A phase change must not restart them.
        tokio::pin!(operation);
        loop {
            if *phase.borrow_and_update() != Phase::ExpectPending {
                return activity.wait(operation).await;
            }
            tokio::select! {
                biased;
                result = &mut operation => {
                    self.started();
                    activity.touch();
                    return result;
                }
                _ = phase.changed() => {}
            }
        }
    }
}

pub(super) struct StartedRead<'a, R> {
    pub io: &'a mut R,
    pub upload: Option<&'a Upload>,
}

impl<R: AsyncRead + Unpin> AsyncRead for StartedRead<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut *this.io).poll_read(cx, buffer);
        if buffer.filled().len() > before {
            if let Some(upload) = this.upload {
                upload.started();
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{
        bridge::{Framing, H1Body},
        line_reader::LineReader,
        message::ReceiveBody,
    };
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test(start_paused = true)]
    async fn expect_wait_is_unbounded_until_continue_with_a_fresh_budget() {
        let upload = Upload::new(true);
        let activity = Activity::new(10);
        let read = upload.read(&activity, std::future::pending());
        tokio::pin!(read);
        assert!(tokio::time::timeout(Duration::from_secs(100), &mut read)
            .await
            .is_err());
        upload.started();
        let start = tokio::time::Instant::now();
        assert_eq!(read.await.err().unwrap().kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn partial_h1_upload_activates_protection_without_restarting_the_read() {
        for buffered in [false, true] {
            let mut upload = Upload::new(true);
            let activity = Activity::new(10);
            let (mut peer, io) = tokio::io::duplex(256);
            let mut reader = LineReader::new();
            if buffered {
                reader = LineReader::new_with_data(b"1".to_vec());
            }
            let mut body = H1Body::new(io, reader, Framing::Chunked, 65536);
            body.watch_upload(&mut upload);
            let (result, ()) = tokio::join!(upload.read(&activity, body.next()), async {
                if !buffered {
                    peer.write_all(b"1").await.unwrap();
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                peer.write_all(b"\r\nx").await.unwrap();
            });
            assert!(matches!(result.unwrap(), Some(BodyFrame::Data(bytes)) if bytes == b"x"[..]));
            assert_eq!(
                upload
                    .read(&activity, body.next())
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::TimedOut
            );
        }
    }

    #[tokio::test]
    async fn buffered_upload_is_active_before_a_ready_final_response() {
        let mut upload = Upload::new(true);
        let (_peer, io) = tokio::io::duplex(256);
        let mut body = H1Body::new(
            io,
            LineReader::new_with_data(b"x".to_vec()),
            Framing::Length(2),
            65536,
        );
        body.watch_upload(&mut upload);
        upload.stop_if_pending();
        assert!(*upload.phase.borrow() == Phase::Active);
        let activity = Activity::new(10);
        assert!(
            matches!(upload.read(&activity, body.next()).await.unwrap(), Some(BodyFrame::Data(bytes)) if bytes == b"x"[..])
        );
    }

    #[tokio::test]
    async fn a_final_response_stops_only_an_expect_pending_upload() {
        for started in [false, true] {
            let upload = Upload::new(true);
            if started {
                upload.started();
            }
            upload.stop_if_pending();
            assert_eq!(*upload.phase.borrow() == Phase::Stopped, !started);
        }
    }
}
