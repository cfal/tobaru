use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct HeaderDeadline {
    deadline: Option<Instant>,
    uploaded: AtomicBool,
}

impl HeaderDeadline {
    pub fn upload_complete(&self) -> bool {
        self.uploaded.load(Ordering::Acquire)
    }
    pub fn new(seconds: Option<u64>, has_body: bool) -> io::Result<Self> {
        let deadline = seconds
            .map(|seconds| {
                Instant::now()
                    .checked_add(Duration::from_secs(seconds))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Timeout is too large")
                    })
            })
            .transpose()?;
        Ok(Self {
            deadline,
            uploaded: AtomicBool::new(!has_body),
        })
    }

    pub fn uploaded(&self) {
        self.uploaded.store(true, Ordering::Release);
    }

    pub async fn wait<T>(
        &self,
        operation: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        match self.deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, operation)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HTTP response header deadline")
                })?,
            None => operation.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn omitted_deadline_stays_disabled_before_and_after_upload() {
        for has_body in [false, true] {
            let deadline = HeaderDeadline::new(None, has_body).unwrap();
            for _ in 0..2 {
                deadline
                    .wait(async {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Ok(())
                    })
                    .await
                    .unwrap();
                deadline.uploaded();
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_deadline_is_absolute_and_upload_does_not_extend_it() {
        for complete in [false, true] {
            let deadline = HeaderDeadline::new(Some(30), true).unwrap();
            tokio::time::advance(Duration::from_secs(20)).await;
            if complete {
                deadline.uploaded();
            }
            let start = Instant::now();
            let error = deadline
                .wait(std::future::pending::<io::Result<()>>())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(start.elapsed(), Duration::from_secs(10));
        }
    }

    #[tokio::test]
    async fn excessive_deadlines_are_rejected_without_panicking() {
        assert!(HeaderDeadline::new(Some(u64::MAX), false).is_err());
    }
}
