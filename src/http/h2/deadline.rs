use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

pub(super) struct HeaderDeadline {
    deadline: watch::Sender<Option<Instant>>,
    explicit: bool,
    uploaded: AtomicBool,
}

impl HeaderDeadline {
    pub fn upload_complete(&self) -> bool {
        self.uploaded.load(Ordering::Acquire)
    }
    pub fn new(explicit: Option<u64>, has_body: bool, expect: bool) -> Self {
        let initial = (explicit.is_some() || !has_body || expect)
            .then(|| Instant::now() + Duration::from_secs(explicit.unwrap_or(30)));
        Self {
            deadline: watch::channel(initial).0,
            explicit: explicit.is_some(),
            uploaded: AtomicBool::new(!has_body),
        }
    }

    pub fn uploaded(&self) {
        self.uploaded.store(true, Ordering::Release);
        if !self.explicit {
            self.deadline
                .send_replace(Some(Instant::now() + Duration::from_secs(30)));
        }
    }

    pub fn informational(&self, status: http::StatusCode) {
        if status == http::StatusCode::CONTINUE
            && !self.explicit
            && !self.uploaded.load(Ordering::Acquire)
        {
            self.deadline.send_replace(None);
        }
    }

    pub async fn wait<T>(
        &self,
        operation: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let mut deadline = self.deadline.subscribe();
        tokio::pin!(operation);
        loop {
            let instant = *deadline.borrow_and_update();
            tokio::select! {
                result = &mut operation => return result,
                _ = deadline.changed() => {},
                _ = async { match instant { Some(instant) => tokio::time::sleep_until(instant).await, None => std::future::pending::<()>().await } } => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP response header deadline"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn default_deadline_starts_after_upload_but_explicit_is_absolute() {
        let default = HeaderDeadline::new(None, true, false);
        let explicit = HeaderDeadline::new(Some(30), true, false);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            default.wait(std::future::pending::<io::Result<()>>())
        )
        .await
        .is_err());
        assert_eq!(
            explicit
                .wait(std::future::pending::<io::Result<()>>())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        default.uploaded();
        assert!(default.wait(async { Ok(()) }).await.is_ok());
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(default
            .wait(std::future::pending::<io::Result<()>>())
            .await
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn hints_do_not_extend_expect_deadline() {
        let deadline = HeaderDeadline::new(None, true, true);
        tokio::time::advance(Duration::from_secs(20)).await;
        deadline.informational(http::StatusCode::EARLY_HINTS);
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(deadline
            .wait(std::future::pending::<io::Result<()>>())
            .await
            .is_err());
    }
}
