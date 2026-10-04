use tokio::net::{lookup_host, ToSocketAddrs};

pub async fn with_timeout<T>(
    seconds: Option<std::num::NonZeroU64>,
    operation: &str,
    future: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match seconds {
        Some(seconds) => {
            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(seconds.get()))
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Timeout is too large"))?;
            tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("{operation} timed out"),
                    )
                })?
        }
        None => future.await,
    }
}

pub async fn resolve_host<T>(host: T) -> std::io::Result<std::net::SocketAddr>
where
    T: ToSocketAddrs,
{
    lookup_host(host)
        .await?
        .next()
        .ok_or_else(|| std::io::Error::other("Unable to resolve host"))
}
