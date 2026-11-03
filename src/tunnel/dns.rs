use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct Resolver(Arc<Semaphore>);

impl Default for Resolver {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(16)))
    }
}

impl Resolver {
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let host = host.to_owned();
        self.lookup(move || {
            (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::other("Unable to resolve tunnel host"))
        })
        .await
    }

    async fn lookup(
        &self,
        resolve: impl FnOnce() -> io::Result<SocketAddr> + Send + 'static,
    ) -> io::Result<SocketAddr> {
        let permit = self
            .0
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        tokio::task::spawn_blocking(move || {
            // Cancellation of the waiter cannot release non-abortable resolver work.
            let _permit = permit;
            resolve()
        })
        .await
        .map_err(io::Error::other)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_waiters_do_not_release_running_dns_jobs() {
        let resolver = Resolver(Arc::new(Semaphore::new(1)));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let first = resolver.clone();
        let task = tokio::spawn(async move {
            first
                .lookup(move || {
                    let _ = started.send(());
                    blocked.recv().unwrap();
                    Ok("127.0.0.1:1".parse().unwrap())
                })
                .await
        });
        ready.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(resolver.0.available_permits(), 0);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            resolver.lookup(|| panic!("second lookup started before the first finished"))
        )
        .await
        .is_err());
        assert_eq!(resolver.resolve("127.0.0.1", 2).await.unwrap().port(), 2);
        release.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(2), resolver.0.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(resolver.0.available_permits(), 1);
    }
}
