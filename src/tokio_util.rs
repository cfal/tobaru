use tokio::net::{lookup_host, ToSocketAddrs};

pub async fn resolve_host<T>(host: T) -> std::io::Result<std::net::SocketAddr>
where
    T: ToSocketAddrs,
{
    lookup_host(host)
        .await?
        .next()
        .ok_or_else(|| std::io::Error::other("Unable to resolve host"))
}
