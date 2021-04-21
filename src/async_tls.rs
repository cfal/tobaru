use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub trait AsyncTlsFactory: Unpin + Send + Sync {
    fn create_acceptor(&self, cert_bytes: &[u8], key_bytes: &[u8]) -> Box<dyn AsyncTlsAcceptor>;
    // TODO: support different configs/certs.
    fn create_connector(&self) -> Box<dyn AsyncTlsConnector>;
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

#[async_trait]
pub trait AsyncTlsAcceptor: Unpin + Send + Sync {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Box<dyn AsyncStream>>;
}

#[async_trait]
pub trait AsyncTlsConnector: Unpin + Send + Sync {
    async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> std::io::Result<Box<dyn AsyncStream>>;
}

impl AsyncStream for TcpStream {}
