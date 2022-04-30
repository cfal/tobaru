use async_trait::async_trait;
use std::os::unix::io::{AsRawFd, FromRawFd};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

#[async_trait]
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {
    async fn try_shutdown(&mut self) -> std::io::Result<()>;
}

#[async_trait]
impl AsyncStream for TcpStream {
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        let _ = self.shutdown().await;

        // Unfortunately, AsyncWriteExt::shutdown/AsyncWrite::poll_shutdown only ends up
        // calling std::net::Shutdown::Write and seems to leave sockets in
        // CLOSE-WAIT/TIME-WAIT/FIN-WAIT states.
        // If the function signature for this returned self instead of &mut self,
        // we could do:
        //
        // self.to_std().shutdown(std::net::Shutdown::Both)
        //
        // but tokio_native_tls has no function to allow going back to a
        // tokio/mio/std stream.
        // So do it the hacky way.

        let std_stream = std::mem::ManuallyDrop::new(unsafe {
            std::net::TcpStream::from_raw_fd(self.as_raw_fd())
        });
        std_stream.shutdown(std::net::Shutdown::Both)
    }
}

#[async_trait]
impl AsyncStream for UnixStream {
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        let _ = self.shutdown().await;

        // Unfortunately, AsyncWriteExt::shutdown/AsyncWrite::poll_shutdown only ends up
        // calling std::net::Shutdown::Write and seems to leave sockets in
        // CLOSE-WAIT/TIME-WAIT/FIN-WAIT states.
        // If the function signature for this returned self instead of &mut self,
        // we could do:
        //
        // self.to_std().shutdown(std::net::Shutdown::Both)
        //
        // but tokio_native_tls has no function to allow going back to a
        // tokio/mio/std stream.
        // So do it the hacky way.

        let std_stream = std::mem::ManuallyDrop::new(unsafe {
            std::net::TcpStream::from_raw_fd(self.as_raw_fd())
        });
        std_stream.shutdown(std::net::Shutdown::Both)
    }
}

#[async_trait]
impl<IO> AsyncStream for tokio_rustls::client::TlsStream<IO>
where
    IO: AsyncStream,
{
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        self.shutdown().await
    }
}

#[async_trait]
impl<IO> AsyncStream for tokio_rustls::server::TlsStream<IO>
where
    IO: AsyncStream,
{
    async fn try_shutdown(&mut self) -> std::io::Result<()> {
        self.shutdown().await
    }
}
