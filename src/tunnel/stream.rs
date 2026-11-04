use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::state::{Permit, Revocation};
use crate::async_stream::AsyncStream;

pub type ServerIo = tokio_rustls::server::TlsStream<TcpStream>;

pub struct Channel {
    pub io: ServerIo,
    pub _accepted: Permit,
    pub _physical: Permit,
}

pub struct DataStream {
    pub channel: Channel,
    pub _active: Permit,
    pub _revocation: Revocation,
}

impl AsyncRead for DataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for DataStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.channel.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel.io).poll_shutdown(cx)
    }
}

#[async_trait::async_trait]
impl AsyncStream for DataStream {
    async fn try_shutdown(&mut self) -> io::Result<()> {
        self.channel.io.try_shutdown().await
    }
}
