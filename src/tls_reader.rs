use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::util::allocate_vec;

// Bound all buffered wire bytes, including headers of fragmented records.
pub const TLS_BUFFER_MAX_LEN: usize = 5 + 65535;

pub struct TlsReader {
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl TlsReader {
    pub fn new() -> Self {
        Self {
            buf: allocate_vec(TLS_BUFFER_MAX_LEN),
            pos: 0,
            end: 0,
        }
    }

    pub fn starts_with_tls(&self) -> bool {
        self.end > 0 && matches!(self.buf[0], 0x14..=0x17)
    }

    pub async fn ensure_bytes(
        &mut self,
        stream: &mut TcpStream,
        len: usize,
    ) -> std::io::Result<()> {
        let needed = self
            .pos
            .checked_add(len)
            .filter(|&n| n <= self.buf.len())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLS ClientHello exceeds buffer size",
                )
            })?;
        while self.end < needed {
            // Keep every byte for replay, even if this read is later cancelled.
            match stream.read(&mut self.buf[self.end..]).await {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF while reading TLS data",
                    ))
                }
                Ok(n) => self.end += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn read_slice(&mut self, len: usize) -> std::io::Result<&[u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&n| n <= self.end)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "buffer underflow")
            })?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn into_inner(self) -> (Vec<u8>, usize, usize) {
        (self.buf, self.pos, self.end)
    }
}
