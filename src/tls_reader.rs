/// Cancellation-safe buffered reader for TLS parsing.
///
/// This reader uses `stream.read()` instead of `read_exact()` to ensure
/// cancellation safety. It maintains a buffer that can be retrieved even
/// if parsing fails, allowing the data to be replayed for other purposes.

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Maximum TLS frame size (5 byte header + 65535 byte payload)
const TLS_FRAME_MAX_LEN: usize = 5 + 65535;

/// Cancellation-safe buffered reader for TLS parsing
/// Uses stream.read() instead of read_exact() for cancellation safety
pub struct TlsReader {
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl TlsReader {
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; TLS_FRAME_MAX_LEN],
            pos: 0,
            end: 0,
        }
    }

    /// Ensure at least `len` more bytes are buffered (cancellation-safe)
    /// Uses stream.read() instead of read_exact() for cancellation safety
    pub async fn ensure_bytes(&mut self, stream: &mut TcpStream, len: usize) -> std::io::Result<()> {
        let needed = self.pos + len;
        if needed > self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Requested data exceeds buffer size"),
            ));
        }

        // Read until we have enough bytes
        while self.end < needed {
            // If buffer would be too small after compaction, error out
            if needed - self.pos > self.buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Request too large for buffer",
                ));
            }

            // Compact buffer if needed
            if self.end == self.buf.len() {
                if self.pos == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Buffer full but need more data",
                    ));
                }
                self.buf.copy_within(self.pos..self.end, 0);
                self.end -= self.pos;
                self.pos = 0;
            }

            // Cancellation-safe read (not read_exact!)
            loop {
                match stream.read(&mut self.buf[self.end..]).await {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while reading TLS data",
                        ));
                    }
                    Ok(n) => {
                        self.end += n;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(())
    }

    /// Read a single u8
    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        if self.pos >= self.end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "buffer underflow",
            ));
        }
        let val = self.buf[self.pos];
        self.pos += 1;
        Ok(val)
    }

    /// Read a u16 in big-endian
    pub fn read_u16_be(&mut self) -> std::io::Result<u16> {
        if self.pos + 2 > self.end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "buffer underflow",
            ));
        }
        let val = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a u24 in big-endian
    pub fn read_u24_be(&mut self) -> std::io::Result<u32> {
        if self.pos + 3 > self.end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "buffer underflow",
            ));
        }
        let val = u32::from_be_bytes([0, self.buf[self.pos], self.buf[self.pos + 1], self.buf[self.pos + 2]]);
        self.pos += 3;
        Ok(val)
    }

    /// Skip n bytes
    pub fn skip(&mut self, n: usize) -> std::io::Result<()> {
        if self.pos + n > self.end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "buffer underflow",
            ));
        }
        self.pos += n;
        Ok(())
    }

    /// Read a slice of bytes
    pub fn read_slice(&mut self, len: usize) -> std::io::Result<&[u8]> {
        if self.pos + len > self.end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "buffer underflow",
            ));
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Read a UTF-8 string
    pub fn read_str(&mut self, len: usize) -> std::io::Result<&str> {
        let slice = self.read_slice(len)?;
        std::str::from_utf8(slice).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid UTF-8: {}", e),
            )
        })
    }

    /// Get the current position
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Check if all data has been consumed
    pub fn is_consumed(&self) -> bool {
        self.pos >= self.end
    }

    /// Get all buffered data (for forwarding/replaying)
    pub fn buffered_data(&self) -> &[u8] {
        &self.buf[0..self.end]
    }

    /// Consume the reader and return the internal buffer and positions
    /// Returns (buffer, position, end) where buffer[0..end] contains all read data
    /// and buffer[position..end] contains unread data
    pub fn into_inner(self) -> (Vec<u8>, usize, usize) {
        (self.buf, self.pos, self.end)
    }
}
