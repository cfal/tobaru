use memchr::memchr;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::util::allocate_vec;

const BUFFER_SIZE: usize = 32768;

pub struct LineReader {
    buf: Box<[u8]>,
    start_offset: usize,
    end_offset: usize,
}

impl LineReader {
    pub fn new() -> Self {
        Self {
            buf: allocate_vec(BUFFER_SIZE).into_boxed_slice(),
            start_offset: 0usize,
            end_offset: 0usize,
        }
    }

    /// Create a LineReader pre-populated with initial data.
    /// This is used when we've already buffered some data (e.g., from a failed TLS parse)
    /// and need to parse it as HTTP. The data buffer is consumed directly without cloning.
    /// If the data is smaller than BUFFER_SIZE, it will be extended to BUFFER_SIZE to allow
    /// reading additional data from the stream. If larger, the data buffer itself is used
    /// as-is (allowing larger initial buffers when needed).
    pub fn new_with_data(mut data: Vec<u8>) -> Self {
        let data_len = data.len();

        if data_len < BUFFER_SIZE {
            // Extend the buffer to BUFFER_SIZE to allow reading more data
            data.resize(BUFFER_SIZE, 0);
            Self {
                buf: data.into_boxed_slice(),
                start_offset: 0,
                end_offset: data_len,
            }
        } else {
            // Use the data buffer directly (larger than standard size)
            Self {
                buf: data.into_boxed_slice(),
                start_offset: 0,
                end_offset: data_len,
            }
        }
    }

    fn reset_buf_offset(&mut self) {
        if self.start_offset == 0 {
            return;
        }
        self.buf.copy_within(self.start_offset..self.end_offset, 0);
        self.end_offset -= self.start_offset;
        self.start_offset = 0;
    }

    pub async fn read_line_bytes<T>(&mut self, stream: &mut T) -> std::io::Result<&mut [u8]>
    where
        T: AsyncRead + Unpin,
    {
        let mut search_start_offset = self.start_offset;
        loop {
            let search_end_offset = self.end_offset;
            match memchr(b'\n', &self.buf[search_start_offset..search_end_offset]) {
                Some(pos) => {
                    let newline_pos = search_start_offset + pos;
                    if newline_pos == self.start_offset || self.buf[newline_pos - 1] != b'\r' {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Line is not terminated by CRLF",
                        ));
                    }
                    // strip crlf
                    let line = &mut self.buf[self.start_offset..newline_pos - 1];
                    let new_start_offset = newline_pos + 1;
                    if new_start_offset == search_end_offset {
                        self.start_offset = 0;
                        self.end_offset = 0;
                    } else {
                        self.start_offset = new_start_offset;
                    }
                    return Ok(line);
                }
                None => {
                    // There are no more newlines.
                    let previous_start_offset = self.start_offset;

                    self.read(stream).await?;

                    // Only search through new data.
                    if previous_start_offset != self.start_offset {
                        // this can only move to zero when reset_buf_offset is called.
                        assert!(self.start_offset == 0);
                        search_start_offset = search_end_offset - previous_start_offset;
                    } else {
                        search_start_offset = search_end_offset;
                    }
                }
            }
        }
    }

    pub async fn read_line<T>(&mut self, stream: &mut T) -> std::io::Result<&str>
    where
        T: AsyncRead + Unpin,
    {
        let line_bytes = self.read_line_bytes(stream).await?;
        std::str::from_utf8(line_bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to decode utf8: {}", e),
            )
        })
    }

    pub fn unparsed_data(&self) -> &[u8] {
        &self.buf[self.start_offset..self.end_offset]
    }

    pub fn into_buf(self) -> Box<[u8]> {
        self.buf
    }

    async fn read<T>(&mut self, stream: &mut T) -> std::io::Result<()>
    where
        T: AsyncRead + Unpin,
    {
        // Note that read() needs to work for blocking I/O. So we need to return
        // immediately after a single read() call.
        if self.is_cache_full() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "cache is full, line is too long",
            ));
        }

        self.reset_buf_offset();

        loop {
            match stream.read(&mut self.buf[self.end_offset..]).await {
                Ok(len) => {
                    if len == 0 {
                        // EOF
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "EOF while reading",
                        ));
                    }
                    self.end_offset += len;
                    return Ok(());
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn is_cache_full(&self) -> bool {
        self.start_offset == 0 && self.end_offset == self.buf.len()
    }
}
