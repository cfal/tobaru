use std::collections::HashMap;

use memchr::memmem;
use tokio::io::{AsyncWrite, AsyncWriteExt};

// 8 byte length + \r\n. max chunk size is 0xffffffff which is over 4gb.
const CHUNK_SIZE_LEN: usize = 10;
const TRAILER_HEADER_LEN: usize = 4096;

pub struct ChunkTransfer {
    state: ChunkTransferState,
    read_size_buf: [u8; CHUNK_SIZE_LEN],
    trailer_header_buf: [u8; TRAILER_HEADER_LEN],
    trailer_headers: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
enum ChunkTransferState {
    ReadSize {
        cached_len: usize,
    },
    ReadData {
        chunk_len: usize,
        remaining_len: usize,
    },
    ReadTrailer {
        cached_len: usize,
    },
    Done,
}

impl ChunkTransfer {
    pub fn new() -> Self {
        Self {
            state: ChunkTransferState::ReadSize { cached_len: 0 },
            read_size_buf: [0u8; CHUNK_SIZE_LEN],
            trailer_header_buf: [0u8; TRAILER_HEADER_LEN],
            trailer_headers: HashMap::new(),
        }
    }

    pub async fn run<T>(
        &mut self,
        data: &[u8],
        maybe_forward_stream: &mut Option<&mut T>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        use ChunkTransferState::*;

        let mut start_offset = 0usize;

        while start_offset < data.len() {
            let unused = &data[start_offset..data.len()];

            match self.state {
                ReadSize { cached_len } => {
                    let copy_len = std::cmp::min(CHUNK_SIZE_LEN - cached_len, unused.len());
                    let new_cached_len = cached_len + copy_len;
                    self.read_size_buf[cached_len..new_cached_len]
                        .copy_from_slice(&unused[0..copy_len]);

                    match memmem::find(&self.read_size_buf[0..new_cached_len], b"\r\n") {
                        Some(i) => {
                            if i == 0 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "no chunk length",
                                ));
                            }

                            let hex_str = match std::str::from_utf8(&self.read_size_buf[0..i]) {
                                Ok(s) => s,
                                Err(e) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        format!("invalid hex string: {}", e),
                                    ));
                                }
                            };

                            let chunk_len = match usize::from_str_radix(hex_str, 16) {
                                Ok(len) => len,
                                Err(e) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        format!("invalid hex size ({}): {}", hex_str, e),
                                    ));
                                }
                            };

                            // the hex string and \r\n
                            let size_header_len = i + 2;

                            if let Some(ref mut forward_stream) = maybe_forward_stream {
                                // forward the size header.
                                forward_stream
                                    .write_all(&self.read_size_buf[0..size_header_len])
                                    .await?;
                            }

                            // this many new bytes were consumed to get to the full size header
                            let used_len = size_header_len - cached_len;

                            start_offset += used_len;

                            if chunk_len > 0 {
                                self.state = ChunkTransferState::ReadData {
                                    chunk_len,
                                    // provided chunk length doesn't include \r\n, but we want to
                                    // include it when forwarding.
                                    remaining_len: chunk_len + 2,
                                };
                            } else {
                                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
                                self.state = ChunkTransferState::ReadTrailer { cached_len: 0 };
                            }
                        }
                        None => {
                            if new_cached_len == self.read_size_buf.len() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "could not read chunk length in initial bytes",
                                ));
                            }
                            self.state = ChunkTransferState::ReadSize {
                                cached_len: new_cached_len,
                            };

                            start_offset += copy_len;

                            // If we got here, we've used all the data, the read size buf is still
                            // waiting for a crlf, and we should break out automatically.
                            assert!(start_offset == data.len());
                        }
                    }
                }
                ReadData {
                    chunk_len,
                    remaining_len,
                } => {
                    let forward_len = std::cmp::min(unused.len(), remaining_len);
                    if let Some(ref mut forward_stream) = maybe_forward_stream {
                        forward_stream.write_all(&unused[0..forward_len]).await?;
                    }

                    let new_remaining_len = remaining_len - forward_len;
                    start_offset += forward_len;

                    if new_remaining_len == 0 {
                        self.state = ChunkTransferState::ReadSize { cached_len: 0 };
                    } else {
                        self.state = ChunkTransferState::ReadData {
                            chunk_len,
                            remaining_len: new_remaining_len,
                        }
                    }
                }

                ReadTrailer { cached_len } => {
                    let copy_len = std::cmp::min(TRAILER_HEADER_LEN - cached_len, unused.len());
                    let new_cached_len = cached_len + copy_len;
                    self.trailer_header_buf[cached_len..new_cached_len]
                        .copy_from_slice(&unused[0..copy_len]);

                    match memmem::find(&self.trailer_header_buf[0..new_cached_len], b"\r\n") {
                        Some(i) => {
                            let size_header_len = i + 2;

                            // this many new bytes were consumed to get to the full size header
                            let used_len = size_header_len - cached_len;

                            start_offset += used_len;

                            if i > 0 {
                                let trailer_header_str =
                                    match std::str::from_utf8(&self.trailer_header_buf[0..i]) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::Other,
                                                format!("failed to parse trailer header: {}", e),
                                            ));
                                        }
                                    };
                                let tokens: Vec<&str> = trailer_header_str.splitn(2, ':').collect();
                                if tokens.len() != 2 {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        format!("invalid trailer header: {}", trailer_header_str),
                                    ));
                                }
                                let header_key = tokens[0].trim().to_lowercase();
                                let header_value = tokens[1].trim().to_string();
                                self.trailer_headers.insert(header_key, header_value);

                                self.state = ChunkTransferState::ReadTrailer { cached_len: 0 };
                            } else {
                                // i == 0 - empty line
                                // we've reached the end of the request/response
                                if start_offset < data.len() {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "extra data after trailers",
                                    ));
                                }
                                self.state = ChunkTransferState::Done;
                            }
                        }
                        None => {
                            if new_cached_len == self.trailer_header_buf.len() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "could not read trailer header, line too long",
                                ));
                            }
                            self.state = ChunkTransferState::ReadTrailer {
                                cached_len: new_cached_len,
                            };

                            start_offset += copy_len;

                            // If we got here, we've used all the data, the read size buf is still
                            // waiting for a crlf, and we should break out automatically.
                            assert!(start_offset == data.len());
                        }
                    }
                }

                Done => {
                    panic!("loop did not exit on done");
                }
            }
        }

        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.state == ChunkTransferState::Done
    }

    pub fn trailer_headers(&mut self) -> &mut HashMap<String, String> {
        &mut self.trailer_headers
    }
}
