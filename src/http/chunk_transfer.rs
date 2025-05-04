use std::collections::HashMap;

use memchr::{memchr, memmem};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::util::write_all;

// 8 byte length + \r\n = 10 bytes. max chunk size is 0xffffffff which is over 4gb.
// We need to support semi-colon delimited chunk extensions, expect at most 64 bytes.
// TODO: is that enough?
const CHUNK_SIZE_LINE_MAX_LEN: usize = 10 + 64;
const TRAILER_HEADER_LEN: usize = 4096;

pub struct ChunkTransfer {
    state: ChunkTransferState,
    read_size_buf: Vec<u8>,
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
            read_size_buf: Vec::with_capacity(CHUNK_SIZE_LINE_MAX_LEN),
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
        T: AsyncWrite + Unpin + ?Sized,
    {
        use ChunkTransferState::*;

        let mut start_offset = 0usize;

        while start_offset < data.len() {
            let unused = &data[start_offset..data.len()];

            match self.state {
                ReadSize { cached_len } => {
                    // Determine how much we can copy without exceeding the buffer capacity
                    let space_available = CHUNK_SIZE_LINE_MAX_LEN.saturating_sub(cached_len);
                    let copy_len = std::cmp::min(space_available, unused.len());

                    // Append new data to the vector buffer
                    self.read_size_buf.extend_from_slice(&unused[0..copy_len]);
                    let new_cached_len = self.read_size_buf.len(); // Vector keeps track of its length

                    match memmem::find(&self.read_size_buf, b"\r\n") {
                        Some(crlf_index) => {
                            // Found the end of the chunk size line (including extensions)

                            // The complete chunk size line content (excluding CRLF)
                            let line_slice = &self.read_size_buf[0..crlf_index];

                            if line_slice.is_empty() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData, // Use InvalidData for parse errors
                                    "empty chunk size line",
                                ));
                            }

                            // Find the end of the hex part (first ';' or end of line)
                            let hex_end_index =
                                memchr(b';', line_slice).unwrap_or(line_slice.len()); // If no ';', hex part is the whole line slice

                            let hex_part_slice = &line_slice[0..hex_end_index];

                            // Check if the hex part itself is empty (e.g., ";extension\r\n")
                            if hex_part_slice.is_empty() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "chunk size hex part is empty",
                                ));
                            }

                            // Parse only the hex part
                            let hex_str = match std::str::from_utf8(hex_part_slice) {
                                Ok(s) => s,
                                Err(e) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        format!("invalid utf8 in chunk size hex part: {}", e),
                                    ));
                                }
                            };

                            // RFC 7230 Section 4.1.1: Parsers MAY ignore leading/trailing whitespace
                            let trimmed_hex_str = hex_str.trim();
                            if trimmed_hex_str.is_empty() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "chunk size hex part is empty after trim",
                                ));
                            }

                            let chunk_len = match usize::from_str_radix(trimmed_hex_str, 16) {
                                Ok(len) => len,
                                Err(e) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        format!("invalid hex size ('{}'): {}", trimmed_hex_str, e),
                                    ));
                                }
                            };

                            // The total length of the size line including extensions and \r\n
                            let size_header_len = crlf_index + 2;

                            if let Some(ref mut forward_stream) = maybe_forward_stream {
                                write_all(forward_stream, &self.read_size_buf[0..size_header_len])
                                    .await?;
                            }

                            let used_from_unused = size_header_len - cached_len;
                            start_offset += used_from_unused;

                            // Reset the size buffer for the next chunk size line
                            self.read_size_buf.clear();

                            // Transition to the next state
                            if chunk_len > 0 {
                                self.state = ChunkTransferState::ReadData {
                                    chunk_len,
                                    // provided chunk length doesn't include \r\n, but we want to
                                    // include it when forwarding the data chunk itself.
                                    remaining_len: chunk_len + 2, // +2 for data's CRLF
                                };
                            } else {
                                // Zero chunk indicates end of data, potentially followed by trailers
                                // ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailers
                                self.state = ChunkTransferState::ReadTrailer { cached_len: 0 };
                            }
                        }
                        None => {
                            // CRLF not found yet.
                            if self.read_size_buf.len() >= CHUNK_SIZE_LINE_MAX_LEN {
                                // Buffer is full, but still no CRLF
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!(
                                        "chunk size line exceeded max length ({}) without CRLF",
                                        CHUNK_SIZE_LINE_MAX_LEN
                                    ),
                                ));
                            }

                            self.state = ChunkTransferState::ReadSize {
                                cached_len: new_cached_len,
                            };

                            // We consumed all the data provided in this `run` call (`unused`)
                            start_offset += copy_len; // Consume the bytes we copied

                            // If we got here, we've used all the data, the read size buf is still
                            // waiting for a crlf, and we should break out of the while loop.
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
                        write_all(forward_stream, &unused[0..forward_len]).await?;
                    }

                    let new_remaining_len = remaining_len - forward_len;
                    start_offset += forward_len;

                    if new_remaining_len == 0 {
                        // Finished reading chunk data + CRLF, go back to reading size
                        self.state = ChunkTransferState::ReadSize { cached_len: 0 };
                    } else {
                        // Still more data needed for this chunk
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
                            let trailer_line_len = i + 2; // Includes CRLF

                            if let Some(ref mut forward_stream) = maybe_forward_stream {
                                write_all(
                                    forward_stream,
                                    &self.trailer_header_buf[0..trailer_line_len],
                                )
                                .await?;
                            }

                            // Bytes consumed from the current `unused` slice
                            let used_len = trailer_line_len - cached_len;
                            start_offset += used_len;

                            if i > 0 {
                                // Process the trailer header line (content before CRLF)
                                let trailer_header_str =
                                    match std::str::from_utf8(&self.trailer_header_buf[0..i]) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData, // Use InvalidData
                                                format!(
                                                    "failed to parse trailer header utf8: {}",
                                                    e
                                                ),
                                            ));
                                        }
                                    };
                                // Basic parsing, could be more robust (e.g., handling LWS)
                                let tokens: Vec<&str> = trailer_header_str.splitn(2, ':').collect();
                                if tokens.len() != 2 {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData, // Use InvalidData
                                        format!(
                                            "invalid trailer header format: {}",
                                            trailer_header_str
                                        ),
                                    ));
                                }
                                let header_key = tokens[0].trim().to_lowercase();
                                let header_value = tokens[1].trim().to_string(); // Store trimmed value

                                // Prevent overwriting standard headers if they appear as trailers
                                // (Though RFC allows it, some intermediaries might strip them)
                                // TODO: Consider if specific trailers should be disallowed.
                                self.trailer_headers.insert(header_key, header_value);

                                self.state = ChunkTransferState::ReadTrailer { cached_len: 0 };
                            } else {
                                // i == 0 means an empty line "\r\n" was found, signaling the end
                                self.state = ChunkTransferState::Done;
                            }
                        }
                        None => {
                            // CRLF not found yet
                            if new_cached_len == self.trailer_header_buf.len() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other, // Or InvalidData?
                                    "could not read trailer header, line exceeded max length",
                                ));
                            }

                            self.state = ChunkTransferState::ReadTrailer {
                                cached_len: new_cached_len,
                            };

                            start_offset += copy_len; // Consume the copied bytes

                            // Expect to break out of the loop as all `unused` data was consumed
                            assert!(start_offset == data.len());
                        }
                    }
                }

                Done => {
                    // If we are already Done, any further data is an error
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "extra data received after chunked transfer completion",
                    ));
                }
            }
        } // end while start_offset < data.len()

        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.state == ChunkTransferState::Done
    }

    pub fn trailer_headers(&mut self) -> &mut HashMap<String, String> {
        &mut self.trailer_headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufWriter}; // Make sure tokio is a dev-dependency

    // Helper struct to act as a mock AsyncWrite target
    struct MockWriter {
        buf: BufWriter<Vec<u8>>,
    }

    impl MockWriter {
        fn new() -> Self {
            Self {
                buf: BufWriter::new(Vec::new()),
            }
        }

        async fn get_written_data(mut self) -> Vec<u8> {
            self.buf.flush().await.expect("Failed to flush mock writer");
            self.buf.into_inner()
        }
    }

    // Implement AsyncWrite for our MockWriter
    // (Simplified for testing - only needs write_all and flush)
    impl AsyncWrite for MockWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.buf).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.buf).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.buf).poll_shutdown(cx)
        }
    }

    // Helper function to run the transfer process with fragmentation
    async fn run_transfer_fragmented(
        input_fragments: &[&[u8]],
        forward: bool,
    ) -> (std::io::Result<()>, ChunkTransfer, Option<Vec<u8>>) {
        let mut transfer = ChunkTransfer::new();
        let mut writer = if forward {
            Some(MockWriter::new())
        } else {
            None
        };
        let mut final_result = Ok(());

        for (i, fragment) in input_fragments.iter().enumerate() {
            // Check if we are already done *before* calling run again
            if transfer.is_done() && !fragment.is_empty() {
                // If already done and there's more data, it might be an error depending on protocol
                // The `run` method itself handles data after Done *within* a single call.
                // This simulates receiving more data *after* completion.
                final_result = Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Extra data fragment {} received after completion", i),
                ));
                break;
            }

            if fragment.is_empty() {
                // Skip empty fragments if any
                continue;
            }

            let mut opt_writer_ref = writer.as_mut();
            match transfer.run(fragment, &mut opt_writer_ref).await {
                Ok(_) => {}
                Err(e) => {
                    final_result = Err(e);
                    break; // Stop processing on first error
                }
            }
        }

        // Check for error if not done after all fragments processed (unless error already occurred)
        if final_result.is_ok() && !transfer.is_done() {
            // Special case: Input might be valid but incomplete (e.g. missing final 0\r\n\r\n)
            // We consider this an error for testing purposes, assuming complete streams.
            final_result = Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof, // More specific?
                "Transfer did not reach Done state after all fragments",
            ));
        }

        let written_data = if let Some(w) = writer {
            Some(w.get_written_data().await)
        } else {
            None
        };

        (final_result, transfer, written_data)
    }

    #[tokio::test]
    async fn test_single_chunk_no_fragmentation() {
        let input = b"A\r\n0123456789\r\n0\r\n\r\n";
        let expected_forward = input; // Expect everything to be forwarded
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_multiple_chunks_no_fragmentation() {
        let input = b"3\r\nABC\r\n5\r\n12345\r\n0\r\n\r\n";
        let expected_forward = input;
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_zero_length_chunk_termination() {
        let input = b"0\r\n\r\n";
        let expected_forward = input;
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_fragmented_size_line() {
        let fragments = [b"A\r".as_slice(), b"\n0123456789\r\n0\r\n\r\n".as_slice()];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_size_line_mid_hex() {
        let expected_len = 0xAB; // 171 bytes
        let chunk_data = vec![b'X'; expected_len];
        let mut full_input = Vec::new();
        full_input.extend_from_slice(b"AB\r\n");
        full_input.extend_from_slice(&chunk_data);
        full_input.extend_from_slice(b"\r\n0\r\n\r\n");

        let fragments_dynamic = [
            b"A".as_slice(),
            b"B\r\n".as_slice(),
            &chunk_data[0..10],
            &chunk_data[10..],
            b"\r\n0\r\n\r\n".as_slice(),
        ];

        let (result, transfer, written_data) =
            run_transfer_fragmented(&fragments_dynamic, true).await;

        assert!(result.is_ok(), "Result was {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), full_input);
    }

    #[tokio::test]
    async fn test_fragmented_chunk_data() {
        let fragments = [
            b"A\r\n0123".as_slice(),
            b"456789\r\n".as_slice(),
            b"0\r\n\r\n".as_slice(),
        ];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_chunk_crlf() {
        let fragments = [b"A\r\n0123456789\r".as_slice(), b"\n0\r\n\r\n".as_slice()];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_zero_chunk_line() {
        let fragments = [b"A\r\n0123456789\r\n0\r".as_slice(), b"\n\r\n".as_slice()];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_final_crlf() {
        let fragments = [b"0\r\n\r".as_slice(), b"\n".as_slice()];
        let expected_forward = b"0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_with_trailers_no_fragmentation() {
        let input = b"3\r\nABC\r\n0\r\nTrailer-Key: Trailer Value\r\nAnother: Yes\r\n\r\n";
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), input);
        assert_eq!(transfer.trailer_headers().len(), 2);
        assert_eq!(
            transfer.trailer_headers().get("trailer-key"),
            Some(&"Trailer Value".to_string())
        );
        assert_eq!(
            transfer.trailer_headers().get("another"),
            Some(&"Yes".to_string())
        );
    }

    #[tokio::test]
    async fn test_with_trailers_fragmented() {
        let fragments = [
            b"3\r\nABC\r\n0\r\nTrai".as_slice(),
            b"ler-Key: Trailer Value\r\n".as_slice(),
            b"Another: Yes\r\n\r".as_slice(),
            b"\n".as_slice(),
        ];
        let expected_forward =
            b"3\r\nABC\r\n0\r\nTrailer-Key: Trailer Value\r\nAnother: Yes\r\n\r\n";
        let (result, mut transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert_eq!(transfer.trailer_headers().len(), 2);
        assert_eq!(
            transfer.trailer_headers().get("trailer-key"),
            Some(&"Trailer Value".to_string())
        );
        assert_eq!(
            transfer.trailer_headers().get("another"),
            Some(&"Yes".to_string())
        );
    }

    #[tokio::test]
    async fn test_no_forwarding() {
        let input = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], false).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert!(written_data.is_none()); // No writer was provided
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_error_invalid_hex_size() {
        let input = b"G\r\nData\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid hex size ('G')"));
        assert!(!transfer.is_done()); // Should not be done on error
    }

    #[tokio::test]
    async fn test_error_empty_size_line_content() {
        // Only CRLF on the size line
        let input = b"\r\nData\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("empty chunk size line"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_size_line_only_extension() {
        // Starts with ';', no hex part
        let input = b";extension\r\nData\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("chunk size hex part is empty"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_size_line_too_long() {
        // CHUNK_SIZE_LINE_MAX_LEN is 64. Input > 64 bytes before \r\n
        let long_line = vec![b'1'; CHUNK_SIZE_LINE_MAX_LEN];
        let mut input = long_line;
        input.extend_from_slice(b"A\r\nData\r\n"); // Add one more byte to exceed limit

        let (result, transfer, _) = run_transfer_fragmented(&[&input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other); // Buffer full error
        assert!(err.to_string().contains("exceeded max length"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_trailer_line_too_long() {
        let mut input = b"0\r\n".to_vec();
        // TRAILER_HEADER_LEN is 4096. Create a line longer than that.
        let long_trailer = vec![b'a'; TRAILER_HEADER_LEN + 1];
        input.extend_from_slice(&long_trailer);
        input.extend_from_slice(b"\r\n\r\n");

        let (result, transfer, _) = run_transfer_fragmented(&[&input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other); // Buffer full error
        assert!(err
            .to_string()
            .contains("could not read trailer header, line exceeded max length"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_invalid_trailer_format() {
        let input = b"0\r\nInvalid Header Line\r\n\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid trailer header format"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_data_after_final_trailer_crlf_same_run() {
        // This error happens if more data is provided *within the same `run` call* after the final \r\n
        let input = b"0\r\nTrailer: Val\r\n\r\nExtraData";
        // run_transfer_fragmented calls run once for the whole slice
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err
            .to_string()
            .contains("extra data received after chunked transfer completion"));
        // State becomes Done *before* the error check for extra data within the *same* run call.
        assert_eq!(transfer.state, ChunkTransferState::Done);
    }

    #[tokio::test]
    async fn test_error_data_after_final_trailer_crlf_separate_run() {
        // This error happens if more data is provided *in a subsequent `run` call* after the final \r\n
        let fragments = [b"0\r\n\r\n".as_slice(), b"ExtraData".as_slice()];
        // run_transfer_fragmented calls run for each fragment
        let (result, transfer, _) = run_transfer_fragmented(&fragments, true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        // This error comes from the helper function detecting data after done state was reached.
        assert!(err
            .to_string()
            .contains("Extra data fragment 1 received after completion"));
        assert!(transfer.is_done()); // Should be done after the first fragment
    }

    #[tokio::test]
    async fn test_state_transitions_detailed() {
        let mut transfer = ChunkTransfer::new();
        let mut writer = MockWriter::new();
        let mut opt_writer_ref = Some(&mut writer as &mut (dyn AsyncWrite + Unpin));

        // Initial state
        assert_eq!(
            transfer.state,
            ChunkTransferState::ReadSize { cached_len: 0 }
        );
        assert!(transfer.read_size_buf.is_empty());

        // 1. Send partial size "A"
        transfer.run(b"A", &mut opt_writer_ref).await.unwrap();
        assert_eq!(
            transfer.state,
            ChunkTransferState::ReadSize { cached_len: 1 } // State reflects vec len
        );
        assert_eq!(&transfer.read_size_buf, b"A");

        // 2. Send rest of size ("\r\n") and partial data ("0123")
        // Input: b"\r\n0123"
        transfer
            .run(b"\r\n0123", &mut opt_writer_ref)
            .await
            .unwrap();
        // Should have parsed "A" (10), forwarded "A\r\n". Consumed "\r\n" from input.
        // Then started reading data. Forwarded "0123". Consumed "0123" from input.
        // State should now be ReadData, expecting 10 bytes total chunk data + 2 (\r\n) = 12 bytes.
        // We forwarded 4 bytes data ("0123"), so 12 - 4 = 8 remaining (6 data + CRLF).
        match transfer.state {
            ChunkTransferState::ReadData {
                chunk_len,
                remaining_len,
            } => {
                assert_eq!(chunk_len, 10);
                assert_eq!(remaining_len, 10 + 2 - 4); // chunk_len + \r\n - forwarded_data
            }
            _ => panic!("Incorrect state: {:?}", transfer.state),
        }
        assert!(transfer.read_size_buf.is_empty()); // Size buf cleared

        // 3. Send rest of data ("456789\r\n") and partial next size ("5\r")
        // Input: b"456789\r\n5\r"
        transfer
            .run(b"456789\r\n5\r", &mut opt_writer_ref)
            .await
            .unwrap();
        // Should have forwarded "456789\r\n". Consumed "456789\r\n" from input. Chunk finished.
        // Started reading next size. Read "5\r". Consumed "5\r" from input.
        // Waiting for "\n" for the size line.
        assert_eq!(
            transfer.state,
            ChunkTransferState::ReadSize { cached_len: 2 } // State reflects vec len
        );
        assert_eq!(&transfer.read_size_buf, b"5\r"); // Contains "5\r"

        // 4. Send rest of size ("\n"), all data for second chunk ("ABCDE\r\n"), zero chunk ("0\r\n"), and partial trailer ("Trailer:")
        // Input: b"\nABCDE\r\n0\r\nTrailer:"
        transfer
            .run(b"\nABCDE\r\n0\r\nTrailer:", &mut opt_writer_ref)
            .await
            .unwrap();
        // Should parse size 5. Forward "5\r\n". Consume "\n".
        // Read data + CRLF. Forward "ABCDE\r\n". Consume "ABCDE\r\n".
        // Read size 0. Forward "0\r\n". Consume "0\r\n".
        // Start reading trailers. Read "Trailer:". Consume "Trailer:".
        // Waiting for "\r\n" for trailer line.
        match transfer.state {
            ChunkTransferState::ReadTrailer { cached_len } => {
                // Trailer buffer holds the partial line
                assert_eq!(cached_len, 8); // "Trailer:" length is 8
                assert_eq!(&transfer.trailer_header_buf[0..cached_len], b"Trailer:");
            }
            _ => panic!("Incorrect state: {:?}", transfer.state),
        }
        assert!(transfer.read_size_buf.is_empty()); // Size buf still empty

        // 5. Send rest of trailer (" Value\r\n") and final CRLFs ("\r\n")
        // Input: b" Value\r\n\r\n"
        transfer
            .run(b" Value\r\n\r\n", &mut opt_writer_ref)
            .await
            .unwrap();
        // Should read " Value\r\n". Parse trailer "Trailer: Value". Forward "Trailer: Value\r\n". Consume " Value\r\n".
        // Should read "\r\n". This is the empty line ending trailers. Forward "\r\n". Consume "\r\n".
        // State becomes Done.
        assert!(transfer.is_done());
        assert_eq!(
            transfer.trailer_headers().get("trailer"), // Keys are lowercased
            Some(&"Value".to_string())                 // Values stored as trimmed strings
        );

        // Check final forwarded data
        let expected_forward = b"A\r\n0123456789\r\n5\r\nABCDE\r\n0\r\nTrailer: Value\r\n\r\n";
        let written_data = writer.get_written_data().await;
        assert_eq!(written_data, expected_forward);
    }

    #[tokio::test]
    async fn test_chunk_extension_ignored() {
        // Chunk extensions are allowed but generally ignored by intermediaries unless specified.
        // This implementation should ignore them *for parsing size* but forward them.
        let input = b"A;extension=value\r\n0123456789\r\n0\r\n\r\n";
        let expected_forward = input; // Forward includes the extension part of the size line
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_chunk_extension_fragmented() {
        let fragments = [
            b"A;ext".as_slice(),
            b"ension=value\r\n".as_slice(),
            b"0123456789\r\n".as_slice(),
            b"0;".as_slice(), // Zero chunk with extension
            b"last=chunk\r\n".as_slice(),
            b"\r\n".as_slice(), // End of trailers (empty)
        ];
        let expected_forward = b"A;extension=value\r\n0123456789\r\n0;last=chunk\r\n\r\n";
        let (result, mut transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_chunk_extension_with_space_before_crlf() {
        // While discouraged, parsers should handle optional whitespace.
        let input = b"A ; extension=value \r\n0123456789\r\n0\r\n\r\n";
        // We parse 'A', ignoring ';...' but forward the original line
        let expected_forward = input;
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok(), "Result was: {:?}", result);
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }
}
