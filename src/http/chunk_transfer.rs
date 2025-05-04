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
        T: AsyncWrite + Unpin + ?Sized,
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

                            if let Some(ref mut forward_stream) = maybe_forward_stream {
                                forward_stream
                                    .write_all(&self.trailer_header_buf[0..size_header_len])
                                    .await?;
                            }

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
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "extra data after chunked transfer ended",
                    ));
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

        for fragment in input_fragments {
            let mut opt_writer_ref = writer.as_mut();
            match transfer.run(fragment, &mut opt_writer_ref).await {
                Ok(_) => {}
                Err(e) => {
                    final_result = Err(e);
                    break; // Stop processing on first error
                }
            }
            // Break early if done, simulating connection closure potentially
            if transfer.is_done() && final_result.is_ok() {
                // Check if there's unexpected data remaining in the current fragment
                // Note: This check depends on how the caller would handle extra data.
                // Here, we assume any data *after* Done is an error if run is called again.
                // The original code has an error check *inside* run for extra data within a single call
                // after trailers. This test simulates calling run *again* after Done.
                // For a more robust test, we'd need to know the exact calling pattern.
            }
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

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_multiple_chunks_no_fragmentation() {
        let input = b"3\r\nABC\r\n5\r\n12345\r\n0\r\n\r\n";
        let expected_forward = input;
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_zero_length_chunk_termination() {
        let input = b"0\r\n\r\n";
        let expected_forward = input;
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }

    #[tokio::test]
    async fn test_fragmented_size_line() {
        let fragments = [b"A\r".as_slice(), b"\n0123456789\r\n0\r\n\r\n".as_slice()];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_size_line_mid_hex() {
        let fragments = [
            b"A".as_slice(),
            b"B\r\n".as_slice(),
            b"Data chunk...\r\n0\r\n\r\n".as_slice(),
        ]; // Example, assumes chunk len 0xAB
        let expected_len = 0xAB;
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

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_chunk_crlf() {
        let fragments = [b"A\r\n0123456789\r".as_slice(), b"\n0\r\n\r\n".as_slice()];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_zero_chunk_line() {
        let fragments = [b"A\r\n0123456789\r\n0\r".as_slice(), b"\n\r\n".as_slice()];
        let expected_forward = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_fragmented_final_crlf() {
        let fragments = [b"0\r\n\r".as_slice(), b"\n".as_slice()];
        let expected_forward = b"0\r\n\r\n";
        let (result, transfer, written_data) = run_transfer_fragmented(&fragments, true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
    }

    #[tokio::test]
    async fn test_with_trailers_no_fragmentation() {
        let input = b"3\r\nABC\r\n0\r\nTrailer-Key: Trailer Value\r\nAnother: Yes\r\n\r\n";
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok());
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

        assert!(result.is_ok());
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

        assert!(result.is_ok());
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
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("invalid hex size"));
        assert!(!transfer.is_done()); // Should not be done on error
    }

    #[tokio::test]
    async fn test_error_empty_size_line() {
        let input = b"\r\nData\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("no chunk length"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_size_line_too_long() {
        // CHUNK_SIZE_LEN is 10. Input > 10 bytes before \r\n
        let input = b"1234567890A\r\nData\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("could not read chunk length")); // Error occurs when buffer fills without finding CRLF
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
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err
            .to_string()
            .contains("could not read trailer header, line too long"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_invalid_trailer_format() {
        let input = b"0\r\nInvalid Header Line\r\n\r\n";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("invalid trailer header"));
        assert!(!transfer.is_done());
    }

    #[tokio::test]
    async fn test_error_data_after_final_trailer_crlf() {
        // This error happens if more data is provided *within the same `run` call* after the final \r\n
        let input = b"0\r\nTrailer: Val\r\n\r\nExtraData";
        let (result, transfer, _) = run_transfer_fragmented(&[input], true).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err
            .to_string()
            .contains("extra data after chunked transfer ended"));
        assert_eq!(transfer.state, ChunkTransferState::Done); // State becomes Done just before the error
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

        // 1. Send partial size
        transfer.run(b"A", &mut opt_writer_ref).await.unwrap();
        assert_eq!(
            transfer.state,
            ChunkTransferState::ReadSize { cached_len: 1 }
        );
        assert_eq!(&transfer.read_size_buf[0..1], b"A");

        // 2. Send rest of size and partial data
        transfer
            .run(b"\r\n0123", &mut opt_writer_ref)
            .await
            .unwrap();
        // State should now be ReadData, expecting A (10) bytes + 2 (\r\n) = 12 bytes total for this chunk
        // We forwarded 4 bytes (0123), so 8 remaining.
        match transfer.state {
            ChunkTransferState::ReadData {
                chunk_len,
                remaining_len,
            } => {
                assert_eq!(chunk_len, 10);
                assert_eq!(remaining_len, 10 + 2 - 4); // chunk_len + \r\n - forwarded
            }
            _ => panic!("Incorrect state: {:?}", transfer.state),
        }

        // 3. Send rest of data and partial next size
        transfer
            .run(b"456789\r\n5\r", &mut opt_writer_ref)
            .await
            .unwrap();
        // Should have finished previous chunk, read next size (5), waiting for \n
        assert_eq!(
            transfer.state,
            ChunkTransferState::ReadSize { cached_len: 2 }
        ); // "5\r" length is 2
        assert_eq!(&transfer.read_size_buf[0..2], b"5\r"); // Should have consumed 5\r fully

        // 4. Send rest of size and all data for second chunk + zero chunk + partial trailer
        transfer
            .run(b"\nABCDE\r\n0\r\nTrailer:", &mut opt_writer_ref)
            .await
            .unwrap();
        match transfer.state {
            ChunkTransferState::ReadTrailer { cached_len } => {
                assert_eq!(cached_len, 8); // "Trailer:" length is 8
                assert_eq!(&transfer.trailer_header_buf[0..cached_len], b"Trailer:");
            }
            _ => panic!("Incorrect state: {:?}", transfer.state),
        }

        // 5. Send rest of trailer and final CRLFs
        transfer
            .run(b" Value\r\n\r\n", &mut opt_writer_ref)
            .await
            .unwrap();
        assert!(transfer.is_done());
        assert_eq!(
            transfer.trailer_headers().get("trailer"),
            Some(&"Value".to_string())
        );

        // Check final forwarded data
        let expected_forward = b"A\r\n0123456789\r\n5\r\nABCDE\r\n0\r\nTrailer: Value\r\n\r\n"; // Remember, trailers aren't forwarded by run itself
        let written_data = writer.get_written_data().await;
        assert_eq!(written_data, expected_forward);
    }

    #[tokio::test]
    async fn test_chunk_extension_ignored() {
        // Chunk extensions are allowed but generally ignored by intermediaries unless specified.
        // This implementation should ignore them.
        let input = b"A;extension=value\r\n0123456789\r\n0\r\n\r\n";
        let expected_forward = input; // Forward includes the extension part of the size line
        let (result, mut transfer, written_data) = run_transfer_fragmented(&[input], true).await;

        assert!(result.is_ok());
        assert!(transfer.is_done());
        assert_eq!(written_data.unwrap(), expected_forward);
        assert!(transfer.trailer_headers().is_empty());
    }
}
