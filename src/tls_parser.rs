/// TLS ClientHello parser for transparent SNI routing.
///
/// This module parses the TLS ClientHello message to extract SNI and ALPN
/// without terminating the TLS connection.
///
/// References:
/// - https://datatracker.ietf.org/doc/html/rfc8446 (TLS 1.3)
/// - https://datatracker.ietf.org/doc/html/rfc5246 (TLS 1.2)
/// - https://datatracker.ietf.org/doc/html/rfc6066 (SNI Extension)
use crate::tls_reader::TlsReader;
use tokio::net::TcpStream;

const TLS_HEADER_LEN: usize = 5;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

// Extension types
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;

/// Parsed ClientHello information
#[derive(Debug)]
pub struct ParsedClientHello {
    /// Requested server name (SNI), if present
    pub server_name: Option<String>,
    /// Requested ALPN protocols, if present
    pub alpn_protocols: Vec<String>,
}

/// Parse a TLS ClientHello message from a stream using the provided TlsReader
///
/// This function reads and parses the ClientHello to extract SNI and ALPN.
/// The TlsReader is passed in so that on parse error, the caller can still
/// access the buffered data via reader.into_inner() for non-TLS fallback.
pub async fn parse_client_hello(
    reader: &mut TlsReader,
    stream: &mut TcpStream,
) -> std::io::Result<ParsedClientHello> {
    // Read TLS record header (5 bytes)
    reader.ensure_bytes(stream, TLS_HEADER_LEN).await?;

    let content_type = reader.read_u8()?;
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected handshake (0x16), got 0x{:02x}", content_type),
        ));
    }

    let legacy_version_major = reader.read_u8()?;
    let legacy_version_minor = reader.read_u8()?;

    // Accept TLS 1.0 (0x0301) through TLS 1.3 (0x0304 in record, but shows as 0x0303)
    // Most TLS 1.3 clients use 0x0303 (TLS 1.2) in the record for compatibility
    if legacy_version_major != 3 || legacy_version_minor > 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unexpected TLS record version {}.{}",
                legacy_version_major, legacy_version_minor
            ),
        ));
    }

    let payload_len = reader.read_u16_be()? as usize;

    // Read the payload
    reader.ensure_bytes(stream, payload_len).await?;

    // Parse handshake message
    let handshake_type = reader.read_u8()?;
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected ClientHello (0x01), got 0x{:02x}", handshake_type),
        ));
    }

    let _handshake_len = reader.read_u24_be()?;

    // Parse ClientHello
    let _client_version_major = reader.read_u8()?;
    let _client_version_minor = reader.read_u8()?;

    // Skip client random (32 bytes)
    reader.skip(32)?;

    // Skip session ID
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    // Skip cipher suites
    let cipher_suites_len = reader.read_u16_be()? as usize;
    reader.skip(cipher_suites_len)?;

    // Skip compression methods
    let compression_methods_len = reader.read_u8()? as usize;
    reader.skip(compression_methods_len)?;

    // Parse extensions
    let mut server_name: Option<String> = None;
    let mut alpn_protocols: Vec<String> = Vec::new();

    if !reader.is_consumed() {
        let extensions_len = reader.read_u16_be()? as usize;
        let extensions_end = reader.position() + extensions_len;

        while reader.position() < extensions_end {
            let ext_type = reader.read_u16_be()?;
            let ext_len = reader.read_u16_be()? as usize;
            let ext_data_start = reader.position();

            match ext_type {
                EXT_SERVER_NAME => {
                    // Parse SNI extension
                    if server_name.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "duplicate SNI extension",
                        ));
                    }
                    let _list_len = reader.read_u16_be()?;
                    let name_type = reader.read_u8()?;
                    if name_type != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("expected hostname type (0), got {}", name_type),
                        ));
                    }
                    let name_len = reader.read_u16_be()? as usize;
                    let name_str = reader.read_str(name_len)?;
                    server_name = Some(name_str.to_string());
                }
                EXT_ALPN => {
                    // Parse ALPN extension
                    let alpn_list_len = reader.read_u16_be()? as usize;
                    let alpn_list_end = reader.position() + alpn_list_len;

                    while reader.position() < alpn_list_end {
                        let proto_len = reader.read_u8()? as usize;
                        let proto_str = reader.read_str(proto_len)?;
                        alpn_protocols.push(proto_str.to_string());
                    }
                }
                _ => {
                    // Skip unknown extensions
                    reader.skip(ext_len)?;
                }
            }

            // Ensure we read exactly ext_len bytes
            let consumed = reader.position() - ext_data_start;
            if consumed < ext_len {
                reader.skip(ext_len - consumed)?;
            } else if consumed > ext_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "extension parsing overrun",
                ));
            }
        }
    }

    Ok(ParsedClientHello {
        server_name,
        alpn_protocols,
    })
}
