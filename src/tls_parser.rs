//! Bounded ClientHello inspection for TLS termination and transparent routing.

use std::collections::HashSet;
use std::io;

use crate::tls_reader::{TlsReader, TLS_BUFFER_MAX_LEN};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct ParsedClientHello {
    pub server_name: Option<String>,
    pub alpn_protocols: Vec<Vec<u8>>,
}

pub async fn parse_client_hello(
    reader: &mut TlsReader,
    stream: &mut TcpStream,
) -> io::Result<ParsedClientHello> {
    reader.ensure_bytes(stream, 1).await?;
    if !reader.starts_with_tls() {
        return Err(invalid("not a TLS record"));
    }

    let mut handshake = Vec::new();
    loop {
        reader.ensure_bytes(stream, 5).await?;
        let record = reader.read_slice(5)?;
        if record[0] != 0x16 || record[1] != 3 || record[2] > 4 {
            return Err(invalid("expected a TLS handshake record"));
        }
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;
        if length == 0 || length > 16384 {
            return Err(invalid("invalid TLS plaintext record length"));
        }
        reader.ensure_bytes(stream, length).await?;
        handshake.extend_from_slice(reader.read_slice(length)?);
        if handshake.len() < 4 {
            continue;
        }
        if handshake[0] != 1 {
            return Err(invalid("expected ClientHello"));
        }
        let length = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
        if length > TLS_BUFFER_MAX_LEN - 9 {
            return Err(invalid("TLS ClientHello exceeds buffer size"));
        }
        if handshake.len() < length + 4 {
            continue;
        }
        if handshake.len() != length + 4 {
            return Err(invalid("unexpected data after ClientHello handshake"));
        }
        return parse_body(&handshake[4..]);
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn take<'a>(data: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    let (value, rest) = data
        .split_at_checked(length)
        .ok_or_else(|| invalid("truncated ClientHello field"))?;
    *data = rest;
    Ok(value)
}

fn byte(data: &mut &[u8]) -> io::Result<u8> {
    Ok(take(data, 1)?[0])
}

fn short(data: &mut &[u8]) -> io::Result<usize> {
    let bytes = take(data, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

fn parse_body(mut data: &[u8]) -> io::Result<ParsedClientHello> {
    take(&mut data, 34)?; // legacy_version and random
    let session_length = byte(&mut data)? as usize;
    if session_length > 32 {
        return Err(invalid("invalid ClientHello session ID length"));
    }
    take(&mut data, session_length)?;
    let cipher_length = short(&mut data)?;
    if cipher_length == 0 || cipher_length % 2 != 0 {
        return Err(invalid("invalid ClientHello cipher suites length"));
    }
    take(&mut data, cipher_length)?;
    let compression_length = byte(&mut data)? as usize;
    if compression_length == 0 {
        return Err(invalid("empty ClientHello compression methods"));
    }
    take(&mut data, compression_length)?;

    let mut parsed = ParsedClientHello {
        server_name: None,
        alpn_protocols: Vec::new(),
    };
    if data.is_empty() {
        return Ok(parsed);
    }
    let extensions_length = short(&mut data)?;
    if extensions_length != data.len() {
        return Err(invalid("invalid ClientHello extensions length"));
    }
    let mut seen = HashSet::new();
    while !data.is_empty() {
        let kind = short(&mut data)?;
        let length = short(&mut data)?;
        let mut extension = take(&mut data, length)?;
        if !seen.insert(kind) {
            return Err(invalid("duplicate ClientHello extension"));
        }
        match kind {
            0 => {
                let list_length = short(&mut extension)?;
                if list_length != extension.len() || byte(&mut extension)? != 0 {
                    return Err(invalid("invalid SNI name list"));
                }
                let name_length = short(&mut extension)?;
                if name_length == 0 || name_length != extension.len() {
                    return Err(invalid("invalid SNI hostname length"));
                }
                let name =
                    std::str::from_utf8(extension).map_err(|_| invalid("invalid SNI UTF-8"))?;
                crate::hostname_util::validate_sni_hostname(name)?;
                parsed.server_name = Some(name.to_owned());
            }
            16 => {
                let list_length = short(&mut extension)?;
                if list_length == 0 || list_length != extension.len() {
                    return Err(invalid("invalid ALPN protocol list length"));
                }
                while !extension.is_empty() {
                    let length = byte(&mut extension)? as usize;
                    if length == 0 {
                        return Err(invalid("empty ALPN protocol"));
                    }
                    parsed
                        .alpn_protocols
                        .push(take(&mut extension, length)?.to_vec());
                }
            }
            _ => {}
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn vector(data: &[u8]) -> Vec<u8> {
        let mut bytes = (data.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(data);
        bytes
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend(vector(data));
        bytes
    }

    fn body(extensions: &[u8]) -> Vec<u8> {
        let mut bytes = vec![3, 3];
        bytes.extend([0; 32]);
        bytes.extend([0, 0, 2, 0x13, 1, 1, 0]);
        bytes.extend(vector(extensions));
        bytes
    }

    fn handshake(body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        bytes.extend_from_slice(body);
        bytes
    }

    fn records(handshake: &[u8], fragment_size: usize) -> Vec<u8> {
        let mut wire = Vec::new();
        for fragment in handshake.chunks(fragment_size) {
            wire.extend([0x16, 3, 3]);
            wire.extend(vector(fragment));
        }
        wire
    }

    async fn inspect(wire: &[u8]) -> io::Result<ParsedClientHello> {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = (
            std::net::Ipv4Addr::LOCALHOST,
            listener.local_addr().unwrap().port(),
        );
        let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client.unwrap();
        let (mut server, _) = server.unwrap();
        client.write_all(wire).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reader = TlsReader::new();
        let parsed = parse_client_hello(&mut reader, &mut server).await;
        let (mut replay, _, end) = reader.into_inner();
        assert!(end <= TLS_BUFFER_MAX_LEN);
        replay.truncate(end);
        server.read_to_end(&mut replay).await.unwrap();
        assert_eq!(replay, wire, "inspection must preserve every original byte");
        parsed
    }

    #[tokio::test]
    async fn record_fragments_reassemble_without_consuming_following_records() {
        let mut name = vec![0];
        name.extend(vector(b"example.com"));
        let mut extensions = extension(0, &vector(&name));
        extensions.extend(extension(16, &vector(&[2, b'h', b'2', 2, 0xff, 0xfe])));
        let hello = handshake(&body(&extensions));
        for size in [1, 2, 3, 4, 17, hello.len()] {
            let mut wire = records(&hello, size);
            wire.extend([0x14, 3, 3, 0, 1, 1]);
            let parsed = inspect(&wire).await.unwrap();
            assert_eq!(parsed.server_name.as_deref(), Some("example.com"));
            assert_eq!(parsed.alpn_protocols, [b"h2".to_vec(), vec![0xff, 0xfe]]);
        }
    }

    #[tokio::test]
    async fn real_rustls_client_hello_can_be_fragmented_at_any_header_byte() {
        let config = crate::rustls_util::create_client_config_with_cert(
            false,
            None,
            vec![b"h2".to_vec()],
            true,
            vec![],
        )
        .unwrap();
        let mut client = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from("example.com").unwrap(),
        )
        .unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let payload = &wire[5..];
        assert_eq!(
            u16::from_be_bytes([wire[3], wire[4]]) as usize,
            payload.len()
        );
        for split in [1, 2, 3, 4, 40, payload.len() - 1] {
            let mut fragmented = records(&payload[..split], 16384);
            fragmented.extend(records(&payload[split..], 16384));
            let parsed = inspect(&fragmented).await.unwrap();
            assert_eq!(parsed.server_name.as_deref(), Some("example.com"));
            assert_eq!(parsed.alpn_protocols, [b"h2".to_vec()]);
        }
    }

    #[tokio::test]
    async fn wire_and_handshake_lengths_are_bounded_and_checked() {
        let hello = handshake(&body(&[]));
        let mut short_hello = hello.clone();
        short_hello[3] -= 1;
        let mut long_hello = hello.clone();
        long_hello[3] += 1;
        for wire in [
            vec![],
            vec![0x16],
            vec![0x16, 3, 3, 0, 0],
            vec![0x16, 3, 3, 0x40, 1],
            records(&[1, 1, 0, 0], 4),
            records(&short_hello, 16384),
            records(&long_hello, 16384),
            records(&hello[..hello.len() - 1], 16384),
        ] {
            assert!(inspect(&wire).await.is_err(), "{wire:?}");
        }
        let large = handshake(&body(&extension(123, &vec![0; 44000])));
        assert!(inspect(&records(&large, 16384)).await.is_ok());
        let error = inspect(&records(&large, 8)).await.unwrap_err();
        assert!(error.to_string().contains("exceeds buffer size"));
    }

    #[test]
    fn nested_extension_lengths_cannot_consume_neighboring_fields() {
        for extension_data in [
            extension(0, &[0, 1, 0, 0, 1, b'a']),
            extension(0, &[0, 4, 0, 0, 2, b'a']),
            extension(0, &[0, 3, 0, 0, 0]),
            extension(16, &[0, 0]),
            extension(16, &[0, 1, 0]),
            extension(16, &[0, 2, 2, b'h']),
            extension(16, &[0, 1, 2, b'h', b'2']),
            vec![0, 123, 0, 2, 0],
            vec![0, 123, 0, 0, 0],
            [
                extension(16, &[0, 3, 2, b'h', b'2']),
                extension(16, &[0, 3, 2, b'h', b'2']),
            ]
            .concat(),
        ] {
            assert!(
                parse_body(&body(&extension_data)).is_err(),
                "{extension_data:?}"
            );
        }
        let valid = body(&extension(123, &[1, 2, 3]));
        for length in 0..valid.len() {
            if length != 41 {
                // TLS 1.2 may omit extensions entirely.
                assert!(parse_body(&valid[..length]).is_err(), "length {length}");
            }
        }
        assert!(parse_body(&valid).is_ok());
    }
}
