use super::header_map::HeaderMap;
use super::{chunk_transfer, http_parser, line_reader, string_util};
use crate::util::write_all;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Framing {
    Empty,
    Length(usize),
    Chunked,
    UntilEof,
}

fn framing(headers: &impl HeaderMap, is_response: bool) -> std::io::Result<Framing> {
    let length = headers.content_length()?;
    let codings: Vec<_> = headers
        .header_values("transfer-encoding")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect();
    if !codings.is_empty() {
        if length.is_some() || codings.iter().any(|coding| coding.is_empty()) {
            return Err(std::io::Error::other("Ambiguous HTTP body framing"));
        }
        let chunked_count = codings
            .iter()
            .filter(|coding| coding.eq_ignore_ascii_case("chunked"))
            .count();
        if chunked_count == 1 && codings.last().unwrap().eq_ignore_ascii_case("chunked") {
            return Ok(Framing::Chunked);
        }
        if chunked_count != 0 || !is_response {
            return Err(std::io::Error::other(
                "Chunked must be the final request transfer coding",
            ));
        }
        return Ok(Framing::UntilEof);
    }
    Ok(match length {
        Some(0) => Framing::Empty,
        Some(length) => Framing::Length(length),
        None if is_response => Framing::UntilEof,
        None => Framing::Empty,
    })
}

pub(super) fn request_framing(headers: &impl HeaderMap) -> std::io::Result<Framing> {
    framing(headers, false)
}

pub(super) fn response_framing(
    headers: &impl HeaderMap,
    method: &str,
    status: u16,
) -> std::io::Result<Framing> {
    if method == "HEAD" || status < 200 || status == 204 || status == 304 {
        return Ok(Framing::Empty);
    }
    framing(headers, true)
}

pub(super) async fn write_head<W: AsyncWrite + Unpin>(
    stream: &mut W,
    data: &http_parser::ParsedHttpData,
) -> std::io::Result<()> {
    write_all(stream, string_util::create_message(data).as_bytes()).await
}

pub(super) async fn drain_request<R: AsyncRead + Unpin>(
    stream: &mut R,
    http_data: http_parser::ParsedHttpData,
) -> std::io::Result<line_reader::LineReader> {
    let framing = request_framing(http_data.headers())?;
    forward_body(
        stream,
        None::<&mut tokio::io::Sink>,
        http_data.into_reader(),
        framing,
    )
    .await
}

pub(super) async fn forward_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    from: &mut R,
    mut to: Option<&mut W>,
    mut reader: line_reader::LineReader,
    framing: Framing,
) -> std::io::Result<line_reader::LineReader> {
    match framing {
        Framing::Empty => Ok(reader),
        Framing::Length(length) => forward_content_with_length(from, to, reader, length).await,
        Framing::Chunked => forward_chunked_content(from, to, reader).await,
        Framing::UntilEof => loop {
            let bytes = reader.unparsed_data();
            if let Some(to) = &mut to {
                write_all(to, bytes).await?;
            }
            reader.consume(bytes.len());
            if reader.read_more(from).await? == 0 {
                return Ok(reader);
            }
        },
    }
}

async fn forward_content_with_length<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    mut reader: line_reader::LineReader,
    content_length: usize,
) -> std::io::Result<line_reader::LineReader>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = content_length;
    while remaining > 0 {
        if reader.unparsed_data().is_empty() && reader.read_more(from_stream).await? == 0 {
            return Err(std::io::Error::other(format!(
                "Got EOF while reading content with length, {} bytes were remaining",
                remaining
            )));
        }
        let read_len = remaining.min(reader.unparsed_data().len());
        if let Some(ref mut to_stream) = maybe_to_stream {
            write_all(to_stream, &reader.unparsed_data()[..read_len]).await?;
        }
        reader.consume(read_len);
        remaining -= read_len;
    }
    Ok(reader)
}

async fn forward_chunked_content<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    mut reader: line_reader::LineReader,
) -> std::io::Result<line_reader::LineReader>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunk_transfer = chunk_transfer::ChunkTransfer::new();
    while !chunk_transfer.is_done() {
        if reader.unparsed_data().is_empty() && reader.read_more(from_stream).await? == 0 {
            return Err(std::io::Error::other("Got EOF during chunk transfer"));
        }
        let consumed = chunk_transfer
            .run_prefix(reader.unparsed_data(), &mut maybe_to_stream)
            .await?;
        reader.consume(consumed);
    }

    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::header_map::Headers;
    use crate::http::test_io::{ReadStep, ScriptedIo};
    use std::io::ErrorKind;
    use tokio::io::AsyncReadExt;

    fn headers(fields: &[(&str, &str)]) -> Headers {
        let mut headers = Headers::default();
        for (name, value) in fields {
            headers.append((*name).into(), (*value).into());
        }
        headers
    }

    #[test]
    fn request_framing_accepts_only_unambiguous_boundaries() {
        for (fields, expected) in [
            (vec![], Some(Framing::Empty)),
            (vec![("content-length", "0")], Some(Framing::Empty)),
            (
                vec![("content-length", "3, 3"), ("Content-Length", "3")],
                Some(Framing::Length(3)),
            ),
            (
                vec![("transfer-encoding", "GZIP, Chunked")],
                Some(Framing::Chunked),
            ),
            (vec![("content-length", "3"), ("content-length", "4")], None),
            (vec![("content-length", "+3")], None),
            (vec![("content-length", "-1")], None),
            (vec![("content-length", "")], None),
            (
                vec![("content-length", "999999999999999999999999999999999999")],
                None,
            ),
            (
                vec![("content-length", "0"), ("transfer-encoding", "Chunked")],
                None,
            ),
            (vec![("transfer-encoding", "chunked, gzip")], None),
            (vec![("transfer-encoding", "chunked, chunked")], None),
            (vec![("transfer-encoding", "gzip")], None),
            (vec![("transfer-encoding", "chunked,")], None),
        ] {
            assert_eq!(
                request_framing(&headers(&fields)).ok(),
                expected,
                "{fields:?}"
            );
        }
    }

    #[test]
    fn response_framing_respects_method_status_and_eof() {
        for fields in [
            vec![],
            vec![("content-length", "99")],
            vec![("transfer-encoding", "chunked")],
        ] {
            let headers = headers(&fields);
            assert_eq!(
                response_framing(&headers, "HEAD", 200).unwrap(),
                Framing::Empty
            );
            for status in [100, 101, 103, 199, 204, 304] {
                assert_eq!(
                    response_framing(&headers, "GET", status).unwrap(),
                    Framing::Empty
                );
            }
        }
        assert_eq!(
            response_framing(&headers(&[]), "GET", 200).unwrap(),
            Framing::UntilEof
        );
        assert_eq!(
            response_framing(&headers(&[("transfer-encoding", "gzip")]), "GET", 200).unwrap(),
            Framing::UntilEof
        );
        assert_eq!(
            response_framing(&headers(&[("content-length", "3")]), "GET", 200).unwrap(),
            Framing::Length(3)
        );
        assert!(response_framing(
            &headers(&[("transfer-encoding", "chunked"), ("content-length", "3")]),
            "GET",
            200
        )
        .is_err());
    }

    #[tokio::test]
    async fn every_body_split_and_short_write_preserves_payload_and_suffix() {
        for (body, framing) in [
            (b"".as_slice(), Framing::Empty),
            (b"hello", Framing::Length(5)),
            (
                b"5;foo=bar\r\nhello\r\n0;end=yes\r\nX-End: one\r\nX-End: two\r\n\r\n",
                Framing::Chunked,
            ),
        ] {
            let wire = [body, b"NEXT"].concat();
            for split in 0..=wire.len() {
                let mut from = ScriptedIo::split(&wire, split);
                let mut to = ScriptedIo::new([]).short_writes(2);
                let reader = forward_body(
                    &mut from,
                    Some(&mut to),
                    line_reader::LineReader::new(),
                    framing,
                )
                .await
                .unwrap();
                assert_eq!(to.written, body, "split {split}, framing {framing:?}");
                let mut suffix = reader.unparsed_data().to_vec();
                from.read_to_end(&mut suffix).await.unwrap();
                assert_eq!(suffix, b"NEXT");
            }
        }
        let mut from = ScriptedIo::split(b"until-eof", 3);
        let mut to = ScriptedIo::new([]).short_writes(1);
        let reader = forward_body(
            &mut from,
            Some(&mut to),
            line_reader::LineReader::new(),
            Framing::UntilEof,
        )
        .await
        .unwrap();
        assert_eq!(to.written, b"until-eof");
        assert!(reader.unparsed_data().is_empty());
    }

    #[tokio::test]
    async fn truncation_and_transport_failures_never_complete_a_body() {
        for (complete, framing) in [
            (b"hello".as_slice(), Framing::Length(5)),
            (b"1\r\nx\r\n0\r\nX-End: yes\r\n\r\n", Framing::Chunked),
        ] {
            for end in 0..complete.len() {
                let mut from =
                    ScriptedIo::new([ReadStep::Data(complete[..end].to_vec()), ReadStep::Eof]);
                let result = forward_body(
                    &mut from,
                    None::<&mut tokio::io::Sink>,
                    line_reader::LineReader::new(),
                    framing,
                )
                .await;
                assert!(
                    result.err().unwrap().to_string().starts_with("Got EOF"),
                    "end {end}"
                );
            }
            let mut from = ScriptedIo::new([ReadStep::Error(ErrorKind::ConnectionReset)]);
            let error = forward_body(
                &mut from,
                None::<&mut tokio::io::Sink>,
                line_reader::LineReader::new(),
                framing,
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error.kind(), ErrorKind::ConnectionReset);
            let mut from = ScriptedIo::new([ReadStep::Data(complete.to_vec())]);
            let mut to = ScriptedIo::new([]).short_writes(1).fail_writes_after(2);
            let error = forward_body(
                &mut from,
                Some(&mut to),
                line_reader::LineReader::new(),
                framing,
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error.kind(), ErrorKind::BrokenPipe);
            assert_eq!(to.written, complete[..2]);
        }
    }
}
