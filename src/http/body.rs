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

fn framing(headers: &impl HeaderMap, response: bool) -> std::io::Result<Framing> {
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
        let chunked = codings
            .iter()
            .filter(|coding| coding.eq_ignore_ascii_case("chunked"))
            .count();
        if chunked == 1 && codings.last().unwrap().eq_ignore_ascii_case("chunked") {
            return Ok(Framing::Chunked);
        }
        if chunked != 0 || !response {
            return Err(std::io::Error::other(
                "Chunked must be the final request transfer coding",
            ));
        }
        return Ok(Framing::UntilEof);
    }
    Ok(match length {
        Some(0) => Framing::Empty,
        Some(length) => Framing::Length(length),
        None if response => Framing::UntilEof,
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

pub(super) async fn forward_message<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    http_data: http_parser::ParsedHttpData,
) -> std::io::Result<line_reader::LineReader>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let framing = request_framing(http_data.headers())?;

    if let Some(ref mut to_stream) = maybe_to_stream {
        write_head(to_stream, &http_data).await?;
    }

    forward_body(
        from_stream,
        maybe_to_stream,
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
