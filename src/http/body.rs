use super::header_map::HeaderMap;
use super::{chunk_transfer, http_parser, line_reader, string_util};
use crate::util::write_all;
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) async fn forward_message<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    http_data: http_parser::ParsedHttpData,
) -> std::io::Result<line_reader::LineReader>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let chunked = http_data.headers().chunked();
    let content_length = http_data.headers().content_length()?;

    if chunked && content_length.is_some() {
        return Err(std::io::Error::other(
            "Chunked transfer encoding and content length both provided",
        ));
    }

    if let Some(ref mut to_stream) = maybe_to_stream {
        let new_message = string_util::create_message(&http_data);
        write_all(to_stream, &new_message.into_bytes()).await?;
    }

    let reader = http_data.into_reader();
    if let Some(len) = content_length {
        forward_content_with_length(from_stream, maybe_to_stream, reader, len).await
    } else if chunked {
        forward_chunked_content(from_stream, maybe_to_stream, reader).await
    } else {
        Ok(reader)
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
