use super::header_map::HeaderMap;
use super::{chunk_transfer, http_parser, line_reader, string_util};
use crate::util::write_all;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

pub(super) async fn forward_message<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    http_data: http_parser::ParsedHttpData,
) -> std::io::Result<()>
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
        if len > 0 {
            forward_content_with_length(from_stream, maybe_to_stream, reader, len).await?;
        }
    } else if chunked {
        forward_chunked_content(from_stream, maybe_to_stream, reader).await?;
    } else if !reader.unparsed_data().is_empty() {
        return Err(std::io::Error::other(format!(
            "Unexpected request data with len {}",
            reader.unparsed_data().len()
        )));
    }

    Ok(())
}

async fn forward_content_with_length<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    reader: line_reader::LineReader,
    content_length: usize,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let unparsed_data = reader.unparsed_data();
    if unparsed_data.len() > content_length {
        return Err(std::io::Error::other(format!(
            "Unexpected content length ({} > {})",
            unparsed_data.len(),
            content_length
        )));
    }

    if !unparsed_data.is_empty() {
        if let Some(ref mut to_stream) = maybe_to_stream {
            write_all(to_stream, unparsed_data).await?;
        }
    }

    let mut remaining = content_length - unparsed_data.len();
    let mut buf = reader.into_buf();
    while remaining > 0 {
        let max_len = std::cmp::min(remaining, buf.len());
        let read_len = from_stream.read(&mut buf[0..max_len]).await?;
        if read_len == 0 {
            return Err(std::io::Error::other(format!(
                "Got EOF while reading content with length, {} bytes were remaining",
                remaining
            )));
        }
        if let Some(ref mut to_stream) = maybe_to_stream {
            write_all(to_stream, &buf[0..read_len]).await?;
        }
        remaining -= read_len;
    }
    Ok(())
}

async fn forward_chunked_content<R, W>(
    from_stream: &mut R,
    mut maybe_to_stream: Option<&mut W>,
    reader: line_reader::LineReader,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunk_transfer = chunk_transfer::ChunkTransfer::new();
    chunk_transfer
        .run(reader.unparsed_data(), &mut maybe_to_stream)
        .await?;

    let mut buf = reader.into_buf();
    while !chunk_transfer.is_done() {
        let read_len = from_stream.read(&mut buf).await?;
        if read_len == 0 {
            return Err(std::io::Error::other("Got EOF during chunk transfer"));
        }
        chunk_transfer
            .run(&buf[0..read_len], &mut maybe_to_stream)
            .await?;
    }

    Ok(())
}
