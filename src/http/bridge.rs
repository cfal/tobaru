use super::line_reader::LineReader;
use super::message::{
    self, invalid, io_error, BodyFrame, ReceiveBody, Respond, SendBody, CHUNK_SIZE,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Framing {
    Empty,
    Length(u64),
    Chunked,
    Eof,
}

pub(super) fn framing(headers: &HeaderMap, response: bool) -> io::Result<Framing> {
    let length = message::content_length(headers)?;
    let codings: Vec<_> = headers.get_all("transfer-encoding").iter().collect();
    if !codings.is_empty() {
        if length.is_some()
            || codings.len() != 1
            || !codings[0].as_bytes().eq_ignore_ascii_case(b"chunked")
        {
            return Err(invalid(
                "Unsupported or ambiguous cross-protocol transfer coding",
            ));
        }
        return Ok(Framing::Chunked);
    }
    Ok(match length {
        Some(0) => Framing::Empty,
        Some(n) => Framing::Length(n),
        None if response => Framing::Eof,
        None => Framing::Empty,
    })
}

pub(super) async fn read_fields<R: AsyncRead + Unpin>(
    io: &mut R,
    reader: &mut LineReader,
    limit: usize,
) -> io::Result<HeaderMap> {
    let mut fields = HeaderMap::new();
    let mut bytes = 0usize;
    loop {
        let line = reader.read_line_bytes(io).await?;
        if line.is_empty() {
            break;
        }
        bytes = bytes
            .checked_add(line.len() + 32)
            .ok_or_else(|| invalid("Header size overflow"))?;
        if bytes > limit || fields.len() >= message::MAX_FIELDS {
            return Err(invalid("HTTP field section too large"));
        }
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or_else(|| invalid("Invalid HTTP header"))?;
        let name = HeaderName::from_bytes(&line[..colon]).map_err(io_error)?;
        let value = HeaderValue::from_bytes(line[colon + 1..].trim_ascii()).map_err(io_error)?;
        fields.append(name, value);
    }
    Ok(fields)
}

pub(super) async fn read_response<R: AsyncRead + Unpin>(
    io: &mut R,
    reader: &mut LineReader,
    limit: usize,
) -> io::Result<Response<()>> {
    let line = reader.read_line_bytes(io).await?;
    let mut parts = line.splitn(3, |byte| *byte == b' ');
    if !matches!(parts.next(), Some(b"HTTP/1.1" | b"HTTP/1.0")) {
        return Err(invalid("Invalid backend response version"));
    }
    let code = parts
        .next()
        .ok_or_else(|| invalid("Missing backend status"))?;
    let status = StatusCode::from_bytes(code).map_err(io_error)?;
    if parts.next().is_some_and(|reason| {
        reason
            .iter()
            .any(|byte| *byte < 32 && *byte != b'\t' || *byte == 127)
    }) {
        return Err(invalid("Invalid backend reason phrase"));
    }
    if status.as_u16() >= 600 || status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(invalid("Unsupported backend response status"));
    }
    let headers = read_fields(io, reader, limit).await?;
    let mut response = Response::builder()
        .status(status)
        .body(())
        .map_err(io_error)?;
    *response.headers_mut() = headers;
    Ok(response)
}

pub(super) struct H1Body<R> {
    pub io: R,
    pub reader: LineReader,
    framing: Framing,
    chunk_remaining: u64,
    chunk_crlf: bool,
    pub done: bool,
    limit: usize,
}

impl<R> H1Body<R> {
    pub fn new(io: R, reader: LineReader, framing: Framing, limit: usize) -> Self {
        Self {
            io,
            reader,
            framing,
            chunk_remaining: 0,
            chunk_crlf: false,
            done: framing == Framing::Empty,
            limit,
        }
    }
}

#[async_trait]
impl<R: AsyncRead + Unpin + Send> ReceiveBody for H1Body<R> {
    async fn next(&mut self) -> io::Result<Option<BodyFrame>> {
        if self.done {
            return Ok(None);
        }
        if self.framing == Framing::Chunked && self.chunk_remaining == 0 {
            if self.chunk_crlf && !self.reader.read_line_bytes(&mut self.io).await?.is_empty() {
                return Err(invalid("Missing chunk terminator"));
            }
            let line = self.reader.read_line_bytes(&mut self.io).await?;
            let size = line.split(|byte| *byte == b';').next().unwrap();
            if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
                return Err(invalid("Invalid chunk size"));
            }
            self.chunk_remaining =
                u64::from_str_radix(std::str::from_utf8(size).map_err(io_error)?, 16)
                    .map_err(io_error)?;
            self.chunk_crlf = true;
            if self.chunk_remaining == 0 {
                let trailers = read_fields(&mut self.io, &mut self.reader, self.limit).await?;
                message::validate_trailers(&trailers, self.limit)?;
                self.done = true;
                return Ok(Some(BodyFrame::Trailers(trailers)));
            }
        }
        if self.reader.unparsed_data().is_empty() && self.reader.read_more(&mut self.io).await? == 0
        {
            if self.framing != Framing::Eof {
                return Err(invalid("Truncated HTTP body"));
            }
            self.done = true;
            return Ok(None);
        }
        let remaining = match self.framing {
            Framing::Length(n) => n,
            Framing::Chunked => self.chunk_remaining,
            _ => u64::MAX,
        };
        let n = self
            .reader
            .unparsed_data()
            .len()
            .min(CHUNK_SIZE)
            .min(remaining.min(usize::MAX as u64) as usize);
        let data = Bytes::copy_from_slice(&self.reader.unparsed_data()[..n]);
        self.reader.consume(n);
        match &mut self.framing {
            Framing::Length(left) => {
                *left -= n as u64;
                self.done = *left == 0;
            }
            Framing::Chunked => self.chunk_remaining -= n as u64,
            _ => {}
        }
        Ok(Some(BodyFrame::Data(data)))
    }
}

pub(super) struct H1Send<W> {
    pub io: W,
    chunked: bool,
    finished: bool,
}
impl<W> H1Send<W> {
    pub fn new(io: W, chunked: bool) -> Self {
        Self {
            io,
            chunked,
            finished: false,
        }
    }
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> SendBody for H1Send<W> {
    async fn data(&mut self, data: Bytes) -> io::Result<()> {
        if self.finished {
            return Err(invalid("DATA after body completion"));
        }
        if data.is_empty() {
            return Ok(());
        }
        if self.chunked {
            self.io
                .write_all(format!("{:x}\r\n", data.len()).as_bytes())
                .await?;
        }
        self.io.write_all(&data).await?;
        if self.chunked {
            self.io.write_all(b"\r\n").await?;
        }
        self.io.flush().await
    }
    async fn trailers(&mut self, trailers: HeaderMap) -> io::Result<()> {
        if !self.chunked && !trailers.is_empty() {
            return Err(invalid("Trailers need chunked H1 output"));
        }
        if self.finished {
            return Err(invalid("Trailers after completion"));
        }
        if self.chunked {
            self.io.write_all(b"0\r\n").await?;
            write_fields(&mut self.io, &trailers).await?;
            self.io.write_all(b"\r\n").await?;
        }
        self.finished = true;
        self.io.flush().await
    }
    async fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.trailers(HeaderMap::new()).await
    }
}

async fn write_fields<W: AsyncWrite + Unpin>(io: &mut W, headers: &HeaderMap) -> io::Result<()> {
    for (name, value) in headers {
        io.write_all(name.as_str().as_bytes()).await?;
        io.write_all(b": ").await?;
        io.write_all(value.as_bytes()).await?;
        io.write_all(b"\r\n").await?;
    }
    Ok(())
}

pub(super) async fn write_request<W: AsyncWrite + Unpin>(
    io: &mut W,
    mut request: Request<()>,
    body: bool,
) -> io::Result<()> {
    request.headers_mut().remove("content-length");
    request.headers_mut().remove("te");
    message::set(request.headers_mut(), "connection", "close")?;
    if body {
        message::set(request.headers_mut(), "transfer-encoding", "chunked")?;
    }
    let cookies: Vec<_> = request.headers().get_all("cookie").iter().collect();
    if cookies.len() > 1 {
        let mut value = Vec::new();
        for cookie in cookies {
            if !value.is_empty() {
                value.extend_from_slice(b"; ");
            }
            value.extend_from_slice(cookie.as_bytes());
        }
        request
            .headers_mut()
            .insert("cookie", HeaderValue::from_bytes(&value).map_err(io_error)?);
    }
    io.write_all(
        format!(
            "{} {} HTTP/1.1\r\n",
            request.method(),
            request.uri().path_and_query().unwrap()
        )
        .as_bytes(),
    )
    .await?;
    write_fields(io, request.headers()).await?;
    io.write_all(b"\r\n").await?;
    io.flush().await
}

pub(super) struct H1Response<W> {
    pub body: H1Send<W>,
    method: Method,
    close: bool,
    final_sent: bool,
}
impl<W> H1Response<W> {
    pub fn reusable(&self) -> bool {
        !self.close
    }
    pub fn final_sent(&self) -> bool {
        self.final_sent
    }
    pub fn new(io: W, method: Method, close: bool) -> Self {
        Self {
            body: H1Send::new(io, false),
            method,
            close,
            final_sent: false,
        }
    }
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> Respond for H1Response<W> {
    fn early_final(&mut self) {
        self.close = true;
    }
    async fn head(&mut self, mut response: Response<()>, end: bool) -> io::Result<()> {
        if self.final_sent {
            return Err(invalid("Response after final head"));
        }
        let status = response.status();
        let empty = end || message::bodyless(&self.method, status);
        if !status.is_informational() {
            self.final_sent = true;
            self.body.chunked = !empty;
            self.body.finished = empty;
            if self.body.chunked {
                response.headers_mut().remove("content-length");
                message::set(response.headers_mut(), "transfer-encoding", "chunked")?;
            } else if !message::bodyless(&self.method, status) {
                message::set(response.headers_mut(), "content-length", "0")?;
            }
            message::set(
                response.headers_mut(),
                "connection",
                if self.close { "close" } else { "keep-alive" },
            )?;
        }
        self.body
            .io
            .write_all(format!("HTTP/1.1 {}\r\n", status).as_bytes())
            .await?;
        write_fields(&mut self.body.io, response.headers()).await?;
        self.body.io.write_all(b"\r\n").await?;
        self.body.io.flush().await
    }
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> SendBody for H1Response<W> {
    async fn data(&mut self, data: Bytes) -> io::Result<()> {
        self.body.data(data).await
    }
    async fn trailers(&mut self, trailers: HeaderMap) -> io::Result<()> {
        self.body.trailers(trailers).await
    }
    async fn finish(&mut self) -> io::Result<()> {
        self.body.finish().await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_io::ScriptedIo;
    use super::*;
    #[tokio::test]
    async fn every_chunk_split_preserves_bytes_trailers_and_read_ahead() {
        let wire = b"3;extension=x\r\na\xffb\r\n0\r\nx-end: one\r\nx-end: two\r\n\r\nNEXT";
        for split in 0..=wire.len() {
            let mut body = H1Body::new(
                ScriptedIo::split(wire, split),
                LineReader::new(),
                Framing::Chunked,
                65536,
            );
            let mut data = Vec::new();
            loop {
                match body.next().await.unwrap() {
                    Some(BodyFrame::Data(chunk)) => data.extend_from_slice(&chunk),
                    Some(BodyFrame::Trailers(fields)) => {
                        assert_eq!(fields.get_all("x-end").iter().count(), 2)
                    }
                    None => break,
                }
            }
            assert_eq!(data, b"a\xffb");
            let mut remaining = body.reader.unparsed_data().to_vec();
            tokio::io::AsyncReadExt::read_to_end(&mut body.io, &mut remaining)
                .await
                .unwrap();
            assert_eq!(remaining, b"NEXT");
        }
    }
    #[tokio::test]
    async fn opaque_repeated_response_fields_survive() {
        let wire =
            b"HTTP/1.1 200 \xff\r\nSet-Cookie: a\r\nSet-Cookie: b\r\nx-value: \xff\r\n\r\nbody";
        for split in 0..=wire.len() {
            let response = read_response(
                &mut ScriptedIo::split(wire, split),
                &mut LineReader::new(),
                65536,
            )
            .await
            .unwrap();
            assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
            assert_eq!(response.headers()["x-value"].as_bytes(), b"\xff");
        }
    }
    #[test]
    fn unsupported_codings_are_not_silently_removed() {
        let mut fields = HeaderMap::new();
        for coding in ["gzip", "gzip, chunked", "chunked, chunked"] {
            message::set(&mut fields, "transfer-encoding", coding).unwrap();
            assert!(framing(&fields, true).is_err());
        }
        message::set(&mut fields, "transfer-encoding", "chunked").unwrap();
        assert_eq!(framing(&fields, true).unwrap(), Framing::Chunked);
        message::set(&mut fields, "content-length", "0").unwrap();
        assert!(framing(&fields, true).is_err());
    }
}
