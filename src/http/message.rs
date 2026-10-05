use std::io;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};

use crate::config::HttpHeaderPatch;

pub(super) const CHUNK_SIZE: usize = 16 * 1024;
pub(super) const MAX_FIELDS: usize = 128;
pub(super) const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "http2-settings",
];

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

pub(super) enum BodyFrame {
    Data(Bytes),
    Trailers(HeaderMap),
}

#[async_trait]
pub(super) trait ReceiveBody: Send {
    async fn next(&mut self) -> io::Result<Option<BodyFrame>>;
    fn release(&mut self, _bytes: usize) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait]
pub(super) trait SendBody: Send {
    async fn data(&mut self, data: Bytes) -> io::Result<()>;
    async fn trailers(&mut self, trailers: HeaderMap) -> io::Result<()>;
    async fn finish(&mut self) -> io::Result<()>;
}

#[async_trait]
pub(super) trait Respond: SendBody {
    fn early_final(&mut self) {}
    async fn head(&mut self, response: Response<()>, end: bool) -> io::Result<()>;
}

pub(super) async fn progress<T>(
    seconds: u64,
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP stream made no progress"))?
}

pub(super) struct Activity {
    last: parking_lot::Mutex<tokio::time::Instant>,
    timeout: Duration,
}

impl Activity {
    pub fn new(seconds: u64) -> Self {
        Self {
            last: parking_lot::Mutex::new(tokio::time::Instant::now()),
            timeout: Duration::from_secs(seconds),
        }
    }

    pub fn touch(&self) {
        *self.last.lock() = tokio::time::Instant::now();
    }

    pub async fn wait<T>(
        &self,
        operation: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        tokio::pin!(operation);
        loop {
            let deadline = *self.last.lock() + self.timeout;
            tokio::select! {
                result = &mut operation => { self.touch(); return result; }
                _ = tokio::time::sleep_until(deadline) => {
                    if tokio::time::Instant::now() >= *self.last.lock() + self.timeout {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP exchange made no progress"));
                    }
                }
            }
        }
    }
}

pub(super) async fn copy_body(
    from: &mut (impl ReceiveBody + ?Sized),
    to: &mut (impl SendBody + ?Sized),
    expected: Option<u64>,
    activity: &Activity,
    header_limit: usize,
) -> io::Result<()> {
    let mut received = 0u64;
    loop {
        match activity.wait(from.next()).await? {
            Some(BodyFrame::Data(data)) => {
                let len = data.len();
                received = received
                    .checked_add(len as u64)
                    .ok_or_else(|| invalid("Body length overflow"))?;
                if expected.is_some_and(|length| received > length) {
                    return Err(invalid("Body exceeds Content-Length"));
                }
                activity.wait(to.data(data)).await?;
                from.release(len)?;
            }
            Some(BodyFrame::Trailers(trailers)) => {
                validate_trailers(&trailers, header_limit)?;
                check_length(expected, received)?;
                return activity.wait(to.trailers(trailers)).await;
            }
            None => {
                check_length(expected, received)?;
                return activity.wait(to.finish()).await;
            }
        }
    }
}

fn check_length(expected: Option<u64>, actual: u64) -> io::Result<()> {
    if expected.is_some_and(|length| actual != length) {
        return Err(invalid("Body does not match Content-Length"));
    }
    Ok(())
}

pub(super) fn content_length(headers: &HeaderMap) -> io::Result<Option<u64>> {
    let mut length = None;
    for value in headers.get_all("content-length") {
        for value in value.as_bytes().split(|byte| *byte == b',') {
            let value = value.trim_ascii();
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(invalid("Invalid Content-Length"));
            }
            let parsed = std::str::from_utf8(value)
                .map_err(io_error)?
                .parse::<u64>()
                .map_err(io_error)?;
            if length.is_some_and(|previous| previous != parsed) {
                return Err(invalid("Conflicting Content-Length"));
            }
            length = Some(parsed);
        }
    }
    Ok(length)
}

pub(super) fn validate_fields(headers: &HeaderMap, limit: usize) -> io::Result<()> {
    let size = headers.iter().try_fold(0usize, |size, (name, value)| {
        size.checked_add(name.as_str().len() + value.as_bytes().len() + 32)
            .ok_or_else(|| invalid("Header size overflow"))
    })?;
    if headers.len() > MAX_FIELDS || size > limit {
        return Err(invalid("HTTP field section exceeds configured limit"));
    }
    Ok(())
}

pub(super) fn validate_multiplexed(
    headers: &HeaderMap,
    request: bool,
    limit: usize,
) -> io::Result<()> {
    validate_fields(headers, limit)?;
    for name in HOP_HEADERS {
        if headers.contains_key(*name) {
            return Err(invalid("Connection-specific HTTP/2 field"));
        }
    }
    for value in headers.get_all("te") {
        if !request || !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
            return Err(invalid("Only request TE: trailers is permitted"));
        }
    }
    content_length(headers)?;
    Ok(())
}

pub(super) fn validate_trailers(headers: &HeaderMap, limit: usize) -> io::Result<()> {
    validate_multiplexed(headers, false, limit)?;
    for name in [
        "content-length",
        "host",
        "trailer",
        "authorization",
        "proxy-authorization",
        "content-encoding",
        "content-type",
        "content-range",
        "expect",
    ] {
        if headers.contains_key(name) {
            return Err(invalid("Forbidden trailer field"));
        }
    }
    Ok(())
}

pub(super) fn strip_hop_headers(headers: &mut HeaderMap, request: bool) -> io::Result<()> {
    let mut nominated = Vec::new();
    for value in headers.get_all("connection") {
        for token in value.as_bytes().split(|byte| *byte == b',') {
            nominated.push(HeaderName::from_bytes(token.trim_ascii()).map_err(io_error)?);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in HOP_HEADERS {
        headers.remove(*name);
    }
    let trailers = request
        && headers.get_all("te").iter().any(|value| {
            value
                .as_bytes()
                .split(|b| *b == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"trailers"))
        });
    headers.remove("te");
    if trailers {
        headers.insert("te", HeaderValue::from_static("trailers"));
    }
    Ok(())
}

pub(super) fn patch(headers: &mut HeaderMap, patch: Option<&HttpHeaderPatch>) -> io::Result<()> {
    if let Some(patch) = patch {
        for name in &patch.remove_headers {
            headers.remove(name);
        }
        for (name, value) in &patch.overwrite_headers {
            set(headers, name, value)?;
        }
        for (name, value) in &patch.default_headers {
            if !headers.contains_key(name) {
                set(headers, name, value)?;
            }
        }
    }
    Ok(())
}

pub(super) fn set(headers: &mut HeaderMap, name: &str, value: &str) -> io::Result<()> {
    headers.insert(
        HeaderName::from_bytes(name.as_bytes()).map_err(io_error)?,
        HeaderValue::from_str(value).map_err(io_error)?,
    );
    Ok(())
}

pub(super) fn patched(
    headers: &mut HeaderMap,
    changes: Option<&HttpHeaderPatch>,
    id: Option<(&str, &str)>,
    request: bool,
    limit: usize,
) -> io::Result<()> {
    let length = content_length(headers)?;
    patch(headers, changes)?;
    if let Some((name, value)) = id {
        set(headers, name, value)?;
    }
    validate_multiplexed(headers, request, limit)?;
    if content_length(headers)? != length {
        return Err(invalid("Header patch changes body framing"));
    }
    Ok(())
}

pub(super) fn bodyless(method: &Method, status: StatusCode) -> bool {
    method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

pub(super) fn validate_response(response: &mut Response<()>, limit: usize) -> io::Result<()> {
    validate_multiplexed(response.headers(), false, limit)?;
    let status = response.status();
    if status.as_u16() >= 600 || status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(invalid("Unsupported response status"));
    }
    if let Some(length) = content_length(response.headers())? {
        if status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::RESET_CONTENT && length != 0
        {
            return Err(invalid("Content-Length on body-forbidden response"));
        }
        set(
            response.headers_mut(),
            "content-length",
            &length.to_string(),
        )?;
    }
    Ok(())
}

pub(super) fn expect_continue(headers: &HeaderMap) -> io::Result<bool> {
    let mut expect = false;
    for value in headers.get_all("expect") {
        if !value.as_bytes().eq_ignore_ascii_case(b"100-continue") {
            return Err(invalid("Unsupported expectation"));
        }
        expect = true;
    }
    Ok(expect)
}

pub(super) fn authority(value: &str) -> io::Result<http::uri::Authority> {
    let parsed: http::uri::Authority = value.parse().map_err(io_error)?;
    if parsed.host().is_empty() || value.contains('@') {
        return Err(invalid("Invalid HTTP authority"));
    }
    let port = if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| invalid("Invalid IPv6 authority"))?;
        value[1..end]
            .parse::<std::net::Ipv6Addr>()
            .map_err(io_error)?;
        let suffix = &value[end + 1..];
        if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("Invalid authority suffix"))?,
            )
        }
    } else {
        if parsed.host().contains(':') {
            return Err(invalid("IPv6 authority requires brackets"));
        }
        value.split_once(':').map(|(_, port)| port)
    };
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return Err(invalid("Invalid authority port"));
        }
    }
    Ok(parsed)
}

pub(super) fn normalize_request(request: &mut Request<()>, limit: usize) -> io::Result<()> {
    validate_multiplexed(request.headers(), true, limit)?;
    if request.method() == Method::CONNECT {
        return Err(invalid("CONNECT is not supported"));
    }
    let path = request
        .uri()
        .path_and_query()
        .ok_or_else(|| invalid("Missing request path"))?
        .as_str();
    if !(path.starts_with('/') || request.method() == Method::OPTIONS && path == "*") {
        return Err(invalid("Invalid request path"));
    }
    if !matches!(request.uri().scheme_str(), Some("http" | "https")) {
        return Err(invalid("Invalid request scheme"));
    }
    let effective = authority(
        request
            .uri()
            .authority()
            .ok_or_else(|| invalid("Missing request authority"))?
            .as_str(),
    )?;
    if request.headers().get_all("host").iter().count() > 1 {
        return Err(invalid("Multiple Host fields"));
    }
    if let Some(host) = request.headers().get("host") {
        let host = authority(host.to_str().map_err(io_error)?)?;
        let default_port = if request.uri().scheme_str() == Some("https") {
            443
        } else {
            80
        };
        if !host.host().eq_ignore_ascii_case(effective.host())
            || host.port_u16().unwrap_or(default_port)
                != effective.port_u16().unwrap_or(default_port)
        {
            return Err(invalid("Host and authority disagree"));
        }
    }
    set(request.headers_mut(), "host", effective.as_str())?;
    expect_continue(request.headers())?;
    Ok(())
}

pub(super) fn update_request_uri(request: &mut Request<()>, path: &str) -> io::Result<()> {
    let host = request
        .headers()
        .get("host")
        .ok_or_else(|| invalid("Host patch removes authority"))?
        .to_str()
        .map_err(io_error)?;
    let host = authority(host)?;
    let uri = http::Uri::builder()
        .scheme(request.uri().scheme_str().unwrap_or("http"))
        .authority(host)
        .path_and_query(path)
        .build()
        .map_err(io_error)?;
    *request.uri_mut() = uri;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn duplex_progress_keeps_a_quiet_direction_alive() {
        let activity = Activity::new(10);
        let blocked = activity.wait(std::future::pending::<io::Result<()>>());
        tokio::pin!(blocked);
        for _ in 0..5 {
            assert!(tokio::time::timeout(Duration::from_secs(9), &mut blocked)
                .await
                .is_err());
            activity.touch();
        }
        assert_eq!(blocked.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn repeated_binary_fields_and_connection_tokens() {
        let mut fields = HeaderMap::new();
        fields.append("set-cookie", HeaderValue::from_static("a=1"));
        fields.append("set-cookie", HeaderValue::from_static("b=2"));
        fields.insert("x-opaque", HeaderValue::from_bytes(b"\xff").unwrap());
        fields.insert("connection", HeaderValue::from_static("close, x-private"));
        fields.insert("x-private", HeaderValue::from_static("secret"));
        strip_hop_headers(&mut fields, false).unwrap();
        assert!(!fields.contains_key("x-private"));
        assert_eq!(fields.get_all("set-cookie").iter().count(), 2);
        assert_eq!(fields["x-opaque"].as_bytes(), b"\xff");
    }

    #[test]
    fn authority_and_host_are_unambiguous() {
        for (uri, host, valid) in [
            ("https://example.com/", "EXAMPLE.COM:443", true),
            ("https://example.com/", "example.com:80", false),
            ("http://[::1]:81/", "[::1]:81", true),
            ("http://a/", "a:bad", false),
        ] {
            let mut request = Request::builder()
                .uri(uri)
                .header("host", host)
                .body(())
                .unwrap();
            assert_eq!(normalize_request(&mut request, 65536).is_ok(), valid);
        }
        let mut request = Request::builder()
            .uri("http://a/")
            .header("host", "a")
            .header("host", "a")
            .body(())
            .unwrap();
        assert!(normalize_request(&mut request, 65536).is_err());
    }

    #[test]
    fn lengths_trailers_and_patch_framing_are_checked() {
        let mut fields = HeaderMap::new();
        fields.append("content-length", HeaderValue::from_static("5, 5"));
        assert_eq!(content_length(&fields).unwrap(), Some(5));
        fields.append("content-length", HeaderValue::from_static("6"));
        assert!(content_length(&fields).is_err());
        assert!(validate_trailers(&fields, 65536).is_err());
        fields.clear();
        set(&mut fields, "content-length", "5").unwrap();
        let changes = HttpHeaderPatch {
            remove_headers: vec!["content-length".into()],
            overwrite_headers: Default::default(),
            default_headers: Default::default(),
        };
        assert!(patched(&mut fields, Some(&changes), None, true, 65536).is_err());
    }
}
