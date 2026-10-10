use tokio::io::AsyncRead;

use super::header_map::Headers;
use super::line_reader::LineReader;

pub struct ParsedHttpData {
    first_line: String,
    headers: Headers,
    line_reader: LineReader,
}

impl ParsedHttpData {
    pub async fn parse<T>(stream: &mut T, mut line_reader: LineReader) -> std::io::Result<Self>
    where
        T: AsyncRead + Unpin,
    {
        let mut first_line: Option<String> = None;
        let mut headers = Headers::default();

        let mut line_count = 0;
        loop {
            let line = line_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::other("http request line is too long"));
            }

            if first_line.is_none() {
                if !super::syntax::is_field_value(line.as_bytes()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid HTTP start line",
                    ));
                }
                first_line = Some(line.to_string());
            } else {
                let (name, value) = super::syntax::parse_field(line).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid http request line: {}", line),
                    )
                })?;
                headers.append(name.to_owned(), value.to_owned());
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::other("http request is too long"));
            }
        }

        let first_line = first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            line_reader,
        })
    }

    pub fn first_line(&self) -> &str {
        self.first_line.as_str()
    }

    pub fn set_first_line(&mut self, first_line: String) {
        self.first_line = first_line;
    }

    pub fn response_status(&self) -> std::io::Result<u16> {
        let mut parts = self.first_line.splitn(3, ' ');
        if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
            return Err(std::io::Error::other("Invalid HTTP response version"));
        }
        let code = parts.next().unwrap_or_default();
        if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(std::io::Error::other("Invalid HTTP response status"));
        }
        let status = code.parse::<u16>().map_err(std::io::Error::other)?;
        if !(100..600).contains(&status) {
            return Err(std::io::Error::other("Invalid HTTP response status"));
        }
        Ok(status)
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    pub fn into_reader(self) -> LineReader {
        self.line_reader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::header_map::HeaderMap;
    use crate::http::test_io::{ReadStep, ScriptedIo};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn malformed_fields_are_rejected_for_requests_and_responses_at_every_split() {
        for start in ["GET / HTTP/1.1", "HTTP/1.1 200 OK"] {
            for field in [
                " X-Key: value",
                "\tX-Key: value",
                "X-Key : value",
                ": value",
                "Bad Name: value",
                "X-Key\0: value",
                "X-Key: a\rb",
                "X-Key: a\nb",
                "X-Key: \u{b}value",
                "X-Key: value\u{7f}",
            ] {
                let wire = format!("{start}\r\n{field}\r\n\r\n");
                for split in 0..=wire.len() {
                    let mut stream = ScriptedIo::split(wire.as_bytes(), split);
                    assert!(
                        ParsedHttpData::parse(&mut stream, LineReader::new())
                            .await
                            .is_err(),
                        "{field:?} at {split}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn header_values_trim_only_http_optional_whitespace() {
        let wire = "GET / HTTP/1.1\r\nX-Test:\t \u{a0}value\u{a0}\t \r\n\r\n";
        let mut stream = ScriptedIo::split(wire.as_bytes(), 10);
        let data = ParsedHttpData::parse(&mut stream, LineReader::new())
            .await
            .unwrap();
        assert_eq!(
            data.headers().header_values("x-test").collect::<Vec<_>>(),
            ["\u{a0}value\u{a0}"]
        );
    }

    #[tokio::test]
    async fn every_head_split_preserves_repeated_fields_and_read_ahead() {
        let wire = b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Repeat: one\r\nx-repeat: two\r\n\r\nBODY";
        for split in 0..=wire.len() {
            let mut stream = ScriptedIo::split(wire, split);
            let data = ParsedHttpData::parse(&mut stream, LineReader::new())
                .await
                .unwrap();
            assert_eq!(data.first_line(), "GET / HTTP/1.1");
            assert_eq!(
                data.headers().header_values("x-repeat").collect::<Vec<_>>(),
                ["one", "two"]
            );
            let mut suffix = data.into_reader().unparsed_data().to_vec();
            stream.read_to_end(&mut suffix).await.unwrap();
            assert_eq!(suffix, b"BODY", "split {split}");
        }
    }

    #[tokio::test]
    async fn head_limits_and_malformed_metadata_have_specific_errors() {
        let cases = [
            ("\r\n".to_owned(), "empty http request"),
            (
                "GET / HTTP/1.1\r\nmissing-colon\r\n\r\n".into(),
                "invalid http request line: missing-colon",
            ),
            (
                format!("{}\r\n\r\n", "x".repeat(4096)),
                "http request line is too long",
            ),
            (
                format!("GET / HTTP/1.1\r\n{}\r\n", "x: y\r\n".repeat(39)),
                "http request is too long",
            ),
        ];
        for (wire, expected) in cases {
            let mut stream = ScriptedIo::new([ReadStep::Data(wire.into_bytes())]);
            let error = ParsedHttpData::parse(&mut stream, LineReader::new())
                .await
                .err()
                .unwrap();
            assert_eq!(error.to_string(), expected);
        }
        for wire in [
            format!("{}\r\n\r\n", "x".repeat(4095)),
            format!("GET / HTTP/1.1\r\n{}\r\n", "x: y\r\n".repeat(38)),
        ] {
            let mut stream = ScriptedIo::new([ReadStep::Data(wire.into_bytes())]);
            assert!(ParsedHttpData::parse(&mut stream, LineReader::new())
                .await
                .is_ok());
        }
    }

    #[tokio::test]
    async fn response_status_requires_a_supported_version_and_three_digit_code() {
        for (line, expected) in [
            ("HTTP/1.1 100 Continue", Some(100)),
            ("HTTP/1.0 599 Custom", Some(599)),
            ("HTTP/1.1 204", Some(204)),
            ("HTTP/2 200 OK", None),
            ("HTTP/1.1 99 Bad", None),
            ("HTTP/1.1 600 Bad", None),
            ("HTTP/1.1 2x0 Bad", None),
            ("HTTP/1.1  200 OK", None),
        ] {
            let mut stream =
                ScriptedIo::new([ReadStep::Data(format!("{line}\r\n\r\n").into_bytes())]);
            let data = ParsedHttpData::parse(&mut stream, LineReader::new())
                .await
                .unwrap();
            assert_eq!(data.response_status().ok(), expected, "{line}");
        }
    }
}
