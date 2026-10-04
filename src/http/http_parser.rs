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
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::other(format!(
                        "invalid http request line: {}",
                        line
                    )));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.append(header_key, header_value);
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
