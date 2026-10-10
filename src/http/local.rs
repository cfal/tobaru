use std::io;
use std::path::{Component, Path, PathBuf};

use log::info;
use mime_guess::MimeGuess;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::body::drain_request;
use super::header_map::HeaderMap;
use super::header_tuple::HeaderTuple;
use super::{string_util, Outcome, Request, Session};
use crate::tcp::TargetHttpActionData;
use crate::tokio_util::with_timeout;
use crate::util::{allocate_vec, write_all};

impl Session<'_> {
    pub(super) async fn serve_message(&mut self, request: Request<'_>) -> io::Result<Outcome> {
        self.close_target().await;
        let TargetHttpActionData::ServeMessage {
            status_code,
            status_message,
            content,
            response_headers,
            response_id_header_name,
        } = request.action
        else {
            unreachable!("message action required")
        };

        if request.data.headers().expect_100()? {
            write_all(&mut self.stream, b"HTTP/1.1 417 Expectation Failed\r\n\r\n").await?;
            info!(
                "[http] {} {} [serve message: expectation failed]",
                request.verb, request.path
            );
        } else {
            with_timeout(
                self.timeouts.local_body_timeout_secs,
                "HTTP local request body",
                drain_request(&mut self.stream, request.data),
            )
            .await?;
            let mut response = format!("HTTP/1.1 {}", status_code);
            if let Some(message) = status_message {
                response.push(' ');
                response.push_str(message);
            }
            response.push_str("\r\n");
            response_headers.append_headers_to_string(&mut response);
            if let Some(name) = response_id_header_name {
                (name, &request.id).append_header_to_string(&mut response);
            }
            let body_allowed = !matches!(status_code, 204 | 205 | 304);
            if body_allowed {
                response.push_str("transfer-encoding: chunked\r\n");
            } else if *status_code == 205 {
                response.push_str("content-length: 0\r\n");
            }
            response.push_str("connection: close\r\n\r\n");
            write_all(&mut self.stream, response.as_bytes()).await?;
            if request.verb != "HEAD" && body_allowed {
                if !content.is_empty() {
                    write_chunk(&mut self.stream, content.as_bytes()).await?;
                }
                write_all(&mut self.stream, b"0\r\n\r\n").await?;
            }
        }
        info!(
            "[http] {} {} [serve message: {}]",
            request.verb, request.path, status_code
        );
        Ok(Outcome::Close)
    }

    pub(super) async fn serve_directory(&mut self, request: Request<'_>) -> io::Result<Outcome> {
        self.close_target().await;
        let TargetHttpActionData::ServeDirectory {
            path,
            response_headers,
            response_id_header_name,
        } = request.action
        else {
            unreachable!("directory action required")
        };
        let close = request.data.headers().connection_close();
        let outcome = if close {
            Outcome::Close
        } else {
            Outcome::Continue
        };
        if request.verb != "GET" && request.verb != "HEAD" {
            let mut response = String::from(
                "HTTP/1.1 501 Not Implemented\r\ncontent-length: 0\r\nconnection: close\r\n",
            );
            if let Some(name) = response_id_header_name {
                (name, &request.id).append_header_to_string(&mut response);
            }
            response.push_str("\r\n");
            write_all(&mut self.stream, response.as_bytes()).await?;
            return Ok(Outcome::Close);
        }
        let file_path = static_file_path(path, &request.path, request.base_path)?;
        if request.data.headers().expect_100()? {
            write_all(&mut self.stream, b"HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(Outcome::Close);
        }
        self.reader = Some(
            with_timeout(
                self.timeouts.local_body_timeout_secs,
                "HTTP local request body",
                drain_request(&mut self.stream, request.data),
            )
            .await?,
        );
        let canonical_path = match resolve_file(path, &file_path).await {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                write_not_found(
                    &mut self.stream,
                    close,
                    response_id_header_name.as_ref(),
                    &request.id,
                )
                .await?;
                info!(
                    "[http] {} {} [serve file: not found]",
                    request.verb, request.path
                );
                return Ok(outcome);
            }
            Err(error) => {
                info!(
                    "[http] {} {} [serve file: invalid path]",
                    request.verb, request.path
                );
                return Err(io::Error::other(format!(
                    "Could not canonicalize path: {}",
                    error
                )));
            }
        };
        if !matches!(tokio::fs::metadata(&canonical_path).await, Ok(metadata) if metadata.is_file())
        {
            write_not_found(
                &mut self.stream,
                close,
                response_id_header_name.as_ref(),
                &request.id,
            )
            .await?;
            info!(
                "[http] {} {} [serve file: invalid, not a file]",
                request.verb, request.path
            );
            return Ok(outcome);
        }

        let mime_type = MimeGuess::from_path(&canonical_path).first_or_octet_stream();
        let mut file = File::open(canonical_path).await?;
        let mut buffer = allocate_vec(4096);
        let mut response = format!(
            "HTTP/1.1 200\r\ntransfer-encoding: chunked\r\ncontent-type: {}\r\n",
            mime_type.essence_str()
        );
        response_headers.append_headers_to_string(&mut response);
        if let Some(name) = response_id_header_name {
            (name, &request.id).append_header_to_string(&mut response);
        }
        response.push_str(connection_header(close));
        response.push_str("\r\n");
        write_all(&mut self.stream, response.as_bytes()).await?;
        if request.verb == "GET" {
            loop {
                let length = file.read(&mut buffer).await?;
                if length == 0 {
                    break;
                }
                write_chunk(&mut self.stream, &buffer[..length]).await?;
            }
            self.stream.write_all(b"0\r\n\r\n").await?;
        }
        info!(
            "[http] {} {} [serve file: {}]",
            request.verb,
            request.path,
            mime_type.essence_str()
        );
        Ok(outcome)
    }
}

fn connection_header(close: bool) -> &'static str {
    if close {
        "connection: close\r\n"
    } else {
        "connection: keep-alive\r\n"
    }
}

async fn write_not_found<W: AsyncWrite + Unpin>(
    stream: &mut W,
    close: bool,
    id_header: Option<&String>,
    request_id: &String,
) -> io::Result<()> {
    let mut response = String::from("HTTP/1.1 404\r\ncontent-length: 0\r\n");
    response.push_str(connection_header(close));
    if let Some(name) = id_header {
        (name, request_id).append_header_to_string(&mut response);
    }
    response.push_str("\r\n");
    write_all(stream, response.as_bytes()).await
}

async fn write_chunk<W: AsyncWrite + Unpin>(stream: &mut W, bytes: &[u8]) -> io::Result<()> {
    write_all(stream, format!("{:X}\r\n", bytes.len()).as_bytes()).await?;
    write_all(stream, bytes).await?;
    write_all(stream, b"\r\n").await
}

pub(super) fn static_file_path(root: &str, target: &str, base_path: &str) -> io::Result<PathBuf> {
    let target_path = target.split_once('?').map_or(target, |(path, _)| path);
    let relative = string_util::update_base_path(target_path, base_path, "/");
    let decoded = percent_encoding::percent_decode_str(&relative)
        .decode_utf8()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if Path::new(decoded.as_ref())
        .components()
        .any(|part| part == Component::ParentDir)
        || decoded.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid static file path",
        ));
    }
    Ok(Path::new(root).join(decoded.trim_start_matches('/')))
}

pub(super) async fn resolve_file(root: &str, requested: &Path) -> io::Result<PathBuf> {
    let root = tokio::fs::canonicalize(root).await?;
    let mut path = tokio::fs::canonicalize(requested).await?;
    if !path.starts_with(&root) {
        return Err(io::Error::other("File is outside the serving root"));
    }
    if tokio::fs::metadata(&path).await?.is_dir() {
        path = tokio::fs::canonicalize(path.join("index.html")).await?;
    }
    // The index may itself be a symlink. Check the final target, not just its directory.
    if !path.starts_with(&root) {
        return Err(io::Error::other("Index is outside the serving root"));
    }
    Ok(path)
}
