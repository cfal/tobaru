use super::body::forward_message;
use super::header_map::HeaderMap;
use super::header_tuple::HeaderTuple;
use super::string_util;
use super::{Outcome, Request, Session};
use crate::tcp::TargetHttpActionData;
use crate::util::allocate_vec;
use crate::util::write_all;
use log::info;
use memchr::memmem;
use mime_guess::MimeGuess;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl Session<'_> {
    pub(super) async fn serve_local(&mut self, request: Request<'_>) -> std::io::Result<Outcome> {
        self.close_target().await;
        let mut stream = &mut self.stream;
        let Request {
            data: request_data,
            verb,
            path: request_path,
            id: request_id,
            base_path,
            action: path_action,
        } = request;
        const LOG_PREFIX: &str = "http";
        match path_action {
            TargetHttpActionData::ServeMessage {
                status_code,
                status_message,
                content,
                response_headers,
                response_id_header_name,
            } => {
                if request_data.headers().expect_100()? {
                    write_all(&mut stream, b"HTTP/1.1 417 Expectation Failed\r\n\r\n").await?;
                    info!(
                        "[{}] {} {} [serve message: expectation failed]",
                        LOG_PREFIX, verb, request_path
                    );
                } else {
                    forward_message(
                        &mut stream,
                        None::<&mut tokio::net::TcpStream>,
                        request_data,
                    )
                    .await?;

                    let mut error_response = format!("HTTP/1.1 {}", status_code);
                    if let Some(msg) = status_message {
                        error_response.push(' ');
                        error_response.push_str(msg);
                    }
                    error_response.push_str("\r\n");
                    response_headers.append_headers_to_string(&mut error_response);
                    if let Some(header_name) = response_id_header_name {
                        (header_name, &request_id).append_header_to_string(&mut error_response);
                    }
                    error_response
                        .push_str("transfer-encoding: chunked\r\nconnection: close\r\n\r\n");
                    write_all(&mut stream, &error_response.into_bytes()).await?;
                    if verb != "HEAD" {
                        if !content.is_empty() {
                            write_all(
                                &mut stream,
                                &format!("{:X}\r\n", content.len()).into_bytes(),
                            )
                            .await?;
                            write_all(&mut stream, content.as_bytes()).await?;
                            write_all(&mut stream, b"\r\n").await?;
                        }
                        write_all(&mut stream, b"0\r\n\r\n").await?;
                    }
                }

                info!(
                    "[{}] {} {} [serve message: {}]",
                    LOG_PREFIX, verb, request_path, status_code
                );

                return Ok(Outcome::Close);
            }
            TargetHttpActionData::ServeDirectory {
                path,
                response_headers,
                response_id_header_name,
            } => {
                if verb != "GET" && verb != "HEAD" {
                    let mut error_response = String::from("HTTP/1.1 501 Not Implemented\r\n");
                    error_response.push_str("content-length: 0\r\nconnection: close\r\n");
                    if let Some(header_name) = response_id_header_name {
                        (header_name, &request_id).append_header_to_string(&mut error_response);
                    }
                    error_response.push_str("\r\n");
                    write_all(&mut stream, &error_response.into_bytes()).await?;
                    return Ok(Outcome::Close);
                }

                if memmem::find(request_path.as_bytes(), b"..").is_some() {
                    return Err(std::io::Error::other(format!(
                        "Ignoring request with possible base path escape: {}",
                        request_data.first_line()
                    )));
                }
                let file_path = string_util::update_base_path(&request_path, base_path, path);
                match resolve_file(path, &file_path).await {
                    Ok(canonical_path) => match tokio::fs::metadata(&canonical_path).await {
                        Ok(m) if m.is_file() => {
                            let mime_type =
                                MimeGuess::from_path(&canonical_path).first_or_octet_stream();
                            let mut file = File::open(canonical_path).await?;
                            let mut buf = allocate_vec(4096);

                            let mut ok_response = format!("HTTP/1.1 200\r\ntransfer-encoding: chunked\r\ncontent-type: {}\r\n", mime_type.essence_str());
                            response_headers.append_headers_to_string(&mut ok_response);
                            if let Some(header_name) = response_id_header_name {
                                (header_name, &request_id)
                                    .append_header_to_string(&mut ok_response);
                            }

                            let request_connection_close =
                                request_data.headers().connection_close();
                            if request_connection_close {
                                ok_response.push_str("connection: close\r\n");
                            } else {
                                ok_response.push_str("connection: keep-alive\r\n");
                            };

                            ok_response.push_str("\r\n");
                            write_all(&mut stream, &ok_response.into_bytes()).await?;

                            if verb == "GET" {
                                loop {
                                    let read_len = file.read(&mut buf).await?;
                                    if read_len == 0 {
                                        break;
                                    }
                                    write_all(
                                        &mut stream,
                                        &format!("{:X}\r\n", read_len).into_bytes(),
                                    )
                                    .await?;
                                    write_all(&mut stream, &buf[0..read_len]).await?;
                                    write_all(&mut stream, b"\r\n").await?;
                                }
                                stream.write_all(b"0\r\n\r\n").await?;
                            }

                            info!(
                                "[{}] {} {} [serve file: {}]",
                                LOG_PREFIX,
                                verb,
                                request_path,
                                mime_type.essence_str()
                            );

                            if request_connection_close {
                                return Ok(Outcome::Close);
                            }
                        }
                        _ => {
                            let mut not_found_response =
                                String::from("HTTP/1.1 404\r\ncontent-length: 0\r\n");
                            let request_connection_close =
                                request_data.headers().connection_close();
                            if request_connection_close {
                                not_found_response.push_str("connection: close\r\n");
                            } else {
                                not_found_response.push_str("connection: keep-alive\r\n");
                            };
                            if let Some(header_name) = response_id_header_name {
                                (header_name, &request_id)
                                    .append_header_to_string(&mut not_found_response);
                            }
                            not_found_response.push_str("\r\n");
                            write_all(&mut stream, &not_found_response.into_bytes()).await?;

                            info!(
                                "[{}] {} {} [serve file: invalid, not a file]",
                                LOG_PREFIX, verb, request_path
                            );

                            if request_connection_close {
                                return Ok(Outcome::Close);
                            }
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let mut not_found_response =
                            String::from("HTTP/1.1 404\r\ncontent-length: 0\r\n");
                        let request_connection_close = request_data.headers().connection_close();
                        if request_connection_close {
                            not_found_response.push_str("connection: close\r\n");
                        } else {
                            not_found_response.push_str("connection: keep-alive\r\n");
                        };
                        if let Some(header_name) = response_id_header_name {
                            (header_name, &request_id)
                                .append_header_to_string(&mut not_found_response);
                        }
                        not_found_response.push_str("\r\n");
                        write_all(&mut stream, &not_found_response.into_bytes()).await?;

                        info!(
                            "[{}] {} {} [serve file: not found]",
                            LOG_PREFIX, verb, request_path
                        );

                        if request_connection_close {
                            return Ok(Outcome::Close);
                        }
                    }
                    Err(e) => {
                        info!(
                            "[{}] {} {} [serve file: invalid path]",
                            LOG_PREFIX, verb, request_path
                        );
                        return Err(std::io::Error::other(format!(
                            "Could not canonicalize path: {}",
                            e
                        )));
                    }
                }
            }

            _ => unreachable!("local action required"),
        }
        Ok(Outcome::Continue)
    }
}

async fn resolve_file(root: &str, requested: &str) -> std::io::Result<std::path::PathBuf> {
    let root = tokio::fs::canonicalize(root).await?;
    let mut path = tokio::fs::canonicalize(requested).await?;
    if !path.starts_with(&root) {
        return Err(std::io::Error::other("File is outside the serving root"));
    }
    if tokio::fs::metadata(&path).await?.is_dir() {
        path = tokio::fs::canonicalize(path.join("index.html")).await?;
    }
    // The index may itself be a symlink. Check the final target, not just its directory.
    if !path.starts_with(&root) {
        return Err(std::io::Error::other("Index is outside the serving root"));
    }
    Ok(path)
}
