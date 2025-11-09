mod chunk_transfer;
mod header_map;
mod header_tuple;
mod http_parser;
mod line_reader;
mod string_util;

use std::collections::HashMap;

use log::{error, info};
use memchr::memmem;
use mime_guess::MimeGuess;
use radix_trie::{Trie, TrieCommon};
use rand::Rng;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::async_stream::AsyncStream;
use crate::config::HttpValueMatch;
use crate::copy_bidirectional::copy_bidirectional;
use crate::tcp::{setup_target_stream, TargetHttpActionData, TargetHttpPathData};
use crate::util::{allocate_vec, write_all};

use header_map::HeaderMap;
use header_tuple::HeaderTuple;

pub async fn handle_http_stream(
    tcp_nodelay: bool,
    path_configs: &Trie<String, Vec<TargetHttpPathData>>,
    default_action: &TargetHttpActionData,
    mut stream: Box<dyn AsyncStream>,
    addr: &std::net::SocketAddr,
    mut initial_data: Option<Vec<u8>>,
) -> std::io::Result<()> {
    const LOG_PREFIX: &str = "http";

    let stream_id = format!("{:x}", rand::rng().random::<u64>());

    let mut iteration = 0usize;

    struct CachedTarget {
        base_path: String,
        stream: Box<dyn AsyncStream>,
    }

    let mut cached_target: Option<CachedTarget> = None;

    loop {
        iteration = iteration.wrapping_add(1);

        if iteration > 1 {
            // A response was written to `stream`, make sure to flush it.
            stream.flush().await?;
        }

        let request_id = format!("{}#{}", stream_id, iteration);

        // TODO: add a read timeout
        // Use initial_data only on the first iteration (take() consumes it)
        let initial = if iteration == 1 {
            initial_data.take()
        } else {
            None
        };
        let mut request_data = http_parser::ParsedHttpData::parse(&mut stream, initial).await?;

        let mut first_line = request_data.first_line().to_string();

        if !first_line.ends_with(" HTTP/1.1") {
            return Err(std::io::Error::other(
                format!("Not a http/1.1 request: {}", request_data.first_line()),
            ));
        }

        // remove the http specifier
        first_line.truncate(first_line.len() - 9);

        let space_index = match first_line.find(' ') {
            Some(i) => i,
            None => {
                return Err(std::io::Error::other(
                    format!(
                        "Invalid http request directive: {}",
                        request_data.first_line()
                    ),
                ));
            }
        };

        let request_path = first_line.split_off(space_index + 1);
        if !request_path.starts_with('/') {
            return Err(std::io::Error::other(
                format!("Invalid http request path: {}", request_data.first_line()),
            ));
        }

        let mut verb = first_line;
        // remove the space from the verb.
        verb.truncate(verb.len() - 1);
        verb.make_ascii_uppercase();

        let (base_path, path_action) =
            find_matching_action(path_configs, default_action, &request_path, &request_data);

        match path_action {
            TargetHttpActionData::CloseConnection => {
                info!("[{}] {} {} [close]", LOG_PREFIX, &verb, &request_path);
                break;
            }
            TargetHttpActionData::ServeMessage {
                status_code,
                status_message,
                content,
                response_headers,
                response_id_header_name,
            } => {
                if let Some(mut t) = cached_target.take() {
                    let _ = t.stream.try_shutdown().await;
                }

                if request_data.headers().expect_100()? {
                    write_all(&mut stream, b"HTTP/1.1 417 Expectation Failed\r\n\r\n").await?;
                    info!(
                        "[{}] {} {} [serve message: expectation failed]",
                        LOG_PREFIX, &verb, &request_path
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
                    LOG_PREFIX, &verb, &request_path, status_code
                );

                break;
            }
            TargetHttpActionData::ServeDirectory {
                path,
                response_headers,
                response_id_header_name,
            } => {
                if let Some(mut t) = cached_target.take() {
                    let _ = t.stream.try_shutdown().await;
                }

                if verb != "GET" && verb != "HEAD" {
                    let mut error_response = String::from("HTTP/1.1 501 Not Implemented\r\n");
                    error_response.push_str("content-length: 0\r\nconnection: close\r\n");
                    if let Some(header_name) = response_id_header_name {
                        (header_name, &request_id).append_header_to_string(&mut error_response);
                    }
                    error_response.push_str("\r\n");
                    write_all(&mut stream, &error_response.into_bytes()).await?;
                    break;
                }

                if memmem::find(request_path.as_bytes(), b"..").is_some() {
                    return Err(std::io::Error::other(
                        format!(
                            "Ignoring request with possible base path escape: {}",
                            request_data.first_line()
                        ),
                    ));
                }
                let file_path = string_util::update_base_path(&request_path, base_path, path);
                match tokio::fs::canonicalize(file_path).await {
                    Ok(mut canonical_path) => {
                        // We filter out '..' from requests, so can this still occur?
                        if !canonical_path.starts_with(path) {
                            return Err(std::io::Error::other(
                                format!(
                                    "Canonical path ({}) does not start with serve path ({})",
                                    canonical_path.display(),
                                    path
                                ),
                            ));
                        }

                        if canonical_path.is_dir() {
                            canonical_path.push("index.html");
                        }

                        match tokio::fs::metadata(&canonical_path).await {
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
                                    &verb,
                                    &request_path,
                                    mime_type.essence_str()
                                );

                                if request_connection_close {
                                    break;
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
                                    LOG_PREFIX, &verb, &request_path
                                );

                                if request_connection_close {
                                    break;
                                }
                            }
                        }
                    }
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
                            LOG_PREFIX, &verb, &request_path
                        );

                        if request_connection_close {
                            break;
                        }
                    }
                    Err(e) => {
                        info!(
                            "[{}] {} {} [serve file: invalid path]",
                            LOG_PREFIX, &verb, &request_path
                        );
                        return Err(std::io::Error::other(
                            format!("Could not canonicalize path: {}", e),
                        ));
                    }
                }
            }
            TargetHttpActionData::Forward {
                location_data,
                next_address_index,
                replacement_path,
                request_header_patch,
                response_header_patch,
                request_id_header_name,
                response_id_header_name,
            } => {
                if let Some(ref p) = replacement_path {
                    let new_path = string_util::update_base_path(&request_path, base_path, p);
                    request_data.set_first_line(format!("{} {} HTTP/1.1", verb, new_path));
                }

                let mut target_stream = match cached_target.take() {
                    Some(t) if t.base_path == base_path => t.stream,
                    no_match => {
                        if let Some(mut t) = no_match {
                            let _ = t.stream.try_shutdown().await;
                        }
                        let target_location = if location_data.len() > 1 {
                            // fetch_add wraps around on overflow.
                            let index = next_address_index
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            &location_data[index % location_data.len()]
                        } else {
                            &location_data[0]
                        };
                        setup_target_stream(addr, target_location, tcp_nodelay).await?
                    }
                };

                request_data
                    .headers_mut()
                    .patch_headers(request_header_patch);

                if let Some(header_name) = request_id_header_name {
                    request_data
                        .headers_mut()
                        .insert(header_name.to_string(), request_id.clone());
                }

                if request_data.headers().expect_100()? {
                    // the expect response looks like: HTTP/1.1 100 Continue\r\n\r\n
                    // TODO: can there be headers after the expectation status line? if so,
                    // read them and check for connection close?
                    let mut target_reader = line_reader::LineReader::new();

                    let mut expect_response = target_reader
                        .read_line(&mut target_stream)
                        .await?
                        .to_string();

                    // Read the second '\r\n' after the expectation status line.
                    if !target_reader
                        .read_line(&mut target_stream)
                        .await?
                        .is_empty()
                    {
                        return Err(std::io::Error::other(
                            "Unexpected non-empty line after reading expectation",
                        ));
                    }

                    // Readd the crlfs to prepare our response for forwarding.
                    expect_response.push_str("\r\n\r\n");

                    let expectation_success = expect_response.starts_with("HTTP/1.1 100");
                    let expectation_failure = expect_response.starts_with("HTTP/1.1 417");

                    if !expectation_success && !expectation_failure {
                        return Err(std::io::Error::other(
                            format!("Unexpected expectation response: {}", expect_response),
                        ));
                    }

                    if !target_reader.unparsed_data().is_empty() {
                        return Err(std::io::Error::other(
                            "Unexpected unparsed data after reading expectation",
                        ));
                    }

                    write_all(&mut stream, &expect_response.into_bytes()).await?;

                    if !expectation_success {
                        cached_target = Some(CachedTarget {
                            base_path: base_path.to_string(),
                            stream: target_stream,
                        });
                        continue;
                    }
                }

                let request_websocket_upgrade = request_data.headers().websocket_upgrade();

                forward_message(&mut stream, Some(&mut target_stream), request_data).await?;

                // Flush the request, and then read the response.
                target_stream.flush().await?;

                // TODO: add a read timeout
                // Responses from target server never have initial_data
                let mut response_data =
                    http_parser::ParsedHttpData::parse(&mut target_stream, None).await?;

                response_data
                    .headers_mut()
                    .patch_headers(response_header_patch);

                if let Some(header_name) = response_id_header_name {
                    response_data
                        .headers_mut()
                        .insert(header_name.to_string(), request_id.clone());
                }

                response_data
                    .headers_mut()
                    .update_path_headers(base_path, replacement_path);

                if request_websocket_upgrade && verb != "HEAD" {
                    if response_data.first_line().starts_with("HTTP/1.1 101") {
                        write_all(
                            &mut stream,
                            &string_util::create_message(&response_data).into_bytes(),
                        )
                        .await?;
                        drop(response_data);
                        info!("[{}] {} {} [forward-ws]", LOG_PREFIX, &verb, &request_path);
                        return copy_bidirectional(
                            &mut stream,
                            &mut target_stream,
                            // immediately flush 101 response
                            true,
                            false,
                        )
                        .await
                        .map(|_| ());
                    }
                    error!("Websocket upgrade failed: {}", response_data.first_line());
                }

                let response_connection_close = response_data.headers().connection_close();

                if verb != "HEAD" {
                    forward_message(&mut target_stream, Some(&mut stream), response_data).await?;
                }

                info!("[{}] {} {} [forward]", LOG_PREFIX, &verb, &request_path);

                if response_connection_close {
                    let _ = target_stream.try_shutdown().await;
                    break;
                }

                cached_target = Some(CachedTarget {
                    base_path: base_path.to_string(),
                    stream: target_stream,
                });
            }
        }
    }

    // Flush any remaining response data.
    stream.flush().await?;
    let _ = stream.try_shutdown().await;

    if let Some(mut t) = cached_target.take() {
        let _ = t.stream.try_shutdown().await;
    }

    Ok(())
}

fn find_matching_action<'a>(
    path_configs: &'a Trie<String, Vec<TargetHttpPathData>>,
    default_action: &'a TargetHttpActionData,
    request_path: &str,
    request_data: &http_parser::ParsedHttpData,
) -> (&'a str, &'a TargetHttpActionData) {
    let matching_configs = if request_path.ends_with("/") {
        path_configs.get_ancestor(request_path)
    } else {
        let mut lookup_path = String::with_capacity(request_path.len() + 1);
        lookup_path.push_str(request_path);
        lookup_path.push('/');
        path_configs.get_ancestor(&lookup_path)
    };

    if let Some(t) = matching_configs {
        for path_config in t.value().unwrap().iter() {
            if let Some(ref required_headers) = path_config.required_request_headers {
                if !has_required_headers(request_data.headers(), required_headers) {
                    continue;
                }
            }
            return (t.key().unwrap(), &path_config.http_action);
        }
    }

    ("/", default_action)
}

fn has_required_headers(
    headers: &HashMap<String, String>,
    required: &HashMap<String, HttpValueMatch>,
) -> bool {
    for (key, value_match) in required.iter() {
        let header_value = headers.get(key).map(String::as_str);
        if !value_match.matches(header_value) {
            return false;
        }
    }
    true
}

//async fn connect_location(location: &Location) -> std::io::Result<Box<dyn TargetStream>> {
//match location {
//Location::Net(address) => TcpStream::connect(address).await.map(|stream| {
//let _ = stream.set_nodelay(true);
//Box::new(stream) as Box<dyn TargetStream>
//}),
//Location::Unix(path) => UnixStream::connect(path)
//.await
//.map(|stream| Box::new(stream) as Box<dyn TargetStream>),
//}
//}

async fn forward_message<R, W>(
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
        return Err(std::io::Error::other(
            format!(
                "Unexpected request data with len {}",
                reader.unparsed_data().len()
            ),
        ));
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
        return Err(std::io::Error::other(
            format!(
                "Unexpected content length ({} > {})",
                unparsed_data.len(),
                content_length
            ),
        ));
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
            return Err(std::io::Error::other(
                format!(
                    "Got EOF while reading content with length, {} bytes were remaining",
                    remaining
                ),
            ));
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
            return Err(std::io::Error::other(
                "Got EOF during chunk transfer",
            ));
        }
        chunk_transfer
            .run(&buf[0..read_len], &mut maybe_to_stream)
            .await?;
    }

    Ok(())
}
