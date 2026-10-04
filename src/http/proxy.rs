use super::body::forward_message;
use super::header_map::HeaderMap;
use super::string_util;
use super::{http_parser, line_reader, CachedTarget};
use super::{Outcome, Request, Session};
use crate::tcp::setup_target_stream;
use crate::tcp::TargetHttpActionData;
use crate::util::write_all;
use log::{error, info};
use tokio::io::AsyncWriteExt;

impl<'a> Session<'a> {
    pub(super) async fn forward(&mut self, request: Request<'a>) -> std::io::Result<Outcome> {
        let Self {
            stream,
            cached_target,
            addr,
            tcp_nodelay,
            tcp_keepalive,
        } = self;
        let mut stream = stream;
        let tcp_nodelay = *tcp_nodelay;
        let tcp_keepalive = *tcp_keepalive;
        let Request {
            data: mut request_data,
            verb,
            path: request_path,
            id: request_id,
            base_path,
            action: path_action,
        } = request;
        const LOG_PREFIX: &str = "http";
        let TargetHttpActionData::Forward {
            location_data,
            next_address_index,
            replacement_path,
            request_header_patch,
            response_header_patch,
            request_id_header_name,
            response_id_header_name,
        } = path_action
        else {
            unreachable!("forward action required")
        };
        if let Some(ref p) = replacement_path {
            let new_path = string_util::update_base_path(&request_path, base_path, p);
            request_data.set_first_line(format!("{} {} HTTP/1.1", verb, new_path));
        }

        let mut target_stream = match cached_target.take() {
            // Actions live in the immutable configuration retained by this session.
            Some(t) if std::ptr::eq(t.action, path_action) => t.stream,
            no_match => {
                if let Some(mut t) = no_match {
                    let _ = t.stream.try_shutdown().await;
                }
                let target_location = if location_data.len() > 1 {
                    // fetch_add wraps around on overflow.
                    let index =
                        next_address_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    &location_data[index % location_data.len()]
                } else {
                    &location_data[0]
                };
                setup_target_stream(addr, target_location, tcp_nodelay, tcp_keepalive).await?
            }
        };

        request_data
            .headers_mut()
            .patch_headers(request_header_patch.as_deref());

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
                return Err(std::io::Error::other(format!(
                    "Unexpected expectation response: {}",
                    expect_response
                )));
            }

            if !target_reader.unparsed_data().is_empty() {
                return Err(std::io::Error::other(
                    "Unexpected unparsed data after reading expectation",
                ));
            }

            write_all(&mut stream, &expect_response.into_bytes()).await?;

            if !expectation_success {
                *cached_target = Some(CachedTarget {
                    action: path_action,
                    stream: target_stream,
                });
                return Ok(Outcome::Continue);
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
            .patch_headers(response_header_patch.as_deref());

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
                info!("[{}] {} {} [forward-ws]", LOG_PREFIX, verb, request_path);
                return Ok(Outcome::Tunnel(target_stream));
            }
            error!("Websocket upgrade failed: {}", response_data.first_line());
        }

        let response_connection_close = response_data.headers().connection_close();

        if verb != "HEAD" {
            forward_message(&mut target_stream, Some(&mut stream), response_data).await?;
        }

        info!("[{}] {} {} [forward]", LOG_PREFIX, verb, request_path);

        if response_connection_close {
            let _ = target_stream.try_shutdown().await;
            return Ok(Outcome::Close);
        }

        *cached_target = Some(CachedTarget {
            action: path_action,
            stream: target_stream,
        });

        Ok(Outcome::Continue)
    }
}
