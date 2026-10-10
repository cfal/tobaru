mod body;
mod client;
mod deadline;
mod exchange;
mod frontend;
mod io;
#[cfg(test)]
mod tests;

pub(crate) use client::Clients;
pub(crate) use exchange::Context;

use super::{
    local,
    message::{self, invalid, io_error, progress, Respond, SendBody},
    routing,
};
use crate::async_stream::AsyncStream;
use crate::config::Http2Config;
use crate::tcp::{HttpTargetData, TargetActionData, TargetData, TargetHttpActionData};
use body::{H2Body, H2Response};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

pub(crate) struct Admission {
    connections: Arc<Semaphore>,
    backends: Arc<Semaphore>,
    physical_backends: Arc<Semaphore>,
    reload: Option<watch::Receiver<()>>,
}

impl Admission {
    pub fn new(config: Http2Config, reload: Option<watch::Receiver<()>>) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(config.max_connections.get())),
            backends: Arc::new(Semaphore::new(config.max_backend_connections.get())),
            physical_backends: Arc::new(Semaphore::new(config.max_backend_connections.get())),
            reload,
        }
    }
}

async fn retired(generation: &mut Option<watch::Receiver<()>>) {
    match generation {
        Some(receiver) => {
            let _ = receiver.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

pub(crate) fn validate_config(http: &HttpTargetData) -> std::io::Result<()> {
    use radix_trie::TrieCommon;
    for action in std::iter::once(&http.default_http_action).chain(
        http.path_configs
            .iter()
            .flat_map(|(_, paths)| paths.iter().map(|path| &path.http_action)),
    ) {
        let fields = match action {
            TargetHttpActionData::ServeMessage {
                status_code,
                content,
                response_headers,
                ..
            } => {
                if *status_code < 200 {
                    return Err(invalid("H2 local responses require final status >= 200"));
                }
                let mut response = local_head(*status_code, response_headers, None, "")?;
                message::validate_response(
                    &mut response,
                    http.http2.max_header_list_size.get() as usize,
                )?;
                if message::content_length(response.headers())?
                    .is_some_and(|n| n != content.len() as u64)
                {
                    return Err(invalid("Local Content-Length differs from content"));
                }
                Some(response_headers)
            }
            TargetHttpActionData::ServeDirectory {
                response_headers, ..
            } => Some(response_headers),
            _ => None,
        };
        if let Some(fields) = fields {
            let mut headers = http::HeaderMap::new();
            for (name, value) in fields {
                message::set(&mut headers, name, value)?;
            }
            message::validate_multiplexed(
                &headers,
                false,
                http.http2.max_header_list_size.get() as usize,
            )?;
        }
    }
    Ok(())
}

pub(crate) async fn handle(
    stream: Box<dyn AsyncStream>,
    addr: std::net::SocketAddr,
    target: Arc<TargetData>,
    initial: Option<Vec<u8>>,
) -> std::io::Result<()> {
    let TargetActionData::Http(http) = &target.action_data else {
        unreachable!()
    };
    let _connection = http
        .h2_admission
        .connections
        .clone()
        .try_acquire_owned()
        .map_err(io_error)?;
    let config = http.http2;
    let context = Arc::new(Context::new(
        addr,
        target.tcp_nodelay,
        target.tcp_keepalive,
        http,
    ));
    let mut reload = http.h2_admission.reload.clone();
    let header_seconds = http
        .http_timeouts
        .request_header_timeout_secs
        .unwrap_or(config.header_timeout_secs)
        .get();
    let io = io::TimedIo::new(
        stream,
        initial.unwrap_or_default(),
        true,
        Duration::from_secs(header_seconds),
        config.max_header_list_size.get() as usize * 4,
        config.max_concurrent_streams.get() as usize,
    );
    let mut watchdog = io.watchdog();
    let handshake = progress(config.connect_timeout_secs.get(), async {
        h2::server::Builder::new()
            .max_concurrent_streams(config.max_concurrent_streams.get())
            .max_header_list_size(config.max_header_list_size.get())
            .initial_window_size(65535)
            .initial_connection_window_size(1024 * 1024)
            .max_send_buffer_size(16384)
            .max_concurrent_reset_streams(64)
            .max_pending_accept_reset_streams(64)
            .reset_stream_duration(Duration::from_secs(1))
            .handshake(io)
            .await
            .map_err(io_error)
    });
    let mut connection = tokio::select! {
        result = handshake => result?,
        error = &mut watchdog => return Err(error),
        _ = retired(&mut reload) => return Ok(()),
    };
    let mut tasks = JoinSet::new();
    let (close_tx, mut close_rx) = tokio::sync::mpsc::channel(1);
    let idle_seconds = http
        .http_timeouts
        .keepalive_idle_timeout_secs
        .map_or(60, |n| n.get());
    let mut idle = tokio::time::Instant::now() + Duration::from_secs(idle_seconds);
    let mut draining = false;
    let mut deadline = tokio::time::Instant::now();
    let result = loop {
        tokio::select! {
            biased;
            error = &mut watchdog => break Err(error),
            _ = retired(&mut reload), if !draining => {
                draining = true;
                deadline = tokio::time::Instant::now() + Duration::from_secs(config.drain_timeout_secs.get());
                connection.graceful_shutdown();
            }
            Some(()) = close_rx.recv() => { connection.abrupt_shutdown(h2::Reason::NO_ERROR); break Ok(()); }
            _ = tokio::time::sleep_until(deadline), if draining => { connection.abrupt_shutdown(h2::Reason::CANCEL); break Ok(()); }
            _ = tokio::time::sleep_until(idle), if tasks.is_empty() && !draining => {
                draining = true;
                deadline = tokio::time::Instant::now() + Duration::from_secs(config.drain_timeout_secs.get());
                connection.graceful_shutdown();
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result { log::warn!("[h2] stream task failed: {error}"); }
                idle = tokio::time::Instant::now() + Duration::from_secs(idle_seconds);
            }
            next = connection.accept() => match next {
                Some(Ok((request, mut response))) => {
                    if draining || tasks.len() >= config.max_concurrent_streams.get() as usize {
                        response.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    let context = context.clone();
                    let target = target.clone();
                    let close = close_tx.clone();
                    tasks.spawn(async move { serve_stream(request, response, context, target, close).await; });
                }
                Some(Err(error)) => break Err(io_error(error)),
                None => break Ok(()),
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    context.clients.shutdown().await;
    result
}

async fn serve_stream(
    request: Request<h2::RecvStream>,
    response: h2::server::SendResponse<Bytes>,
    context: Arc<Context>,
    target: Arc<TargetData>,
    close: tokio::sync::mpsc::Sender<()>,
) {
    let stream_id = request.body().stream_id();
    let (parts, body) = request.into_parts();
    let mut request = Request::from_parts(parts, ());
    let mut response = H2Response::new(response);
    let monitor = response.clone();
    let limit = context.config.max_header_list_size.get() as usize;
    if request.method() == http::Method::CONNECT {
        let _ = response
            .head(Response::builder().status(501).body(()).unwrap(), true)
            .await;
        return;
    }
    if let Err(error) = message::normalize_request(&mut request, limit) {
        log::debug!("[h2] invalid request: {error}");
        let _ = response
            .head(Response::builder().status(400).body(()).unwrap(), true)
            .await;
        return;
    }
    let has_body = !body.is_end_stream();
    let mut body = H2Body::new(body);
    let operation = async {
        let TargetActionData::Http(http) = &target.action_data else {
            unreachable!()
        };
        let path = request.uri().path_and_query().unwrap().as_str().to_owned();
        let (base, action) = routing::find_matching_headers(
            &http.path_configs,
            &http.default_http_action,
            &path,
            |name| {
                routing::single_required_header(
                    name,
                    request
                        .headers()
                        .get_all(name)
                        .iter()
                        .map(|value| value.to_str().map_err(io_error)),
                )
            },
        )?;
        let request_id = format!("{:x}#{}", rand::random::<u64>(), stream_id.as_u32());
        match action {
            TargetHttpActionData::CloseConnection => {
                let _ = close.try_send(());
            }
            TargetHttpActionData::Forward { .. } => {
                exchange::forward(
                    &context,
                    exchange::Plan {
                        action,
                        base_path: base,
                        request_id: &request_id,
                    },
                    request,
                    &mut body,
                    &mut response,
                    has_body,
                )
                .await?;
            }
            _ => {
                local_response(
                    action,
                    &request,
                    base,
                    &request_id,
                    &mut response,
                    context.config,
                )
                .await?
            }
        }
        Ok::<_, std::io::Error>(())
    };
    let result = tokio::select! { biased; result = monitor.cancelled() => result, result = operation => result };
    if let Err(error) = result {
        log::debug!("[h2] stream {}: {}", stream_id.as_u32(), error);
        if !response.final_sent() {
            let _ = response
                .head(Response::builder().status(502).body(()).unwrap(), true)
                .await;
        } else {
            response.reset(h2::Reason::INTERNAL_ERROR);
        }
    }
}

async fn local_response(
    action: &TargetHttpActionData,
    request: &Request<()>,
    base: &str,
    id: &str,
    output: &mut H2Response,
    config: Http2Config,
) -> std::io::Result<()> {
    if message::expect_continue(request.headers())? {
        return output
            .head(Response::builder().status(417).body(()).unwrap(), true)
            .await;
    }
    let (mut response, file, content) = match action {
        TargetHttpActionData::ServeMessage {
            status_code,
            content,
            response_headers,
            response_id_header_name,
            ..
        } => (
            local_head(
                *status_code,
                response_headers,
                response_id_header_name.as_deref(),
                id,
            )?,
            None,
            content.as_bytes(),
        ),
        TargetHttpActionData::ServeDirectory {
            path,
            response_headers,
            response_id_header_name,
        } => {
            if request.method() != http::Method::GET && request.method() != http::Method::HEAD {
                return output
                    .head(
                        local_head(
                            501,
                            &Default::default(),
                            response_id_header_name.as_deref(),
                            id,
                        )?,
                        true,
                    )
                    .await;
            }
            let requested = local::static_file_path(
                path,
                request.uri().path_and_query().unwrap().as_str(),
                base,
            )?;
            let selected = local::resolve_file(path, &requested).await;
            let file = match selected {
                Ok(path) if tokio::fs::metadata(&path).await?.is_file() => path,
                Ok(_) => {
                    return output
                        .head(
                            local_head(
                                404,
                                &Default::default(),
                                response_id_header_name.as_deref(),
                                id,
                            )?,
                            true,
                        )
                        .await
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return output
                        .head(
                            local_head(
                                404,
                                &Default::default(),
                                response_id_header_name.as_deref(),
                                id,
                            )?,
                            true,
                        )
                        .await
                }
                Err(error) => return Err(error),
            };
            let mut response = local_head(
                200,
                response_headers,
                response_id_header_name.as_deref(),
                id,
            )?;
            if !response.headers().contains_key("content-type") {
                message::set(
                    response.headers_mut(),
                    "content-type",
                    mime_guess::from_path(&file)
                        .first_or_octet_stream()
                        .essence_str(),
                )?;
            }
            (response, Some(tokio::fs::File::open(file).await?), &b""[..])
        }
        _ => unreachable!(),
    };
    if response.status().is_informational() {
        return Err(invalid("Local response must be final"));
    }
    let length = match &file {
        Some(file) => file.metadata().await?.len(),
        None => content.len() as u64,
    };
    if message::content_length(response.headers())?.is_some_and(|value| value != length) {
        return Err(invalid("Local Content-Length differs from content"));
    }
    let empty = message::bodyless(request.method(), response.status());
    if !empty
        || request.method() == http::Method::HEAD
            && !matches!(
                response.status(),
                StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT
            )
    {
        message::set(
            response.headers_mut(),
            "content-length",
            &length.to_string(),
        )?;
    }
    message::validate_response(&mut response, config.max_header_list_size.get() as usize)?;
    output.head(response, empty || length == 0).await?;
    if empty || length == 0 {
        return Ok(());
    }
    let seconds = config.body_progress_timeout_secs.get();
    if let Some(mut file) = file {
        let mut buffer = vec![0; message::CHUNK_SIZE];
        let mut remaining = length;
        loop {
            let n = progress(seconds, file.read(&mut buffer)).await?;
            if n == 0 {
                if remaining != 0 {
                    return Err(invalid("Local file shrank during response"));
                }
                break;
            }
            remaining = remaining
                .checked_sub(n as u64)
                .ok_or_else(|| invalid("Local file grew during response"))?;
            progress(seconds, output.data(Bytes::copy_from_slice(&buffer[..n]))).await?;
        }
    } else {
        for chunk in content.chunks(message::CHUNK_SIZE) {
            progress(seconds, output.data(Bytes::copy_from_slice(chunk))).await?;
        }
    }
    output.finish().await
}

fn local_head(
    status: u16,
    fields: &std::collections::HashMap<String, String>,
    id_name: Option<&str>,
    id: &str,
) -> std::io::Result<Response<()>> {
    let mut response = Response::builder()
        .status(StatusCode::from_u16(status).map_err(io_error)?)
        .body(())
        .map_err(io_error)?;
    for (name, value) in fields {
        message::set(response.headers_mut(), name, value)?;
    }
    if let Some(name) = id_name {
        message::set(response.headers_mut(), name, id)?;
    }
    Ok(response)
}
