use super::{
    body::{H2Body, H2Send},
    deadline::HeaderDeadline,
    Clients,
};
use crate::config::{Http2Config, HttpProtocol, HttpTimeouts, TcpKeepaliveConfig};
use crate::http::{
    bridge,
    line_reader::LineReader,
    message::{self, invalid, io_error, progress, ReceiveBody, Respond},
    string_util,
    upload::Upload,
};
use crate::tcp::{setup_http_target_stream, TargetHttpActionData};
use http::{Method, Request, Response};
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::Poll;
use tokio::io::AsyncWriteExt;

pub(crate) struct Context {
    pub addr: std::net::SocketAddr,
    pub nodelay: bool,
    pub keepalive: Option<TcpKeepaliveConfig>,
    pub config: Http2Config,
    pub timeouts: HttpTimeouts,
    pub clients: Clients,
    pub backends: Arc<tokio::sync::Semaphore>,
    pub physical_backends: Arc<tokio::sync::Semaphore>,
}

impl Context {
    pub fn new(
        addr: std::net::SocketAddr,
        nodelay: bool,
        keepalive: Option<TcpKeepaliveConfig>,
        http: &crate::tcp::HttpTargetData,
    ) -> Self {
        Self {
            addr,
            nodelay,
            keepalive,
            config: http.http2,
            timeouts: http.http_timeouts,
            clients: Clients::default(),
            backends: http.h2_admission.backends.clone(),
            physical_backends: http.h2_admission.physical_backends.clone(),
        }
    }
    #[cfg(test)]
    pub fn testing() -> Self {
        Self {
            addr: "127.0.0.1:1".parse().unwrap(),
            nodelay: true,
            keepalive: None,
            config: Http2Config::default(),
            timeouts: HttpTimeouts::default(),
            clients: Clients::default(),
            backends: Arc::new(tokio::sync::Semaphore::new(256)),
            physical_backends: Arc::new(tokio::sync::Semaphore::new(256)),
        }
    }
}

pub(super) struct Plan<'a> {
    pub action: &'a TargetHttpActionData,
    pub base_path: &'a str,
    pub request_id: &'a str,
}

impl Plan<'_> {
    fn prepare(&self, request: &mut Request<()>, limit: usize) -> io::Result<()> {
        let TargetHttpActionData::Forward {
            replacement_path,
            request_header_patch,
            request_id_header_name,
            ..
        } = self.action
        else {
            unreachable!()
        };
        let path = request
            .uri()
            .path_and_query()
            .ok_or_else(|| invalid("Missing path"))?
            .as_str();
        let path = replacement_path.as_ref().map_or_else(
            || path.to_string(),
            |replacement| string_util::update_base_path(path, self.base_path, replacement),
        );
        message::patched(
            request.headers_mut(),
            request_header_patch.as_deref(),
            request_id_header_name
                .as_deref()
                .map(|name| (name, self.request_id)),
            true,
            limit,
        )?;
        message::update_request_uri(request, &path)?;
        message::normalize_request(request, limit)
    }

    fn response(&self, response: &mut Response<()>, limit: usize) -> io::Result<()> {
        let TargetHttpActionData::Forward {
            response_header_patch,
            response_id_header_name,
            replacement_path,
            ..
        } = self.action
        else {
            unreachable!()
        };
        message::patched(
            response.headers_mut(),
            response_header_patch.as_deref(),
            response_id_header_name
                .as_deref()
                .map(|name| (name, self.request_id)),
            false,
            limit,
        )?;
        if let Some(prefix) = replacement_path {
            if let Some(value) = response.headers().get_all("location").iter().next_back() {
                if let Ok(value) = value.to_str() {
                    if value.starts_with(prefix) {
                        let replacement =
                            string_util::update_base_path(value, prefix, self.base_path);
                        message::set(response.headers_mut(), "location", &replacement)?;
                    }
                }
            }
        }
        message::validate_response(response, limit)
    }
}

pub(super) async fn forward(
    context: &Context,
    plan: Plan<'_>,
    mut request: Request<()>,
    body: &mut (impl ReceiveBody + ?Sized),
    output: &mut (impl Respond + ?Sized),
    has_body: bool,
) -> io::Result<bool> {
    let activity = message::Activity::new(context.config.body_progress_timeout_secs.get());
    let _exchange = match context.backends.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            output.early_final();
            activity
                .wait(output.head(Response::builder().status(503).body(()).unwrap(), true))
                .await?;
            return Ok(false);
        }
    };
    let config = context.config;
    let limit = config.max_header_list_size.get() as usize;
    plan.prepare(&mut request, limit)?;
    let expected = message::content_length(request.headers())?;
    if !has_body && expected.is_some_and(|n| n != 0) {
        return Err(invalid("Missing declared request body"));
    }
    if let Some(length) = expected {
        message::set(request.headers_mut(), "content-length", &length.to_string())?;
    }
    let method = request.method().clone();
    let TargetHttpActionData::Forward {
        upstream_protocol,
        location_data,
        next_address_index,
        ..
    } = plan.action
    else {
        unreachable!()
    };
    let upload_state = Upload::new(message::expect_continue(request.headers())?);
    body.watch_upload(upload_state.clone());
    let upload_policy = message::BodyPolicy {
        activity: &activity,
        upstream_seconds: context.timeouts.upstream_body_progress_timeout_secs,
        upload: Some(&upload_state),
    };
    let response_policy = message::BodyPolicy {
        upload: None,
        ..upload_policy
    };
    let deadline = || {
        HeaderDeadline::new(
            context
                .timeouts
                .response_header_timeout_secs
                .map(|n| n.get()),
            has_body,
        )
    };
    let seconds = config.body_progress_timeout_secs.get();
    if *upstream_protocol == HttpProtocol::Http2 {
        let open = context
            .clients
            .open(plan.action, request, !has_body, context)
            .await?;
        let mut send = H2Send::new(
            open.send,
            !has_body,
            context.timeouts.upstream_body_progress_timeout_secs,
        );
        let deadline = deadline()?;
        let upload = async {
            if has_body {
                tokio::select! {
                    result = message::copy_body(body, &mut send, expected, &upload_policy, limit) => result?,
                    _ = upload_state.stopped() => return Ok(false),
                }
            }
            deadline.uploaded();
            Ok(true)
        };
        let response = response_h2(
            open.response,
            &plan,
            &method,
            output,
            &deadline,
            &response_policy,
            &upload_state,
            config,
        );
        let result = concurrent(upload, response).await;
        drop(open._client);
        result
    } else {
        let _connection = context
            .physical_backends
            .clone()
            .try_acquire_owned()
            .map_err(io_error)?;
        let index = next_address_index.fetch_add(1, Ordering::Relaxed) % location_data.len();
        let transport = progress(
            config.connect_timeout_secs.get(),
            setup_http_target_stream(
                &context.addr,
                &location_data[index],
                context.nodelay,
                context.keepalive,
            ),
        )
        .await?;
        if transport
            .negotiated_alpn
            .as_deref()
            .is_some_and(|alpn| alpn != b"http/1.1")
        {
            return Err(invalid("H1 backend negotiated another protocol"));
        }
        let (mut read, mut write) = tokio::io::split(transport.io);
        progress(
            config.connect_timeout_secs.get(),
            bridge::write_request(&mut write, request, has_body),
        )
        .await?;
        let mut send = bridge::H1Send::new(
            crate::http::body_io::UpstreamIo::new(
                write,
                context.timeouts.upstream_body_progress_timeout_secs,
            ),
            has_body,
        );
        let deadline = deadline()?;
        let final_received = AtomicBool::new(false);
        let upload = async {
            if !has_body {
                return Ok(true);
            }
            tokio::select! {
                result = message::copy_body(body, &mut send, expected, &upload_policy, limit) => {
                    if let Err(error) = result {
                        // An early response may need upload EOF before its body can finish.
                        progress(seconds, send.io.shutdown()).await?;
                        if error.kind() != io::ErrorKind::TimedOut && final_received.load(Ordering::Acquire) {
                            return Ok(false);
                        }
                        return Err(error);
                    }
                    deadline.uploaded();
                    Ok(true)
                },
                _ = upload_state.stopped() => {
                    progress(seconds, send.io.shutdown()).await?;
                    Ok(false)
                }
            }
        };
        let response = async {
            let mut reader = LineReader::new();
            let mut response = deadline
                .wait(async {
                    let mut informational = 0;
                    loop {
                        let mut response =
                            bridge::read_response(&mut read, &mut reader, limit).await?;
                        if !response.status().is_informational() {
                            return Ok(response);
                        }
                        informational += 1;
                        if informational > message::MAX_INFORMATIONAL_RESPONSES {
                            return Err(invalid("Too many informational responses"));
                        }
                        bridge::framing(response.headers(), true)?;
                        message::strip_hop_headers(response.headers_mut(), false)?;
                        message::validate_response(&mut response, limit)?;
                        let status = response.status();
                        activity.wait(output.head(response, false)).await?;
                        if status == http::StatusCode::CONTINUE {
                            upload_state.started();
                        }
                    }
                })
                .await?;
            final_received.store(true, Ordering::Release);
            if !deadline.upload_complete() {
                output.early_final();
                upload_state.stop_if_pending();
            }
            if response.status().is_client_error() || response.status().is_server_error() {
                upload_state.stop();
            }
            let empty = message::bodyless(&method, response.status());
            let framing = if empty {
                bridge::Framing::Empty
            } else {
                bridge::framing(response.headers(), true)?
            };
            let expected = if empty {
                Some(0)
            } else {
                message::content_length(response.headers())?
            };
            message::strip_hop_headers(response.headers_mut(), false)?;
            plan.response(&mut response, limit)?;
            activity
                .wait(output.head(response, framing == bridge::Framing::Empty))
                .await?;
            if framing != bridge::Framing::Empty {
                let read = crate::http::body_io::UpstreamIo::new(
                    read,
                    context.timeouts.upstream_body_progress_timeout_secs,
                );
                let mut source = bridge::H1Body::new(read, reader, framing, limit);
                let policy = message::BodyPolicy {
                    upstream_seconds: None,
                    ..response_policy
                };
                message::copy_body(&mut source, output, expected, &policy, limit).await?;
            }
            Ok(())
        };
        concurrent(upload, response).await
    }
}

async fn concurrent(
    upload: impl Future<Output = io::Result<bool>>,
    response: impl Future<Output = io::Result<()>>,
) -> io::Result<bool> {
    tokio::pin!(upload, response);
    tokio::select! {
        biased;
        result = &mut response => { result?; Ok(false) },
        result = &mut upload => {
            let complete = result?;
            response.await?;
            Ok(complete)
        }
    }
}

enum Head {
    Informational(Response<()>),
    Final(Response<h2::RecvStream>),
}

#[allow(clippy::too_many_arguments)]
async fn response_h2(
    mut response: h2::client::ResponseFuture,
    plan: &Plan<'_>,
    method: &Method,
    output: &mut (impl Respond + ?Sized),
    deadline: &HeaderDeadline,
    policy: &message::BodyPolicy<'_>,
    upload_state: &Upload,
    config: Http2Config,
) -> io::Result<()> {
    let limit = config.max_header_list_size.get() as usize;
    let response = deadline
        .wait(async {
            let mut informational = 0;
            loop {
                let event = poll_fn(|cx| {
                    match response.poll_informational(cx) {
                        Poll::Ready(Some(result)) => {
                            return Poll::Ready(result.map(Head::Informational))
                        }
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(None) => {}
                    }
                    Pin::new(&mut response)
                        .poll(cx)
                        .map(|result| result.map(Head::Final))
                })
                .await
                .map_err(io_error)?;
                match event {
                    Head::Informational(mut head) => {
                        informational += 1;
                        if informational > message::MAX_INFORMATIONAL_RESPONSES
                            || head.status().as_u16() == 101
                        {
                            return Err(invalid("Invalid informational response sequence"));
                        }
                        message::validate_response(&mut head, limit)?;
                        let status = head.status();
                        policy.activity.wait(output.head(head, false)).await?;
                        if status == http::StatusCode::CONTINUE {
                            upload_state.started();
                        }
                    }
                    Head::Final(head) => return Ok(head),
                }
            }
        })
        .await?;
    if !deadline.upload_complete() {
        output.early_final();
        upload_state.stop_if_pending();
    }
    let (parts, body) = response.into_parts();
    let mut response = Response::from_parts(parts, ());
    if response.status().as_u16() >= 600 || response.status().is_informational() {
        return Err(invalid("Invalid final response"));
    }
    let empty = message::bodyless(method, response.status());
    let expected = if empty {
        Some(0)
    } else {
        message::content_length(response.headers())?
    };
    plan.response(&mut response, limit)?;
    let end = body.is_end_stream();
    if end && !empty && expected.is_some_and(|n| n != 0) {
        return Err(invalid("Missing declared response body"));
    }
    policy
        .activity
        .wait(output.head(response, empty || end))
        .await?;
    if !empty && !end {
        message::copy_body(&mut H2Body::new(body), output, expected, policy, limit).await?;
    }
    Ok(())
}
