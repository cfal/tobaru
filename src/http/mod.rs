mod body;
mod chunk_transfer;
mod header_map;
mod header_tuple;
mod http_parser;
mod line_reader;
mod local;
mod proxy;
mod routing;
mod string_util;

#[cfg(test)]
mod idle_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod test_io;
#[cfg(test)]
mod timeout_tests;

use log::info;
use radix_trie::Trie;
use rand::RngExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::async_stream::AsyncStream;
use crate::config::{HttpTimeouts, TcpKeepaliveConfig};
use crate::copy_bidirectional::copy_bidirectional;
use crate::tcp::{HttpTargetData, TargetHttpActionData, TargetHttpPathData};
use crate::tokio_util::with_timeout;
use header_map::HeaderMap;
use routing::find_matching_action;

struct CachedTarget<'a> {
    action: &'a TargetHttpActionData,
    stream: Box<dyn AsyncStream>,
    reader: line_reader::LineReader,
}

struct Session<'a> {
    stream: Box<dyn AsyncStream>,
    reader: Option<line_reader::LineReader>,
    cached_target: Option<CachedTarget<'a>>,
    addr: &'a std::net::SocketAddr,
    tcp_nodelay: bool,
    tcp_keepalive: Option<TcpKeepaliveConfig>,
    timeouts: HttpTimeouts,
}

enum Outcome {
    Continue,
    Close,
    Tunnel(Box<dyn AsyncStream>, line_reader::LineReader),
}

struct Request<'a> {
    data: http_parser::ParsedHttpData,
    verb: String,
    path: String,
    id: String,
    base_path: &'a str,
    action: &'a TargetHttpActionData,
}

impl<'a> Request<'a> {
    fn new(
        data: http_parser::ParsedHttpData,
        id: String,
        path_configs: &'a Trie<String, Vec<TargetHttpPathData>>,
        default_action: &'a TargetHttpActionData,
    ) -> std::io::Result<Self> {
        if data.headers().header_values("host").count() > 1 {
            return Err(std::io::Error::other(
                "Multiple Host fields are not allowed",
            ));
        }
        let first_line = data.first_line().strip_suffix(" HTTP/1.1").ok_or_else(|| {
            std::io::Error::other(format!("Not a http/1.1 request: {}", data.first_line()))
        })?;
        let (verb, request_path) = first_line.split_once(' ').ok_or_else(|| {
            std::io::Error::other(format!(
                "Invalid http request directive: {}",
                data.first_line()
            ))
        })?;
        if !request_path.starts_with('/') {
            return Err(std::io::Error::other(format!(
                "Invalid http request path: {}",
                data.first_line()
            )));
        }

        let verb = verb.to_ascii_uppercase();
        let request_path = request_path.to_owned();

        let (base_path, path_action) =
            find_matching_action(path_configs, default_action, &request_path, &data)?;

        Ok(Self {
            data,
            verb,
            path: request_path,
            id,
            base_path,
            action: path_action,
        })
    }
}

impl<'a> Session<'a> {
    async fn read_request(
        &mut self,
        keepalive: bool,
    ) -> std::io::Result<http_parser::ParsedHttpData> {
        let mut reader = self
            .reader
            .take()
            .expect("continued session must retain its reader");
        let request = async {
            if keepalive && reader.unparsed_data().is_empty() {
                let read = with_timeout(
                    self.timeouts.keepalive_idle_timeout_secs,
                    "HTTP keepalive idle",
                    reader.read_more(&mut self.stream),
                )
                .await?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF while reading",
                    ));
                }
            }
            with_timeout(
                self.timeouts.request_header_timeout_secs,
                "HTTP request headers",
                http_parser::ParsedHttpData::parse(&mut self.stream, reader),
            )
            .await
        };
        tokio::pin!(request);
        if let Some(target) = &mut self.cached_target {
            let mut byte = [0];
            tokio::select! {
                biased;
                _ = target.stream.read(&mut byte) => self.cached_target = None,
                data = &mut request => return data,
            }
        }
        // Preserve partial frontend parsing when an idle backend is retired.
        request.await
    }

    async fn close_target(&mut self) {
        if let Some(mut target) = self.cached_target.take() {
            let _ = target.stream.try_shutdown().await;
        }
    }

    async fn dispatch(&mut self, request: Request<'a>) -> std::io::Result<Outcome> {
        match request.action {
            TargetHttpActionData::CloseConnection => {
                info!("[http] {} {} [close]", request.verb, request.path);
                Ok(Outcome::Close)
            }
            TargetHttpActionData::ServeMessage { .. } => self.serve_message(request).await,
            TargetHttpActionData::ServeDirectory { .. } => self.serve_directory(request).await,
            TargetHttpActionData::Forward { .. } => self.forward(request).await,
        }
    }
}

pub async fn handle_http_stream(
    tcp_nodelay: bool,
    tcp_keepalive: Option<TcpKeepaliveConfig>,
    http: &HttpTargetData,
    stream: Box<dyn AsyncStream>,
    addr: &std::net::SocketAddr,
    initial_data: Option<Vec<u8>>,
) -> std::io::Result<()> {
    let mut session = Session {
        stream,
        reader: Some(initial_data.map_or_else(
            line_reader::LineReader::new,
            line_reader::LineReader::new_with_data,
        )),
        cached_target: None,
        addr,
        tcp_nodelay,
        tcp_keepalive,
        timeouts: http.http_timeouts,
    };
    let stream_id = format!("{:x}", rand::rng().random::<u64>());
    let mut iteration = 0usize;

    loop {
        iteration = iteration.wrapping_add(1);
        if iteration > 1 {
            session.stream.flush().await?;
        }
        let data = session.read_request(iteration > 1).await?;
        let request = Request::new(
            data,
            format!("{}#{}", stream_id, iteration),
            &http.path_configs,
            &http.default_http_action,
        )?;
        match session.dispatch(request).await? {
            Outcome::Continue => {}
            Outcome::Close => break,
            Outcome::Tunnel(mut target, target_reader) => {
                let reader = session
                    .reader
                    .take()
                    .expect("upgrade must retain its reader");
                tokio::try_join!(
                    crate::util::write_all(&mut session.stream, target_reader.unparsed_data()),
                    crate::util::write_all(&mut target, reader.unparsed_data()),
                )?;
                return copy_bidirectional(
                    &mut session.stream,
                    &mut target,
                    true,
                    !reader.unparsed_data().is_empty(),
                )
                .await
                .map(|_| ());
            }
        }
    }

    session.stream.flush().await?;
    let _ = session.stream.try_shutdown().await;
    session.close_target().await;
    Ok(())
}
