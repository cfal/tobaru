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
mod session_tests;

use log::info;
use radix_trie::Trie;
use rand::RngExt;
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;
use crate::config::TcpKeepaliveConfig;
use crate::copy_bidirectional::copy_bidirectional;
use crate::tcp::{TargetHttpActionData, TargetHttpPathData};
use routing::find_matching_action;

struct CachedTarget {
    base_path: String,
    stream: Box<dyn AsyncStream>,
}

struct Session<'a> {
    stream: Box<dyn AsyncStream>,
    cached_target: Option<CachedTarget>,
    addr: &'a std::net::SocketAddr,
    tcp_nodelay: bool,
    tcp_keepalive: Option<TcpKeepaliveConfig>,
}

enum Outcome {
    Continue,
    Close,
    Tunnel(Box<dyn AsyncStream>),
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
        let mut first_line = data.first_line().to_string();

        if !first_line.ends_with(" HTTP/1.1") {
            return Err(std::io::Error::other(format!(
                "Not a http/1.1 request: {}",
                data.first_line()
            )));
        }

        first_line.truncate(first_line.len() - 9);

        let space_index = match first_line.find(' ') {
            Some(i) => i,
            None => {
                return Err(std::io::Error::other(format!(
                    "Invalid http request directive: {}",
                    data.first_line()
                )));
            }
        };

        let request_path = first_line.split_off(space_index + 1);
        if !request_path.starts_with('/') {
            return Err(std::io::Error::other(format!(
                "Invalid http request path: {}",
                data.first_line()
            )));
        }

        let mut verb = first_line;
        verb.truncate(verb.len() - 1);
        verb.make_ascii_uppercase();

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

impl Session<'_> {
    async fn close_target(&mut self) {
        if let Some(mut target) = self.cached_target.take() {
            let _ = target.stream.try_shutdown().await;
        }
    }

    async fn dispatch(&mut self, request: Request<'_>) -> std::io::Result<Outcome> {
        match request.action {
            TargetHttpActionData::CloseConnection => {
                info!("[http] {} {} [close]", request.verb, request.path);
                Ok(Outcome::Close)
            }
            TargetHttpActionData::ServeMessage { .. }
            | TargetHttpActionData::ServeDirectory { .. } => self.serve_local(request).await,
            TargetHttpActionData::Forward { .. } => self.forward(request).await,
        }
    }
}

pub async fn handle_http_stream(
    tcp_nodelay: bool,
    tcp_keepalive: Option<TcpKeepaliveConfig>,
    path_configs: &Trie<String, Vec<TargetHttpPathData>>,
    default_action: &TargetHttpActionData,
    stream: Box<dyn AsyncStream>,
    addr: &std::net::SocketAddr,
    mut initial_data: Option<Vec<u8>>,
) -> std::io::Result<()> {
    let mut session = Session {
        stream,
        cached_target: None,
        addr,
        tcp_nodelay,
        tcp_keepalive,
    };
    let stream_id = format!("{:x}", rand::rng().random::<u64>());
    let mut iteration = 0usize;

    loop {
        iteration = iteration.wrapping_add(1);
        if iteration > 1 {
            session.stream.flush().await?;
        }
        let initial = if iteration == 1 {
            initial_data.take()
        } else {
            None
        };
        let data = http_parser::ParsedHttpData::parse(&mut session.stream, initial).await?;
        let request = Request::new(
            data,
            format!("{}#{}", stream_id, iteration),
            path_configs,
            default_action,
        )?;
        match session.dispatch(request).await? {
            Outcome::Continue => {}
            Outcome::Close => break,
            Outcome::Tunnel(mut target) => {
                return copy_bidirectional(&mut session.stream, &mut target, true, false)
                    .await
                    .map(|_| ())
            }
        }
    }

    session.stream.flush().await?;
    let _ = session.stream.try_shutdown().await;
    session.close_target().await;
    Ok(())
}
