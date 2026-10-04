use std::io;

use log::info;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::body::{forward_body, request_framing, response_framing, write_head, Framing};
use super::header_map::HeaderMap;
use super::http_parser::ParsedHttpData;
use super::line_reader::LineReader;
use super::{string_util, CachedTarget, Outcome, Request, Session};
use crate::async_stream::AsyncStream;
use crate::tcp::{setup_target_stream, TargetHttpActionData};

impl<'a> Session<'a> {
    async fn target_for(
        &mut self,
        action: &'a TargetHttpActionData,
    ) -> io::Result<CachedTarget<'a>> {
        if self
            .cached_target
            .as_ref()
            .is_some_and(|target| std::ptr::eq(target.action, action))
        {
            return Ok(self.cached_target.take().unwrap());
        }
        self.close_target().await;
        let TargetHttpActionData::Forward {
            location_data,
            next_address_index,
            ..
        } = action
        else {
            unreachable!("forward action required")
        };
        let index = if location_data.len() > 1 {
            next_address_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % location_data.len()
        } else {
            0
        };
        let stream = setup_target_stream(
            self.addr,
            &location_data[index],
            self.tcp_nodelay,
            self.tcp_keepalive,
        )
        .await?;
        Ok(CachedTarget {
            action,
            stream,
            reader: LineReader::new(),
        })
    }

    pub(super) async fn forward(&mut self, mut request: Request<'a>) -> io::Result<Outcome> {
        let TargetHttpActionData::Forward {
            replacement_path,
            request_header_patch,
            response_header_patch,
            request_id_header_name,
            response_id_header_name,
            ..
        } = request.action
        else {
            unreachable!("forward action required")
        };

        let request_body = request_framing(request.data.headers())?;
        let client_close = request.data.headers().connection_close();
        if let Some(path) = replacement_path {
            let path = string_util::update_base_path(&request.path, request.base_path, path);
            request
                .data
                .set_first_line(format!("{} {} HTTP/1.1", request.verb, path));
        }
        request
            .data
            .headers_mut()
            .patch_headers(request_header_patch.as_deref());
        if let Some(name) = request_id_header_name {
            request
                .data
                .headers_mut()
                .insert(name.clone(), request.id.clone());
        }
        if request_framing(request.data.headers())? != request_body {
            return Err(io::Error::other(
                "Request header patch changes body framing",
            ));
        }
        request.data.headers().expect_100()?;
        let client_close = client_close || request.data.headers().connection_close();
        let upgrade = request.data.headers().websocket_upgrade();
        let offered: Vec<String> = request
            .data
            .headers()
            .header_values("upgrade")
            .flat_map(|value| value.split(','))
            .map(|value| value.trim().to_owned())
            .collect();

        let mut target = self.target_for(request.action).await?;
        write_head(&mut target.stream, &request.data).await?;
        target.stream.flush().await?;
        let (reader, mut response) = exchange(
            &mut self.stream,
            &mut target.stream,
            request.data.into_reader(),
            target.reader,
            request_body,
        )
        .await?;
        let upload_complete = reader.is_some();
        self.reader = reader;
        let status = response.response_status()?;
        let response_body = response_framing(response.headers(), &request.verb, status)?;
        let upstream_close = response.headers().connection_close()
            || (response.first_line().starts_with("HTTP/1.0 ")
                && !response
                    .headers()
                    .contains_token("connection", "keep-alive"));

        response
            .headers_mut()
            .patch_headers(response_header_patch.as_deref());
        if let Some(name) = response_id_header_name {
            response.headers_mut().insert(name.clone(), request.id);
        }
        response
            .headers_mut()
            .update_path_headers(request.base_path, replacement_path);
        if response_framing(response.headers(), &request.verb, status)? != response_body {
            return Err(io::Error::other(
                "Response header patch changes body framing",
            ));
        }

        if status == 101 {
            let selected: Vec<_> = response
                .headers()
                .header_values("upgrade")
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .collect();
            if !upgrade
                || request.verb == "HEAD"
                || !upload_complete
                || !response.headers().websocket_upgrade()
                || selected.is_empty()
                || selected.iter().any(|value| {
                    value.is_empty()
                        || !offered
                            .iter()
                            .any(|offer| offer.eq_ignore_ascii_case(value))
                })
            {
                return Err(io::Error::other("Invalid upstream protocol upgrade"));
            }
            write_head(&mut self.stream, &response).await?;
            info!("[http] {} {} [forward-ws]", request.verb, request.path);
            return Ok(Outcome::Tunnel(target.stream, response.into_reader()));
        }

        let close = client_close
            || upstream_close
            || response.headers().connection_close()
            || !upload_complete
            || response_body == Framing::UntilEof;
        if close {
            response
                .headers_mut()
                .insert("connection".into(), "close".into());
        }
        write_head(&mut self.stream, &response).await?;
        target.reader = forward_body(
            &mut target.stream,
            Some(&mut self.stream),
            response.into_reader(),
            response_body,
        )
        .await?;
        info!("[http] {} {} [forward]", request.verb, request.path);
        if close {
            let _ = target.stream.try_shutdown().await;
            Ok(Outcome::Close)
        } else {
            self.cached_target = Some(target);
            Ok(Outcome::Continue)
        }
    }
}

async fn exchange(
    client: &mut Box<dyn AsyncStream>,
    target: &mut Box<dyn AsyncStream>,
    request_reader: LineReader,
    response_reader: LineReader,
    framing: Framing,
) -> io::Result<(Option<LineReader>, ParsedHttpData)> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let upload = async {
        let reader = forward_body(
            &mut client_read,
            Some(&mut target_write),
            request_reader,
            framing,
        )
        .await?;
        target_write.flush().await?;
        Ok::<_, io::Error>(reader)
    };
    let response = read_response(&mut target_read, &mut client_write, response_reader);
    tokio::pin!(upload, response);
    tokio::select! {
        biased;
        reader = &mut upload => Ok((Some(reader?), response.await?)),
        response = &mut response => {
            // Cancellation may interrupt a partial upload. Neither connection can be reused.
            Ok((None, response?))
        }
    }
}

async fn read_response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    target: &mut R,
    client: &mut W,
    mut reader: LineReader,
) -> io::Result<ParsedHttpData> {
    loop {
        let response = ParsedHttpData::parse(target, reader).await?;
        let status = response.response_status()?;
        if status >= 200 || status == 101 {
            return Ok(response);
        }
        write_head(client, &response).await?;
        client.flush().await?;
        reader = response.into_reader();
    }
}
