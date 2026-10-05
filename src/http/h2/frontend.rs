use super::exchange;
use crate::http::message::Respond;
use crate::http::{bridge, header_map::HeaderMap, message, Outcome, Request, Session};
use http::{HeaderName, HeaderValue};

impl Session<'_> {
    pub(in crate::http) async fn forward_h2(
        &mut self,
        request: Request<'_>,
    ) -> std::io::Result<Outcome> {
        self.close_target().await;
        if request.data.headers().websocket_upgrade() {
            crate::util::write_all(
                &mut self.stream,
                b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await?;
            return Ok(Outcome::Close);
        }
        let close = request.data.headers().connection_close();
        // http::Uri drops fragments; never change the target after routing.
        if request.path.contains('#') {
            return Err(message::invalid("Fragment in request target"));
        }
        let mut headers = http::HeaderMap::new();
        for (name, value) in request.data.headers().fields() {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).map_err(message::io_error)?,
                HeaderValue::from_bytes(value.as_bytes()).map_err(message::io_error)?,
            );
        }
        let framing = bridge::framing(&headers, false)?;
        let host = headers
            .get("host")
            .ok_or_else(|| message::invalid("H2 backend requires Host"))?
            .to_str()
            .map_err(message::io_error)?;
        let uri = http::Uri::builder()
            .scheme(if self.tls { "https" } else { "http" })
            .authority(message::authority(host)?)
            .path_and_query(request.path.as_str())
            .build()
            .map_err(message::io_error)?;
        let mut head = http::Request::builder()
            .method(request.verb.as_str())
            .uri(uri)
            .body(())
            .map_err(message::io_error)?;
        message::strip_hop_headers(&mut headers, true)?;
        *head.headers_mut() = headers;
        message::normalize_request(
            &mut head,
            self.h2.config.max_header_list_size.get() as usize,
        )?;
        let method = head.method().clone();
        let (read, write) = tokio::io::split(&mut self.stream);
        let mut source = bridge::H1Body::new(
            read,
            request.data.into_reader(),
            framing,
            self.h2.config.max_header_list_size.get() as usize,
        );
        let mut response = bridge::H1Response::new(write, method, close);
        let result = exchange::forward(
            &self.h2,
            exchange::Plan {
                action: request.action,
                base_path: request.base_path,
                request_id: &request.id,
            },
            head,
            &mut source,
            &mut response,
            framing != bridge::Framing::Empty,
        )
        .await;
        let result = match result {
            Ok(complete) => complete,
            Err(error) => {
                if !response.final_sent() {
                    response.early_final();
                    let _ = message::progress(
                        self.h2.config.body_progress_timeout_secs.get(),
                        response.head(
                            http::Response::builder().status(502).body(()).unwrap(),
                            true,
                        ),
                    )
                    .await;
                }
                return Err(error);
            }
        };
        self.reader = Some(source.reader);
        Ok(if close || !result || !response.reusable() {
            Outcome::Close
        } else {
            Outcome::Continue
        })
    }
}
