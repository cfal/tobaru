use super::*;
use crate::config::{HttpPathAction, HttpTimeouts};
use crate::http::message::{BodyFrame, ReceiveBody};
use http::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::task::JoinHandle;

mod forwarding;
mod wire;

struct Task<T>(JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn checked(future: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(8), future)
        .await
        .expect("test deadline");
}

fn action(value: Value) -> TargetHttpActionData {
    let config: HttpPathAction = serde_json::from_value(value).unwrap();
    config.try_into().unwrap()
}

fn runtime(
    action: TargetHttpActionData,
    config: Http2Config,
    reload: Option<watch::Receiver<()>>,
) -> HttpTargetData {
    HttpTargetData {
        http_protocols: crate::config::HttpProtocols {
            http1: true,
            http2: true,
        },
        path_configs: radix_trie::Trie::new(),
        default_http_action: action,
        http_timeouts: HttpTimeouts::default(),
        http2: config,
        h2_admission: Admission::new(config, reload),
    }
}

async fn frontend(
    action: TargetHttpActionData,
) -> (
    h2::client::SendRequest<Bytes>,
    Task<()>,
    Task<std::io::Result<()>>,
) {
    configured_frontend(runtime(action, Http2Config::default(), None)).await
}

async fn configured_frontend(
    http: HttpTargetData,
) -> (
    h2::client::SendRequest<Bytes>,
    Task<()>,
    Task<std::io::Result<()>>,
) {
    let (client, proxy) = UnixStream::pair().unwrap();
    let target = Arc::new(TargetData {
        tcp_nodelay: true,
        tcp_keepalive: None,
        action_data: TargetActionData::Http(Box::new(http)),
    });
    let server = Task(tokio::spawn(handle(
        Box::new(proxy),
        "127.0.0.1:1".parse().unwrap(),
        target,
        None,
    )));
    let (send, connection) = h2::client::Builder::new()
        .enable_push(false)
        .initial_window_size(1024)
        .initial_connection_window_size(1024 * 1024)
        .handshake(client)
        .await
        .unwrap();
    let driver = Task(tokio::spawn(async move {
        let _ = connection.await;
    }));
    (send, driver, server)
}

async fn collect(body: h2::RecvStream) -> (Vec<u8>, HeaderMap) {
    let mut source = body::H2Body::new(body);
    let mut data = Vec::new();
    let mut trailers = HeaderMap::new();
    while let Some(frame) = source.next().await.unwrap() {
        match frame {
            BodyFrame::Data(bytes) => {
                source.release(bytes.len()).unwrap();
                data.extend_from_slice(&bytes);
            }
            BodyFrame::Trailers(fields) => trailers = fields,
        }
    }
    (data, trailers)
}

async fn head(io: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        data.push(io.read_u8().await.unwrap());
        assert!(data.len() < 65536);
    }
    data
}

async fn backend() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let mut addr = listener.local_addr().unwrap();
    addr.set_ip("127.0.0.1".parse().unwrap());
    (listener, addr)
}

async fn h2_backend<F, Fut>(handler: F) -> (std::net::SocketAddr, Arc<AtomicUsize>, Task<()>)
where
    F: Fn(Request<h2::RecvStream>, h2::server::SendResponse<Bytes>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (listener, addr) = backend().await;
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    let handler = Arc::new(handler);
    let task = Task(tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                connection = listener.accept() => {
                    let (io, _) = connection.unwrap();
                    counted.fetch_add(1, Ordering::SeqCst);
                    let handler = handler.clone();
                    connections.spawn(async move {
                        let mut connection = h2::server::handshake(io).await.unwrap();
                        let mut requests = JoinSet::new();
                        loop {
                            tokio::select! {
                                next = connection.accept() => match next {
                                    Some(Ok((request, response))) => { requests.spawn(handler(request, response)); }
                                    _ => break,
                                },
                                Some(result) = requests.join_next(), if !requests.is_empty() => result.unwrap(),
                            }
                        }
                        while let Some(result) = requests.join_next().await {
                            result.unwrap();
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => result.unwrap(),
            }
        }
    }));
    (addr, count, task)
}

#[tokio::test]
async fn local_get_head_expect_and_sibling_requests() {
    checked(async {
    let (mut client, _driver, _server) = frontend(action(json!({"type":"serve-message", "status_code":200, "content":"hello", "response_id_header_name":"x-id"}))).await;
    for method in ["GET", "HEAD", "GET"] {
        let request = Request::builder().method(method).uri("https://example.test/").body(()).unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key("x-id"));
        assert_eq!(collect(response.into_body()).await.0, if method == "HEAD" { b"".as_slice() } else { b"hello" });
    }
    let request = Request::builder().method("POST").uri("https://example.test/").header("expect", "100-continue").body(()).unwrap();
    let (response, _upload) = client.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), 417);
}).await
}

#[tokio::test]
async fn h2_to_h1_preserves_interim_cookies_binary_and_trailers() {
    checked(async {
    let (listener, addr) = backend().await;
    let backend = Task(tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        let _ = head(&mut io).await;
        io.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close, x-private\r\nx-private: hidden\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nx-opaque: \xff\r\n\r\n2\r\nOK\r\n0\r\nx-end: one\r\nx-end: two\r\n\r\n").await.unwrap();
    }));
    let (mut client, _driver, _server) = frontend(action(json!({"type":"forward", "location":addr.to_string()}))).await;
    let (mut response, _) = client.send_request(Request::builder().uri("https://example.test/").body(()).unwrap(), true).unwrap();
    let informational = std::future::poll_fn(|cx| response.poll_informational(cx)).await.unwrap().unwrap();
    assert_eq!(informational.status(), 103);
    let response = response.await.unwrap();
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    assert_eq!(response.headers()["x-opaque"].as_bytes(), b"\xff");
    assert!(!response.headers().contains_key("x-private"));
    let (body, trailers) = collect(response.into_body()).await;
    assert_eq!(body, b"OK");
    assert_eq!(trailers.get_all("x-end").iter().count(), 2);
    assert!(backend.0.is_finished());
}).await
}

#[tokio::test]
async fn fixed_length_upload_uses_trailer_capable_h1_framing() {
    checked(async {
        let (listener, addr) = backend().await;
        let (captured, capture) = tokio::sync::oneshot::channel();
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let header = head(&mut io).await;
            assert!(String::from_utf8_lossy(&header).contains("transfer-encoding: chunked"));
            assert!(!String::from_utf8_lossy(&header).contains("content-length"));
            let mut body = Vec::new();
            while !body.ends_with(b"x-proof: yes\r\n\r\n") {
                body.push(io.read_u8().await.unwrap());
            }
            captured.send(body).unwrap();
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }));
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        let (response, mut upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://example.test/")
                    .header("content-length", "5")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        upload
            .send_data(Bytes::from_static(b"hello"), false)
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-proof", HeaderValue::from_static("yes"));
        upload.send_trailers(trailers).unwrap();
        assert_eq!(response.await.unwrap().status(), 200);
        assert_eq!(
            capture.await.unwrap(),
            b"5\r\nhello\r\n0\r\nx-proof: yes\r\n\r\n"
        );
    })
    .await
}

#[tokio::test]
async fn early_rejection_does_not_wait_for_upload_end() {
    checked(async {
        let (listener, addr) = backend().await;
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let _ = head(&mut io).await;
            io.write_all(b"HTTP/1.1 413 Too Large\r\nContent-Length: 6\r\n\r\nDENIED")
                .await
                .unwrap();
        }));
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        let (response, mut upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://example.test/")
                    .header("content-length", "100")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        upload.send_data(Bytes::from_static(b"x"), false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 413);
        assert_eq!(collect(response.into_body()).await.0, b"DENIED");
    })
    .await
}

#[tokio::test]
async fn h2_to_h2_is_duplex_and_preserves_both_trailers() {
    checked(async {
        let (addr, count, _backend) = h2_backend(|mut request, mut response| async move {
            response
                .send_informational(Response::builder().status(100).body(()).unwrap())
                .unwrap();
            response
                .send_informational(Response::builder().status(103).body(()).unwrap())
                .unwrap();
            let mut send = response
                .send_response(Response::builder().status(200).body(()).unwrap(), false)
                .unwrap();
            while let Some(data) = request.body_mut().data().await {
                let data = data.unwrap();
                request
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len())
                    .unwrap();
                send.send_data(data, false).unwrap();
            }
            let trailers = request.body_mut().trailers().await.unwrap().unwrap();
            send.send_trailers(trailers).unwrap();
        })
        .await;
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"}),
        ))
        .await;
        let (mut response, mut upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://example.test/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        for status in [100, 103] {
            assert_eq!(
                std::future::poll_fn(|cx| response.poll_informational(cx))
                    .await
                    .unwrap()
                    .unwrap()
                    .status(),
                status
            );
        }
        let mut response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        upload
            .send_data(Bytes::from_static(b"first"), false)
            .unwrap();
        let data = response.body_mut().data().await.unwrap().unwrap();
        assert_eq!(data, b"first".as_slice());
        response
            .body_mut()
            .flow_control()
            .release_capacity(data.len())
            .unwrap();
        upload
            .send_data(Bytes::from_static(b"second"), false)
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-end", HeaderValue::from_static("yes"));
        upload.send_trailers(trailers).unwrap();
        let (body, trailers) = collect(response.into_body()).await;
        assert_eq!(body, b"second");
        assert_eq!(trailers["x-end"], "yes");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    })
    .await
}

#[tokio::test]
async fn h1_to_h2_streams_and_reuses_backend() {
    checked(async {
    let (addr, count, _backend) = h2_backend(|request, mut response| async move {
        assert_eq!(request.uri().authority().unwrap(), "example.test");
        let mut send = response.send_response(Response::builder().status(200).header("set-cookie", "a").header("set-cookie", "b").body(()).unwrap(), false).unwrap();
        send.send_data(Bytes::from_static(b"OK"), true).unwrap();
    }).await;
    let (mut client, server) = UnixStream::pair().unwrap();
    let _session = Task(tokio::spawn(async move {
        let http = runtime(action(json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"})), Http2Config::default(), None);
        crate::http::handle_http_stream(true, None, &http, Box::new(server), &"127.0.0.1:1".parse().unwrap(), None).await.unwrap();
    }));
    for close in [false, true] {
        client.write_all(format!("GET / HTTP/1.1\r\nHost: example.test\r\nConnection: {}\r\n\r\n", if close { "close" } else { "keep-alive" }).as_bytes()).await.unwrap();
        let header = head(&mut client).await;
        assert!(header.starts_with(b"HTTP/1.1 200"));
        assert_eq!(String::from_utf8_lossy(&header).matches("set-cookie:").count(), 2);
        let mut wire = [0;12]; client.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, b"2\r\nOK\r\n0\r\n\r\n");
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
}).await
}

#[tokio::test]
async fn reset_cancels_backend_and_keeps_sibling_alive() {
    checked(async {
        let (listener, addr) = backend().await;
        let (eof, got_eof) = tokio::sync::oneshot::channel();
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let _ = head(&mut io).await;
            let n = io.read(&mut [0; 1]).await.unwrap();
            eof.send(n).unwrap();
        }));
        let mut http = runtime(
            action(json!({"type":"serve-message", "status_code":200, "content":"alive"})),
            Http2Config::default(),
            None,
        );
        http.path_configs.insert(
            "/slow/".into(),
            vec![crate::tcp::TargetHttpPathData {
                required_request_headers: Default::default(),
                http_action: action(json!({"type":"forward", "location":addr.to_string()})),
            }],
        );
        let (mut client, _driver, _server) = configured_frontend(http).await;
        let (response, mut send) = client
            .send_request(
                Request::builder()
                    .uri("https://example.test/slow/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        send.send_reset(h2::Reason::CANCEL);
        drop(response);
        assert_eq!(got_eof.await.unwrap(), 0);
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("https://example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(
            collect(response.await.unwrap().into_body()).await.0,
            b"alive"
        );
    })
    .await
}

#[tokio::test]
async fn blocked_response_does_not_starve_sibling() {
    checked(async {
        let mut http = runtime(
            action(
                json!({"type":"serve-message", "status_code":200, "content":"x".repeat(131072)}),
            ),
            Http2Config::default(),
            None,
        );
        http.path_configs.insert(
            "/fast/".into(),
            vec![crate::tcp::TargetHttpPathData {
                required_request_headers: Default::default(),
                http_action: action(
                    json!({"type":"serve-message", "status_code":200, "content":"fast"}),
                ),
            }],
        );
        let (mut client, _driver, _server) = configured_frontend(http).await;
        let (slow, _unfinished_upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("http://example.test/slow/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let mut slow = slow.await.unwrap().into_body();
        let first = slow.data().await.unwrap().unwrap();
        assert_eq!(first.len(), 1024);
        assert!(tokio::time::timeout(Duration::from_millis(30), slow.data())
            .await
            .is_err());
        let (fast, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/fast/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(collect(fast.await.unwrap().into_body()).await.0, b"fast");
        slow.flow_control().release_capacity(first.len()).unwrap();
        assert_eq!(collect(slow).await.0.len() + first.len(), 131072);
    })
    .await;
}

#[tokio::test]
async fn reload_bounds_drain_and_joins_backend() {
    checked(async {
        let (listener, addr) = backend().await;
        let (accepted, accept) = tokio::sync::oneshot::channel();
        let (closed, close) = tokio::sync::oneshot::channel();
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            head(&mut io).await;
            accepted.send(()).unwrap();
            closed.send(io.read(&mut [0]).await.unwrap()).unwrap();
        }));
        let (generation, reload) = watch::channel(());
        let config = Http2Config {
            drain_timeout_secs: 1.try_into().unwrap(),
            ..Default::default()
        };
        let http = runtime(
            action(json!({"type":"forward", "location":addr.to_string()})),
            config,
            Some(reload),
        );
        let (mut client, _driver, mut server) = configured_frontend(http).await;
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        accept.await.unwrap();
        drop(generation);
        assert!(tokio::time::timeout(Duration::from_secs(3), &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
        assert!(response.await.is_err());
        assert_eq!(close.await.unwrap(), 0);
        assert!(client.ready().await.is_err());
    })
    .await;
}

#[tokio::test]
async fn early_h1_rejection_half_closes_upload_before_response_eof() {
    checked(async {
        let (listener, addr) = backend().await;
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            head(&mut io).await;
            io.write_all(b"HTTP/1.1 413 Too Large\r\nConnection: close\r\n\r\nfirst")
                .await
                .unwrap();
            let mut discarded = Vec::new();
            io.read_to_end(&mut discarded).await.unwrap();
            io.write_all(b"last").await.unwrap();
        }));
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string()}),
        ))
        .await;
        let (response, _upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 413);
        assert_eq!(collect(response.into_body()).await.0, b"firstlast");
    })
    .await;
}

#[tokio::test]
async fn request_validation_is_stream_local() {
    checked(async {
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"serve-message", "status_code":200, "content":"ok"}),
        ))
        .await;
        for host in ["different.test", "example.test:bad"] {
            let (response, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/")
                        .header("host", host)
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            assert_eq!(response.await.unwrap().status(), 400);
        }
        let (response, _) = client
            .send_request(
                Request::builder()
                    .method("CONNECT")
                    .uri("example.test:443")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(response.await.unwrap().status(), 501);
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(collect(response.await.unwrap().into_body()).await.0, b"ok");
    })
    .await;
}

#[tokio::test]
async fn backend_push_is_disabled_and_violations_fail_the_exchange() {
    checked(async {
        let (listener, addr) = backend().await;
        let (checked_settings, settings) = tokio::sync::oneshot::channel();
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let mut preface = [0; 24];
            io.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            io.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
            let mut disabled = false;
            loop {
                let mut frame = [0; 9];
                io.read_exact(&mut frame).await.unwrap();
                let size =
                    ((frame[0] as usize) << 16) | ((frame[1] as usize) << 8) | frame[2] as usize;
                let mut payload = vec![0; size];
                io.read_exact(&mut payload).await.unwrap();
                if frame[3] == 4 && frame[4] == 0 {
                    disabled = payload.as_chunks::<6>().0.contains(&[0, 2, 0, 0, 0, 0]);
                    io.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.unwrap();
                }
                if frame[3] == 1 {
                    break;
                }
            }
            checked_settings.send(disabled).unwrap();
            let mut push = vec![
                0, 0, 21, 5, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0x82, 0x86, 0x84, 0x41, 12,
            ];
            push.extend_from_slice(b"example.test");
            io.write_all(&push).await.unwrap();
            let mut remainder = Vec::new();
            let _ = io.read_to_end(&mut remainder).await;
        }));
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"}),
        ))
        .await;
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert!(settings.await.unwrap());
        assert_eq!(response.await.unwrap().status(), 502);
    })
    .await;
}

#[tokio::test]
async fn goaway_drains_accepted_streams_without_replay() {
    checked(async {
        let (listener, addr) = backend().await;
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let _backend = Task(tokio::spawn(async move {
            for _ in 0..2 {
                let (io, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(io).await.unwrap();
                let (_, mut response) = connection.accept().await.unwrap().unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let mut body = response
                    .send_response(Response::builder().status(200).body(()).unwrap(), false)
                    .unwrap();
                connection.graceful_shutdown();
                body.send_data(Bytes::from_static(b"accepted"), true)
                    .unwrap();
                while connection.accept().await.is_some() {}
            }
        }));
        let (mut client, _driver, _server) = frontend(action(
            json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"}),
        ))
        .await;
        let mut completed = 0;
        for _ in 0..3 {
            let (response, _) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let response = response.await.unwrap();
            if response.status() == 200 {
                assert_eq!(collect(response.into_body()).await.0, b"accepted");
                completed += 1;
            } else {
                assert_eq!(response.status(), 502);
            }
            if completed == 2 {
                break;
            }
        }
        assert_eq!(completed, 2);
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    })
    .await;
}

#[tokio::test]
async fn backend_admission_is_bounded_and_recovers_after_reset() {
    checked(async {
        let (listener, addr) = backend().await;
        let (accepted, accept) = tokio::sync::oneshot::channel();
        let _backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            head(&mut io).await;
            accepted.send(()).unwrap();
            let mut bytes = Vec::new();
            io.read_to_end(&mut bytes).await.unwrap();
            let (mut io, _) = listener.accept().await.unwrap();
            head(&mut io).await;
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }));
        let config = Http2Config {
            max_backend_connections: 1.try_into().unwrap(),
            ..Default::default()
        };
        let (mut client, _driver, _server) = configured_frontend(runtime(
            action(json!({"type":"forward", "location":addr.to_string()})),
            config,
            None,
        ))
        .await;
        let request = || {
            Request::builder()
                .uri("http://example.test/")
                .body(())
                .unwrap()
        };
        let (first, mut cancel) = client.send_request(request(), true).unwrap();
        accept.await.unwrap();
        let (overloaded, _) = client.send_request(request(), true).unwrap();
        assert_eq!(overloaded.await.unwrap().status(), 503);
        cancel.send_reset(h2::Reason::CANCEL);
        drop(first);
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let (response, _) = client.send_request(request(), true).unwrap();
            let response = response.await.unwrap();
            if response.status() == 200 {
                return;
            }
            assert_eq!(response.status(), 503);
        }
        panic!("backend permit was not released");
    })
    .await;
}

#[tokio::test]
async fn literal_close_terminates_the_frontend_connection() {
    checked(async {
        let (mut client, _driver, mut server) = frontend(action(json!("close"))).await;
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert!(response.await.is_err());
        assert!((&mut server.0).await.unwrap().is_ok());
        assert!(client.ready().await.is_err());
    })
    .await;
}

#[tokio::test]
async fn local_bodyless_statuses_and_config_validation() {
    checked(async {
        for status in [204, 205, 304] {
            let (mut client, _driver, _server) = frontend(action(json!({"type":"serve-message", "status_code":status, "content":"not on wire"}))).await;
            for method in ["GET", "HEAD"] {
                let (response, _) = client.send_request(Request::builder().method(method).uri("http://example.test/").body(()).unwrap(), true).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status().as_u16(), status);
                assert!(collect(response.into_body()).await.0.is_empty());
            }
        }
        for fields in [json!({"connection":"close"}), json!({"content-length":"100"})] {
            let http = runtime(action(json!({"type":"serve-message", "status_code":200, "content":"short", "response_headers":fields})), Http2Config::default(), None);
            assert!(validate_config(&http).is_err());
        }
    }).await;
}

#[tokio::test]
async fn retired_generation_does_not_wait_for_h2_preface() {
    let (generation, retired) = watch::channel(());
    let http = runtime(
        action(json!({"type":"serve-message", "status_code":200, "content":"ok"})),
        Http2Config::default(),
        Some(retired),
    );
    let target = Arc::new(TargetData {
        tcp_nodelay: true,
        tcp_keepalive: None,
        action_data: TargetActionData::Http(Box::new(http)),
    });
    let (_peer, io) = UnixStream::pair().unwrap();
    let mut server = Task(tokio::spawn(handle(
        Box::new(io),
        "127.0.0.1:1".parse().unwrap(),
        target,
        None,
    )));
    tokio::task::yield_now().await;
    drop(generation);
    assert!(tokio::time::timeout(Duration::from_secs(1), &mut server.0)
        .await
        .unwrap()
        .unwrap()
        .is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_h2_sections_do_not_poison_reuse_or_siblings() {
    checked(async {
        let (finish, finished) = watch::channel(false);
        let (addr, count, _backend) = h2_backend(move |request, mut response| {
            let mut finished = finished.clone();
            async move {
                if request.uri().path() == "/cancel" {
                    response
                        .send_informational(Response::builder().status(103).body(()).unwrap())
                        .unwrap();
                    let _ = std::future::poll_fn(|cx| response.poll_reset(cx)).await;
                } else {
                    response
                        .send_informational(Response::builder().status(103).body(()).unwrap())
                        .unwrap();
                    if !*finished.borrow() {
                        finished.changed().await.unwrap();
                    }
                    let mut send = response
                        .send_response(Response::builder().status(200).body(()).unwrap(), false)
                        .unwrap();
                    send.send_data(Bytes::from_static(b"sibling"), true)
                        .unwrap();
                }
            }
        })
        .await;
        let config = Http2Config {
            max_backend_connections: 2.try_into().unwrap(),
            ..Default::default()
        };
        let (mut client, _driver, _server) = configured_frontend(runtime(
            action(
                json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"}),
            ),
            config,
            None,
        ))
        .await;
        let (mut sibling, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/sibling")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(
            std::future::poll_fn(|cx| sibling.poll_informational(cx))
                .await
                .unwrap()
                .unwrap()
                .status(),
            103
        );
        for _ in 0..4 {
            let (mut response, mut cancel) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/cancel")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            assert_eq!(
                std::future::poll_fn(|cx| response.poll_informational(cx))
                    .await
                    .unwrap()
                    .unwrap()
                    .status(),
                103
            );
            cancel.send_reset(h2::Reason::CANCEL);
            drop(response);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        finish.send(true).unwrap();
        assert_eq!(
            collect(sibling.await.unwrap().into_body()).await.0,
            b"sibling"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    })
    .await;
}

#[tokio::test]
async fn cold_connect_waiters_share_an_absolute_setup_deadline() {
    checked(async {
        let (listener, addr) = backend().await;
        let _backend = Task(tokio::spawn(async move {
            let mut sockets = Vec::new();
            loop { sockets.push(listener.accept().await.unwrap().0); }
        }));
        let config = Http2Config { connect_timeout_secs: 1.try_into().unwrap(), ..Default::default() };
        let (mut client, _driver, _server) = configured_frontend(runtime(action(json!({"type":"forward", "upstream_protocol":"http2", "location":{"address":addr.to_string(), "client_tls":{"verify":false}}})), config, None)).await;
        let start = tokio::time::Instant::now();
        let mut responses = Vec::new();
        for _ in 0..8 {
            responses.push(client.send_request(Request::builder().uri("http://example.test/").body(()).unwrap(), true).unwrap().0);
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            for response in responses { assert_eq!(response.await.unwrap().status(), 502); }
        }).await.expect("slot waiters exceeded their connect deadline");
        assert!(start.elapsed() < Duration::from_secs(3));
    }).await;
}

#[tokio::test]
async fn h1_overload_response_advertises_close() {
    let mut context = Context::testing();
    context.backends = Arc::new(Semaphore::new(0));
    let action =
        action(json!({"type":"forward", "upstream_protocol":"http2", "location":"127.0.0.1:1"}));
    let mut output = crate::http::bridge::H1Response::new(Vec::new(), http::Method::GET, false);
    let mut body = crate::http::bridge::H1Body::new(
        &b""[..],
        crate::http::line_reader::LineReader::new(),
        crate::http::bridge::Framing::Empty,
        65536,
    );
    assert!(!exchange::forward(
        &context,
        exchange::Plan {
            action: &action,
            base_path: "/",
            request_id: "test"
        },
        Request::builder()
            .uri("http://example.test/")
            .body(())
            .unwrap(),
        &mut body,
        &mut output,
        false
    )
    .await
    .unwrap());
    let wire = String::from_utf8(output.body.io).unwrap();
    assert!(wire.starts_with("HTTP/1.1 503"));
    assert!(wire.contains("connection: close\r\n"));
}
