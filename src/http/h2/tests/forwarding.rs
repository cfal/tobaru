use super::*;
use crate::tcp::TargetHttpPathData;
use std::future::poll_fn;
use tokio::sync::mpsc;

fn forwarding(addr: std::net::SocketAddr) -> HttpTargetData {
    runtime(
        action(json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"})),
        Http2Config::default(),
        None,
    )
}

fn h1_frontend(http: HttpTargetData) -> (UnixStream, Task<std::io::Result<()>>) {
    let (client, server) = UnixStream::pair().unwrap();
    let task = Task(tokio::spawn(async move {
        crate::http::handle_http_stream(
            true,
            None,
            &http,
            Box::new(server),
            &"127.0.0.1:1".parse().unwrap(),
            None,
        )
        .await
    }));
    (client, task)
}

fn values(head: &[u8], name: &str) -> Vec<String> {
    std::str::from_utf8(head)
        .unwrap()
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

// Test-side wire decoder: do not validate the H1 encoder with its own body parser.
async fn chunked(io: &mut UnixStream) -> (Vec<u8>, Vec<u8>) {
    let mut body = Vec::new();
    loop {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            line.push(io.read_u8().await.unwrap());
        }
        let length =
            usize::from_str_radix(std::str::from_utf8(&line[..line.len() - 2]).unwrap(), 16)
                .unwrap();
        if length == 0 {
            let mut trailers = Vec::new();
            loop {
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") {
                    line.push(io.read_u8().await.unwrap());
                }
                if line == b"\r\n" {
                    return (body, trailers);
                }
                trailers.extend(line);
            }
        }
        let start = body.len();
        body.resize(start + length, 0);
        io.read_exact(&mut body[start..]).await.unwrap();
        let mut crlf = [0; 2];
        io.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
    }
}

async fn eof(io: &mut UnixStream) {
    assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn h1_to_h2_rejects_fragments_before_lossy_uri_conversion() {
    checked(async {
        for path in ["/admin", "/admin#x", "/admin?query#fragment"] {
            let (listener, addr) = backend().await;
            let mut http = forwarding(addr);
            http.path_configs.insert(
                "/admin/".into(),
                vec![TargetHttpPathData {
                    required_request_headers: Default::default(),
                    http_action: action(json!({"type":"close"})),
                }],
            );
            let (mut client, mut session) = h1_frontend(http);
            client
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n").as_bytes())
                .await
                .unwrap();
            // A connection attempt itself is a failure, even before H2 setup completes.
            tokio::select! {
                biased;
                _ = listener.accept() => panic!("blocked path reached backend: {path}"),
                result = &mut session.0 => { let _ = result.unwrap(); }
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
            eof(&mut client).await;
        }
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (addr, _, _backend) = h2_backend(move |request, mut response| {
            let tx = tx.clone();
            async move {
                tx.send(request.uri().path_and_query().unwrap().as_str().to_owned())
                    .unwrap();
                response.send_response(Response::new(()), true).unwrap();
            }
        })
        .await;
        let (mut client, mut session) = h1_frontend(forwarding(addr));
        client
            .write_all(
                b"GET /admin%23x HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200"));
        assert_eq!(rx.recv().await.unwrap(), "/admin%23x");
        eof(&mut client).await;
        (&mut session.0).await.unwrap().unwrap();
    })
    .await;
}

#[tokio::test]
async fn h1_to_h2_uploads_preserve_pipelining_and_trailers() {
    checked(async {
        for is_chunked in [false, true] {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let (addr, count, _backend) = h2_backend(move |request, mut response| {
                let tx = tx.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let (data, trailers) = collect(body).await;
                    tx.send((parts, data, trailers)).unwrap();
                    let mut send = response.send_response(Response::new(()), false).unwrap();
                    send.send_data(Bytes::from_static(b"OK"), true).unwrap();
                }
            }).await;
            let (mut client, mut session) = h1_frontend(forwarding(addr));
            let payload: Vec<_> = (0..131072).map(|n| (n % 256) as u8).collect();
            let framing = if is_chunked { "Transfer-Encoding: chunked\r\n".into() }
                else { format!("Content-Length: {}\r\n", payload.len()) };
            let mut wire = format!("POST /upload HTTP/1.1\r\nHost: example.test\r\n{framing}Connection: keep-alive, x-secret\r\nx-secret: hidden\r\nTE: gzip, trailers\r\n\r\n").into_bytes();
            if is_chunked {
                for part in payload.chunks(997) {
                    wire.extend_from_slice(format!("{:x};extension=yes\r\n", part.len()).as_bytes());
                    wire.extend_from_slice(part);
                    wire.extend_from_slice(b"\r\n");
                }
                wire.extend_from_slice(b"0\r\nx-end: one\r\nx-end: two\r\n\r\n");
            } else { wire.extend_from_slice(&payload); }
            wire.extend_from_slice(b"GET /next HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n");
            client.write_all(&wire).await.unwrap();
            for close in ["keep-alive", "close"] {
                let header = head(&mut client).await;
                assert!(header.starts_with(b"HTTP/1.1 200"));
                assert_eq!(values(&header, "connection"), [close]);
                assert_eq!(values(&header, "transfer-encoding"), ["chunked"]);
                assert!(values(&header, "content-length").is_empty());
                assert_eq!(chunked(&mut client).await.0, b"OK");
            }
            eof(&mut client).await;
            (&mut session.0).await.unwrap().unwrap();
            let (parts, data, trailers) = rx.recv().await.unwrap();
            assert_eq!(parts.method, "POST");
            assert_eq!(parts.uri.path(), "/upload");
            for forbidden in ["connection", "x-secret", "transfer-encoding"] {
                assert!(!parts.headers.contains_key(forbidden), "{forbidden}");
            }
            assert_eq!(parts.headers["te"], "trailers");
            assert_eq!(parts.headers.get("content-length").is_none(), is_chunked);
            assert_eq!(data, payload);
            assert_eq!(trailers.get_all("x-end").iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>(),
                if is_chunked { vec!["one", "two"] } else { vec![] });
            let (parts, data, trailers) = rx.recv().await.unwrap();
            assert_eq!(parts.uri.path(), "/next");
            assert!(data.is_empty() && trailers.is_empty());
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }
    }).await;
}

#[tokio::test]
async fn h1_to_h2_rejects_ambiguous_heads_without_backend_io() {
    checked(async {
        for fields in [
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: 1\r\nContent-Length: 2\r\n",
            "Content-Length: 2\r\nContent-Length: 1\r\n",
            "Content-Length: 1, 2\r\n", "Content-Length: -1\r\n",
            "Content-Length: 18446744073709551616\r\n",
            "Transfer-Encoding: gzip, chunked\r\n", "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Host: other.test\r\n",
        ] {
            let (listener, addr) = backend().await;
            let (mut client, mut session) = h1_frontend(forwarding(addr));
            client.write_all(format!("POST / HTTP/1.1\r\nHost: example.test\r\n{fields}\r\nGET /smuggled HTTP/1.1\r\nHost: example.test\r\n\r\n").as_bytes()).await.unwrap();
            assert!((&mut session.0).await.unwrap().is_err(), "{fields:?}");
            assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept()).await.is_err(), "{fields:?}");
            eof(&mut client).await;
        }
    }).await;
}

#[tokio::test]
async fn h1_to_h2_invalid_upload_resets_without_parsing_surplus() {
    checked(async {
        for (framing, malformed) in [
            ("Content-Length: 5", "abc"),
            ("Transfer-Encoding: chunked", "z\r\nabc\r\n"),
            ("Transfer-Encoding: chunked", "3\r\nabcX\r\n0\r\n\r\n"),
            (
                "Transfer-Encoding: chunked",
                "3\r\nabc\r\n0\r\nContent-Length: 3\r\n\r\n",
            ),
            (
                "Transfer-Encoding: chunked",
                "3\r\nabc\r\n0\r\nHost: other.test\r\n\r\n",
            ),
        ] {
            let (started, mut start) = mpsc::unbounded_channel();
            let (done, mut result) = mpsc::unbounded_channel();
            let (addr, _, _backend) = h2_backend(move |mut request, response| {
                let started = started.clone();
                let done = done.clone();
                async move {
                    started.send(()).unwrap();
                    loop {
                        match request.body_mut().data().await {
                            Some(Ok(bytes)) => request
                                .body_mut()
                                .flow_control()
                                .release_capacity(bytes.len())
                                .unwrap(),
                            Some(Err(error)) => {
                                done.send(error.reason()).unwrap();
                                break;
                            }
                            None => panic!("malformed upload completed successfully"),
                        }
                    }
                    drop(response);
                }
            })
            .await;
            let (mut client, mut session) = h1_frontend(forwarding(addr));
            client
                .write_all(
                    format!("POST / HTTP/1.1\r\nHost: example.test\r\n{framing}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            start.recv().await.unwrap();
            client.write_all(malformed.as_bytes()).await.unwrap();
            if framing.starts_with("Transfer") {
                client
                    .write_all(b"GET /smuggled HTTP/1.1\r\nHost: example.test\r\n\r\n")
                    .await
                    .unwrap();
            }
            client.shutdown().await.unwrap();
            let header = head(&mut client).await;
            assert!(header.starts_with(b"HTTP/1.1 502"));
            assert_eq!(values(&header, "connection"), ["close"]);
            eof(&mut client).await;
            assert!((&mut session.0).await.unwrap().is_err());
            let reason = result.recv().await.unwrap();
            assert!(reason.is_none() || reason == Some(h2::Reason::CANCEL));
            assert!(start.try_recv().is_err());
        }
    })
    .await;
}

#[tokio::test]
async fn h2_upstream_expect_rewrites_and_patches_only_final_heads() {
    checked(async {
        for h2_ingress in [false, true] {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let (addr, _, _backend) = h2_backend(move |request, mut response| {
                let tx = tx.clone();
                async move {
                    response.send_informational(Response::builder().status(100).body(()).unwrap()).unwrap();
                    response.send_informational(Response::builder().status(103).header("location", "/internal/hint").body(()).unwrap()).unwrap();
                    let (parts, body) = request.into_parts();
                    let (data, trailers) = collect(body).await;
                    tx.send((parts, data, trailers)).unwrap();
                    let mut send = response.send_response(Response::builder().status(200).header("location", "/internal/next").body(()).unwrap(), false).unwrap();
                    send.send_data(Bytes::from_static(b"OK"), false).unwrap();
                    let mut trailers = HeaderMap::new();
                    trailers.insert("location", HeaderValue::from_static("/internal/trailer"));
                    send.send_trailers(trailers).unwrap();
                }
            }).await;
            let mut http = runtime(action(json!({"type":"close"})), Http2Config::default(), None);
            http.path_configs.insert("/public/".into(), vec![TargetHttpPathData {
                required_request_headers: Default::default(),
                http_action: action(json!({
                    "type":"forward", "location":addr.to_string(), "upstream_protocol":"http2",
                    "replacement_path":"/internal/", "request_id_header_name":"x-request-id", "response_id_header_name":"x-response-id",
                    "request_header_patch":{"remove_headers":["x-remove"], "overwrite_headers":{"x-existing":"overwritten"}, "default_headers":{"x-default":"added"}},
                    "response_header_patch":{"default_headers":{"x-response":"yes"}}
                })),
            }]);
            let response_id;
            if h2_ingress {
                let (mut client, _driver, _server) = configured_frontend(http).await;
                let (mut response, mut upload) = client.send_request(Request::builder().method("POST").uri("http://example.test/public/file?x=1")
                    .header("expect", "100-continue").header("x-existing", "original").header("x-remove", "gone").body(()).unwrap(), false).unwrap();
                for status in [100, 103] {
                    let info = poll_fn(|cx| response.poll_informational(cx)).await.unwrap().unwrap();
                    assert_eq!(info.status(), status);
                    assert!(!info.headers().contains_key("x-response-id"));
                    assert!(!info.headers().contains_key("x-response"));
                    if status == 103 { assert_eq!(info.headers()["location"], "/internal/hint"); }
                }
                upload.send_data(Bytes::from_static(b"hello"), false).unwrap();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-upload", HeaderValue::from_static("yes"));
                upload.send_trailers(trailers).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.headers()["location"], "/public/next");
                assert_eq!(response.headers()["x-response"], "yes");
                response_id = response.headers()["x-response-id"].to_str().unwrap().to_owned();
                let (data, trailers) = collect(response.into_body()).await;
                assert_eq!(data, b"OK");
                assert_eq!(trailers.len(), 1);
                assert_eq!(trailers["location"], "/internal/trailer");
            } else {
                let (mut client, mut session) = h1_frontend(http);
                client.write_all(b"POST /public/file?x=1 HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nX-Existing: original\r\nX-Remove: gone\r\nConnection: close\r\n\r\n").await.unwrap();
                for status in [100, 103] {
                    let info = head(&mut client).await;
                    assert!(info.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
                    assert!(values(&info, "x-response-id").is_empty());
                    assert!(values(&info, "x-response").is_empty());
                    if status == 103 { assert_eq!(values(&info, "location"), ["/internal/hint"]); }
                }
                client.write_all(b"5\r\nhello\r\n0\r\nx-upload: yes\r\n\r\n").await.unwrap();
                let response = head(&mut client).await;
                assert!(response.starts_with(b"HTTP/1.1 200"));
                assert_eq!(values(&response, "location"), ["/public/next"]);
                assert_eq!(values(&response, "x-response"), ["yes"]);
                response_id = values(&response, "x-response-id")[0].clone();
                let (data, trailers) = chunked(&mut client).await;
                assert_eq!(data, b"OK");
                assert_eq!(trailers, b"location: /internal/trailer\r\n");
                eof(&mut client).await;
                (&mut session.0).await.unwrap().unwrap();
            }
            let (parts, data, trailers) = rx.recv().await.unwrap();
            assert_eq!(parts.uri.path_and_query().unwrap(), "/internal/file?x=1");
            assert_eq!(parts.headers["x-existing"], "overwritten");
            assert_eq!(parts.headers["x-default"], "added");
            assert!(!parts.headers.contains_key("x-remove"));
            assert!(!response_id.is_empty());
            assert_eq!(parts.headers["x-request-id"], response_id);
            assert_eq!(data, b"hello");
            assert_eq!(trailers["x-upload"], "yes");
        }
    }).await;
}

#[tokio::test]
async fn forwarded_bodyless_responses_preserve_all_four_paths() {
    checked(async {
        for h2_upstream in [false, true] {
            for h2_ingress in [false, true] {
                let cases = [("HEAD", 200, Some("123")), ("GET", 204, None), ("GET", 205, Some("0")), ("GET", 304, Some("123"))];
                let (addr, _backend) = if h2_upstream {
                    let (addr, _, task) = h2_backend(|request, mut response| async move {
                        let status: u16 = request.uri().path()[1..].parse().unwrap();
                        let mut head = Response::builder().status(status);
                        if status != 204 { head = head.header("content-length", if status == 205 { "0" } else { "123" }); }
                        response.send_response(head.body(()).unwrap(), true).unwrap();
                    }).await;
                    (addr, task)
                } else {
                    let (listener, addr) = backend().await;
                    let task = Task(tokio::spawn(async move {
                        // H2 ingress deliberately uses exclusive H1 leases; H1 ingress reuses.
                        let mut io = None;
                        for (_, status, length) in cases {
                            if io.is_none() { io = Some(listener.accept().await.unwrap().0); }
                            let stream = io.as_mut().unwrap();
                            let request = head(stream).await;
                            assert!(std::str::from_utf8(&request).unwrap().contains(&format!(" /{status} HTTP/1.1")));
                            let length = length.map(|n| format!("Content-Length: {n}\r\n")).unwrap_or_default();
                            stream.write_all(format!("HTTP/1.1 {status} Test\r\n{length}\r\n").as_bytes()).await.unwrap();
                            if h2_ingress { io = None; }
                        }
                    }));
                    (addr, task)
                };
                let http = runtime(action(json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":if h2_upstream {"http2"} else {"http1"}})), Http2Config::default(), None);
                if h2_ingress {
                    let (mut client, _driver, _server) = configured_frontend(http).await;
                    for (method, status, length) in cases {
                        let (response, _) = client.send_request(Request::builder().method(method).uri(format!("http://example.test/{status}")).body(()).unwrap(), true).unwrap();
                        let response = response.await.unwrap();
                        assert_eq!(response.status(), status);
                        assert_eq!(response.headers().get("content-length").map(|v| v.to_str().unwrap()), length);
                        let (data, trailers) = collect(response.into_body()).await;
                        assert!(data.is_empty() && trailers.is_empty());
                    }
                } else {
                    let (mut client, mut session) = h1_frontend(http);
                    // Send together so any accidental body bytes corrupt the next status line.
                    for (method, status, _) in cases {
                        client.write_all(format!("{method} /{status} HTTP/1.1\r\nHost: example.test\r\nConnection: {}\r\n\r\n", if status == 304 {"close"} else {"keep-alive"}).as_bytes()).await.unwrap();
                    }
                    for (_, status, length) in cases {
                        let response = head(&mut client).await;
                        assert!(response.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
                        assert_eq!(values(&response, "content-length"), length.into_iter().collect::<Vec<_>>());
                        assert!(values(&response, "transfer-encoding").is_empty());
                    }
                    eof(&mut client).await;
                    (&mut session.0).await.unwrap().unwrap();
                }
            }
        }
    }).await;
}

#[tokio::test]
async fn h2_upstream_early_final_completes_before_upload_cancellation() {
    checked(async {
        for h2_ingress in [false, true] {
            for status in [200, 413] {
                let finish = Arc::new(tokio::sync::Notify::new());
                let complete = finish.clone();
                let (reset_tx, mut resets) = mpsc::unbounded_channel();
                let requests = Arc::new(AtomicUsize::new(0));
                let seen = requests.clone();
                let (addr, count, _backend) = h2_backend(move |request, mut response| {
                    let complete = complete.clone(); let reset_tx = reset_tx.clone(); let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        if request.uri().path() == "/sibling" {
                            let mut send = response.send_response(Response::new(()), false).unwrap();
                            send.send_data(Bytes::from_static(b"sibling"), true).unwrap();
                            return;
                        }
                        let mut send = response.send_response(Response::builder().status(status).body(()).unwrap(), false).unwrap();
                        complete.notified().await;
                        send.send_data(Bytes::from_static(b"complete response"), true).unwrap();
                        reset_tx.send(poll_fn(|cx| send.poll_reset(cx)).await).unwrap();
                        drop(request);
                    }
                }).await;
                if h2_ingress {
                    let (mut client, _driver, _server) = configured_frontend(forwarding(addr)).await;
                    let (response, _upload) = client.send_request(Request::builder().method("POST").uri("http://example.test/early")
                        .header("expect", "100-continue").header("content-length", "100000").body(()).unwrap(), false).unwrap();
                    let response = response.await.unwrap();
                    assert_eq!(response.status(), status);
                    assert!(!response.body().is_end_stream());
                    assert!(resets.try_recv().is_err());
                    complete_sibling(&mut client).await;
                    finish.notify_one();
                    assert_eq!(collect(response.into_body()).await.0, b"complete response");
                    assert_eq!(resets.recv().await.unwrap().unwrap(), h2::Reason::CANCEL);
                    complete_sibling(&mut client).await;
                    assert_eq!(count.load(Ordering::SeqCst), 1);
                    assert_eq!(requests.load(Ordering::SeqCst), 3);
                } else {
                    let (mut client, mut session) = h1_frontend(forwarding(addr));
                    client.write_all(b"POST /early HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 100000\r\n\r\n").await.unwrap();
                    let response = head(&mut client).await;
                    assert!(response.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
                    assert_eq!(values(&response, "connection"), ["close"]);
                    assert!(resets.try_recv().is_err());
                    client.write_all(b"GET /smuggled HTTP/1.1\r\nHost: example.test\r\n\r\n").await.unwrap();
                    finish.notify_one();
                    assert_eq!(chunked(&mut client).await.0, b"complete response");
                    eof(&mut client).await;
                    (&mut session.0).await.unwrap().unwrap();
                    // Closing the H1 owner may retire its entire backend driver before RST flushes.
                    let reset = resets.recv().await.unwrap();
                    assert!(reset.is_err() || reset.unwrap() == h2::Reason::CANCEL);
                    assert_eq!(requests.load(Ordering::SeqCst), 1);
                }
            }
        }
    }).await;
}

async fn complete_sibling(client: &mut h2::client::SendRequest<Bytes>) {
    let (response, _) = client
        .send_request(
            Request::builder()
                .uri("http://example.test/sibling")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(collect(response.into_body()).await.0, b"sibling");
}

#[tokio::test]
async fn h2_upstream_body_failure_never_completes_downstream_framing() {
    checked(async {
        for h2_ingress in [false, true] {
            for truncated in [false, true] {
                let fail = Arc::new(tokio::sync::Notify::new());
                let failed = fail.clone();
                let requests = Arc::new(AtomicUsize::new(0));
                let seen = requests.clone();
                let (addr, count, _backend) = h2_backend(move |request, mut response| {
                    let failed = failed.clone(); let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        if request.uri().path() == "/sibling" {
                            let mut send = response.send_response(Response::new(()), false).unwrap();
                            send.send_data(Bytes::from_static(b"sibling"), true).unwrap();
                            return;
                        }
                        let mut send = response.send_response(Response::builder().header("content-length", "5").body(()).unwrap(), false).unwrap();
                        send.send_data(Bytes::from_static(b"abc"), false).unwrap();
                        // Wait until the frontend has actually consumed the head and DATA.
                        failed.notified().await;
                        if truncated { send.send_data(Bytes::new(), true).unwrap(); }
                        else { send.send_reset(h2::Reason::CANCEL); }
                    }
                }).await;
                if h2_ingress {
                    let (mut client, _driver, _server) = configured_frontend(forwarding(addr)).await;
                    let (response, _) = client.send_request(Request::builder().uri("http://example.test/fail").body(()).unwrap(), true).unwrap();
                    let mut response = response.await.unwrap();
                    assert_eq!(response.status(), 200);
                    assert_eq!(response.body_mut().data().await.unwrap().unwrap(), b"abc"[..]);
                    complete_sibling(&mut client).await;
                    fail.notify_one();
                    assert_eq!(response.body_mut().data().await.unwrap().unwrap_err().reason(), Some(h2::Reason::INTERNAL_ERROR));
                    complete_sibling(&mut client).await;
                    assert_eq!(requests.load(Ordering::SeqCst), 3);
                    assert_eq!(count.load(Ordering::SeqCst), 1);
                } else {
                    let (mut client, mut session) = h1_frontend(forwarding(addr));
                    client.write_all(b"GET /fail HTTP/1.1\r\nHost: example.test\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: example.test\r\n\r\n").await.unwrap();
                    let response = head(&mut client).await;
                    assert!(response.starts_with(b"HTTP/1.1 200"));
                    assert_eq!(values(&response, "transfer-encoding"), ["chunked"]);
                    let mut data = [0;8];
                    client.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"3\r\nabc\r\n");
                    fail.notify_one();
                    // No zero chunk, no second response, and no parsing of the pipelined request.
                    eof(&mut client).await;
                    assert!((&mut session.0).await.unwrap().is_err());
                    assert_eq!(requests.load(Ordering::SeqCst), 1);
                }
            }
        }
    }).await;
}

#[tokio::test]
async fn h2_to_h2_backpressure_and_cancellation_preserve_forwarded_siblings() {
    checked(async {
        for cancel in [false, true] {
            let (blocked_tx, mut blocked) = mpsc::unbounded_channel();
            let (done_tx, mut done) = mpsc::unbounded_channel();
            let requests = Arc::new(AtomicUsize::new(0));
            let seen = requests.clone();
            let (addr, count, _backend) = h2_backend(move |request, mut response| {
                let blocked_tx = blocked_tx.clone();
                let done_tx = done_tx.clone();
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    let mut send = response.send_response(Response::new(()), false).unwrap();
                    if request.uri().path() == "/sibling" {
                        send.send_data(Bytes::from_static(b"sibling"), true)
                            .unwrap();
                        return;
                    }
                    let mut sent = 0;
                    let mut reported = false;
                    while sent < 1024 * 1024 {
                        send.reserve_capacity(16384);
                        let capacity = tokio::time::timeout(
                            Duration::from_millis(100),
                            poll_fn(|cx| send.poll_capacity(cx)),
                        )
                        .await;
                        let capacity = match capacity {
                            Ok(value) => value,
                            Err(_) => {
                                if !reported && sent >= 65535 {
                                    blocked_tx.send(sent).unwrap();
                                    reported = true;
                                }
                                poll_fn(|cx| send.poll_capacity(cx)).await
                            }
                        };
                        match capacity {
                            Some(Ok(n)) if n > 0 => {
                                let n = n.min(16384).min(1024 * 1024 - sent);
                                send.send_data(Bytes::from(vec![b'x'; n]), false).unwrap();
                                sent += n;
                            }
                            Some(Ok(_)) => continue,
                            Some(Err(error)) => {
                                done_tx.send(Err(error.reason())).unwrap();
                                return;
                            }
                            None => {
                                let reset = poll_fn(|cx| send.poll_reset(cx)).await.unwrap();
                                done_tx.send(Err(Some(reset))).unwrap();
                                return;
                            }
                        }
                    }
                    send.send_data(Bytes::new(), true).unwrap();
                    done_tx.send(Ok(sent)).unwrap();
                }
            })
            .await;
            let (mut client, _driver, _server) = configured_frontend(forwarding(addr)).await;
            let (response, mut request) = client
                .send_request(
                    Request::builder()
                        .uri("http://example.test/large")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            // The frontend advertises 1024 bytes and deliberately releases no credit yet.
            let sent = blocked.recv().await.unwrap();
            assert!(
                (65535..=128 * 1024).contains(&sent),
                "unbounded or premature stall: {sent}"
            );
            assert!(done.try_recv().is_err());
            complete_sibling(&mut client).await;
            if cancel {
                request.send_reset(h2::Reason::CANCEL);
                drop(response);
                assert_eq!(done.recv().await.unwrap(), Err(Some(h2::Reason::CANCEL)));
            } else {
                assert_eq!(
                    collect(response.into_body()).await.0,
                    vec![b'x'; 1024 * 1024]
                );
                assert_eq!(done.recv().await.unwrap(), Ok(1024 * 1024));
            }
            complete_sibling(&mut client).await;
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(requests.load(Ordering::SeqCst), 3);
        }
    })
    .await;
}

#[tokio::test]
async fn h2_to_h1_rewrites_and_patches_only_final_heads() {
    checked(async {
        let (listener, addr) = backend().await;
        let mut backend = Task(tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let request = head(&mut io).await;
            io.write_all(b"HTTP/1.1 103 Early Hints\r\nLocation: /internal/hint\r\n\r\nHTTP/1.1 200 OK\r\nLocation: /internal/next\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\nlocation: /internal/trailer\r\n\r\n").await.unwrap();
            request
        }));
        let mut http = runtime(action(json!({"type":"close"})), Http2Config::default(), None);
        http.path_configs.insert("/public/".into(), vec![TargetHttpPathData {
            required_request_headers: Default::default(),
            http_action: action(json!({
                "type":"forward", "location":addr.to_string(), "replacement_path":"/internal/",
                "request_id_header_name":"x-request-id", "response_id_header_name":"x-response-id",
                "request_header_patch":{"overwrite_headers":{"x-request":"patched"}},
                "response_header_patch":{"default_headers":{"x-response":"yes"}}
            })),
        }]);
        let (mut client, _driver, _server) = configured_frontend(http).await;
        let (mut response, _) = client.send_request(Request::builder().uri("http://example.test/public/file?x=1").body(()).unwrap(), true).unwrap();
        let info = poll_fn(|cx| response.poll_informational(cx)).await.unwrap().unwrap();
        assert_eq!(info.status(), 103);
        assert_eq!(info.headers()["location"], "/internal/hint");
        assert!(!info.headers().contains_key("x-response-id"));
        assert!(!info.headers().contains_key("x-response"));
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["location"], "/public/next");
        assert_eq!(response.headers()["x-response"], "yes");
        let response_id = response.headers()["x-response-id"].to_str().unwrap().to_owned();
        let (data, trailers) = collect(response.into_body()).await;
        assert_eq!(data, b"OK");
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers["location"], "/internal/trailer");
        let request = (&mut backend.0).await.unwrap();
        assert!(request.starts_with(b"GET /internal/file?x=1 HTTP/1.1\r\n"));
        assert_eq!(values(&request, "x-request"), ["patched"]);
        assert!(!response_id.is_empty());
        assert_eq!(values(&request, "x-request-id"), [response_id]);
    }).await;
}
