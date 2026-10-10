use super::forwarding::{chunked, h1_frontend};
use super::*;
use tokio::sync::mpsc;

async fn elapse(seconds: u64) {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(seconds)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    tokio::time::resume();
}

#[tokio::test]
async fn upstream_latency_is_unbounded_in_all_four_protocol_combinations() {
    for frontend_h2 in [false, true] {
        for backend_h2 in [false, true] {
            let (listener, addr) = backend().await;
            let (commands, mut command) = mpsc::channel::<()>(1);
            let (events, mut event) = mpsc::channel::<&str>(8);
            let backend_events = events.clone();
            let mut backend = Task(tokio::spawn(async move {
                let (mut io, _) = listener.accept().await.unwrap();
                if backend_h2 {
                    let mut connection = h2::server::handshake(io).await.unwrap();
                    let (mut request, mut response) = connection.accept().await.unwrap().unwrap();
                    let _driver = Task(tokio::spawn(async move {
                        while connection.accept().await.is_some() {}
                    }));
                    backend_events.send("request").await.unwrap();
                    command.recv().await.unwrap();
                    response
                        .send_informational(Response::builder().status(100).body(()).unwrap())
                        .unwrap();
                    let mut data = Vec::new();
                    while let Some(bytes) = request.body_mut().data().await {
                        let bytes = bytes.unwrap();
                        request
                            .body_mut()
                            .flow_control()
                            .release_capacity(bytes.len())
                            .unwrap();
                        data.extend_from_slice(&bytes);
                    }
                    assert_eq!(data, b"x");
                    backend_events.send("uploaded").await.unwrap();
                    command.recv().await.unwrap();
                    let mut response = response.send_response(Response::new(()), false).unwrap();
                    command.recv().await.unwrap();
                    response.send_data(Bytes::from_static(b"a"), false).unwrap();
                    command.recv().await.unwrap();
                    response.send_data(Bytes::from_static(b"b"), true).unwrap();
                    command.recv().await.unwrap();
                } else {
                    let request = head(&mut io).await;
                    backend_events.send("request").await.unwrap();
                    command.recv().await.unwrap();
                    io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                        .await
                        .unwrap();
                    if frontend_h2 {
                        let mut bytes = [0; 11];
                        io.read_exact(&mut bytes).await.unwrap();
                        assert_eq!(&bytes, b"1\r\nx\r\n0\r\n\r\n");
                    } else {
                        assert!(String::from_utf8_lossy(&request)
                            .to_ascii_lowercase()
                            .contains("content-length: 1"));
                        assert_eq!(io.read_u8().await.unwrap(), b'x');
                    }
                    backend_events.send("uploaded").await.unwrap();
                    command.recv().await.unwrap();
                    io.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                    command.recv().await.unwrap();
                    io.write_all(b"a").await.unwrap();
                    command.recv().await.unwrap();
                    io.write_all(b"b").await.unwrap();
                    command.recv().await.unwrap();
                }
            }));
            let http = runtime(
                action(
                    json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":if backend_h2 { "http2" } else { "http1" }}),
                ),
                Http2Config::default(),
                None,
            );
            let mut client = Task(tokio::spawn(async move {
                if frontend_h2 {
                    let (mut client, _driver, _server) = configured_frontend(http).await;
                    let (mut response, mut upload) = client
                        .send_request(
                            Request::builder()
                                .method("POST")
                                .uri("http://example.test/")
                                .header("expect", "100-continue")
                                .header("content-length", "1")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    assert_eq!(
                        std::future::poll_fn(|cx| response.poll_informational(cx))
                            .await
                            .unwrap()
                            .unwrap()
                            .status(),
                        100
                    );
                    upload.send_data(Bytes::from_static(b"x"), true).unwrap();
                    let mut response = response.await.unwrap();
                    assert_eq!(response.status(), 200);
                    events.send("head").await.unwrap();
                    let first = response.body_mut().data().await.unwrap().unwrap();
                    assert_eq!(first, b"a"[..]);
                    response
                        .body_mut()
                        .flow_control()
                        .release_capacity(first.len())
                        .unwrap();
                    events.send("data").await.unwrap();
                    assert_eq!(collect(response.into_body()).await.0, b"b");
                } else {
                    let (mut client, _session) = h1_frontend(http);
                    client.write_all(b"POST / HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 1\r\nConnection: close\r\n\r\n").await.unwrap();
                    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 100"));
                    client.write_all(b"x").await.unwrap();
                    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200"));
                    events.send("head").await.unwrap();
                    if backend_h2 {
                        let mut first = [0; 6];
                        client.read_exact(&mut first).await.unwrap();
                        assert_eq!(&first, b"1\r\na\r\n");
                        events.send("data").await.unwrap();
                        assert_eq!(chunked(&mut client).await.0, b"b");
                    } else {
                        assert_eq!(client.read_u8().await.unwrap(), b'a');
                        events.send("data").await.unwrap();
                        assert_eq!(client.read_u8().await.unwrap(), b'b');
                    }
                }
            }));
            for expected in ["request", "uploaded", "head", "data"] {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), event.recv())
                        .await
                        .unwrap()
                        .unwrap(),
                    expected,
                    "frontend H2={frontend_h2}, backend H2={backend_h2}"
                );
                elapse(35).await;
                commands.send(()).await.unwrap();
            }
            tokio::time::timeout(Duration::from_secs(5), &mut client.0)
                .await
                .unwrap()
                .unwrap();
            commands.send(()).await.unwrap();
            (&mut backend.0).await.unwrap();
        }
    }
}

#[tokio::test]
async fn h2_explicit_null_disables_idle_retirement() {
    let mut http = runtime(
        action(json!({"type":"serve-message", "status_code":200, "content":"OK"})),
        Http2Config::default(),
        None,
    );
    http.http_timeouts.keepalive_idle_timeout_secs = None;
    let (mut client, _driver, _server) = configured_frontend(http).await;
    for _ in 0..2 {
        elapse(100).await;
        let (response, _) = client
            .send_request(
                Request::builder()
                    .uri("http://example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(collect(response.await.unwrap().into_body()).await.0, b"OK");
    }
}

#[tokio::test]
async fn explicit_h2_upstream_body_budget_releases_admission_and_preserves_siblings() {
    let (addr, _, _backend) = h2_backend(|request, mut response| async move {
        let mut send = response.send_response(Response::new(()), false).unwrap();
        if request.uri().path() == "/slow" {
            send.send_data(Bytes::from_static(b"a"), false).unwrap();
            std::future::pending::<()>().await;
        } else {
            send.send_data(Bytes::from_static(b"OK"), true).unwrap();
        }
        drop(request);
    })
    .await;
    let mut http = runtime(
        action(json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"})),
        Http2Config {
            max_backend_connections: 1.try_into().unwrap(),
            ..Default::default()
        },
        None,
    );
    http.http_timeouts.upstream_body_progress_timeout_secs = std::num::NonZeroU64::new(2);
    let (mut client, _driver, _server) = configured_frontend(http).await;
    let (response, _) = client
        .send_request(
            Request::builder()
                .uri("http://example.test/slow")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let mut response = response.await.unwrap();
    let first = response.body_mut().data().await.unwrap().unwrap();
    response
        .body_mut()
        .flow_control()
        .release_capacity(first.len())
        .unwrap();
    elapse(3).await;
    assert!(response.body_mut().data().await.unwrap().is_err());
    let (response, _) = client
        .send_request(
            Request::builder()
                .uri("http://example.test/next")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(collect(response.await.unwrap().into_body()).await.0, b"OK");
}

#[tokio::test]
async fn explicit_header_budget_expires_during_expect_and_interim_responses() {
    for status in [100, 103] {
        let (addr, _, _backend) = h2_backend(move |request, mut response| async move {
            response
                .send_informational(Response::builder().status(status).body(()).unwrap())
                .unwrap();
            std::future::pending::<()>().await;
            drop((request, response));
        })
        .await;
        let mut http = runtime(
            action(
                json!({"type":"forward", "location":addr.to_string(), "upstream_protocol":"http2"}),
            ),
            Http2Config::default(),
            None,
        );
        http.http_timeouts.response_header_timeout_secs = std::num::NonZeroU64::new(2);
        let (mut client, _driver, _server) = configured_frontend(http).await;
        let (mut response, _upload) = client
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("http://example.test/")
                    .header("expect", "100-continue")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        assert_eq!(
            std::future::poll_fn(|cx| response.poll_informational(cx))
                .await
                .unwrap()
                .unwrap()
                .status(),
            status
        );
        elapse(3).await;
        assert_eq!(response.await.unwrap().status(), 502);
    }
}
