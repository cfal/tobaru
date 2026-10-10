use super::*;
use serde_json::json;
use tokio::io::AsyncWriteExt;

const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);

fn target(protocols: HttpProtocols) -> Arc<TargetData> {
    let config: HttpTcpActionConfig = serde_json::from_value(json!({
        "default_http_action": {"type":"serve-message", "status_code":200, "content":"selected"}
    }))
    .unwrap();
    Arc::new(TargetData {
        tcp_nodelay: true,
        tcp_keepalive: None,
        action_data: TargetActionData::Http(Box::new(HttpTargetData {
            http_protocols: protocols,
            h2_admission: crate::http::h2::Admission::new(*config.http2, None),
            http2: *config.http2,
            http_timeouts: config.http_timeouts,
            path_configs: Trie::new(),
            default_http_action: config.default_http_action.try_into().unwrap(),
        })),
    })
}

#[tokio::test]
async fn optional_tls_hands_off_after_four_plaintext_bytes() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address: SocketAddr = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client.unwrap();
        let (server, peer) = accepted.unwrap();
        let owner = tokio::spawn(async move {
            process_tls_stream(
                server,
                &peer,
                std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
                Some(target(HttpProtocols::default())),
                Arc::new(DomainTrie::new()),
                Arc::new(vec![]),
            )
            .await
        });
        for byte in b"PRI " {
            client.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        // h2 flushes its SETTINGS before reading the rest of the client preface.
        let mut header = [0; 9];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[3], 4);
        drop(client);
        assert!(owner.await.unwrap().is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h1_dispatch_replays_read_ahead_and_preserves_extension_methods() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for method in ["GET", "POST", "PUT", "PATCH", "PRINT"] {
            let request = format!("{method} / HTTP/1.1\r\nHost: example\r\n\r\n");
            for buffered in [0, 1, 3, 4, request.len()] {
                let (mut client, server) = UnixStream::pair().unwrap();
                let initial = (buffered != 0).then(|| request.as_bytes()[..buffered].to_vec());
                let owner = tokio::spawn(run_stream_action(
                    Box::new(server),
                    &PEER,
                    target(HttpProtocols::default()),
                    initial,
                ));
                client
                    .write_all(&request.as_bytes()[buffered..])
                    .await
                    .unwrap();
                let mut response = String::new();
                client.read_to_string(&mut response).await.unwrap();
                owner.await.unwrap().unwrap();
                assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
                assert!(
                    response.ends_with("8\r\nselected\r\n0\r\n\r\n"),
                    "{response:?}"
                );
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_dispatch_replays_preface_and_settings_read_ahead() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (protocols, tls, alpn) in [
            (HttpProtocols::default(), false, None),
            (
                HttpProtocols {
                    http1: false,
                    http2: true,
                },
                false,
                None,
            ),
            (HttpProtocols::default(), true, Some(b"h2".to_vec())),
        ] {
            for buffered in [0, 1, 3, 4, 24, 33] {
                let (client, mut server) = UnixStream::pair().unwrap();
                let alpn = alpn.clone();
                let owner = tokio::spawn(async move {
                    let mut initial = vec![0; buffered];
                    server.read_exact(&mut initial).await.unwrap();
                    run_stream_action_with_protocol(
                        Box::new(server),
                        &PEER,
                        target(protocols),
                        Some(initial),
                        alpn,
                        tls,
                    )
                    .await
                });
                let (mut send, connection) = h2::client::handshake(client).await.unwrap();
                let driver = tokio::spawn(connection);
                let (response, _) = send
                    .send_request(
                        http::Request::builder()
                            .uri("http://example/")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                let mut body = response.into_body();
                let mut data = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                    data.extend_from_slice(&chunk);
                }
                assert_eq!(data, b"selected");
                drop(body);
                drop(send);
                driver.abort();
                let _ = driver.await;
                let _ = owner.await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tls_h1_and_no_alpn_never_sniff_the_reserved_method() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for alpn in [
            None,
            Some(b"http/1.1".to_vec()),
            Some(b"legacy-http".to_vec()),
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let owner = tokio::spawn(run_stream_action_with_protocol(
                Box::new(server),
                &PEER,
                target(HttpProtocols::default()),
                None,
                alpn,
                true,
            ));
            client
                .write_all(b"PRI / HTTP/1.1\r\nHost: example\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            owner.await.unwrap().unwrap();
            assert!(response.starts_with("HTTP/1.1 200"));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn disabled_protocols_and_invalid_h2_prefaces_never_fall_back() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let h1 = HttpProtocols {
            http1: true,
            http2: false,
        };
        let h2 = HttpProtocols {
            http1: false,
            http2: true,
        };
        for (protocols, tls, alpn, request) in [
            (h1, false, None, &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]),
            (
                h2,
                false,
                None,
                &b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"[..],
            ),
            (
                HttpProtocols::default(),
                false,
                None,
                &b"PRI / HTTP/1.1\r\nHost: example\r\n\r\n"[..],
            ),
            (
                HttpProtocols::default(),
                true,
                Some(b"http/1.1".to_vec()),
                &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..],
            ),
            (
                HttpProtocols::default(),
                true,
                Some(b"h2".to_vec()),
                &b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"[..],
            ),
            (h1, true, Some(b"h2".to_vec()), &b""[..]),
            (h2, true, Some(b"http/1.1".to_vec()), &b""[..]),
            (h2, true, None, &b""[..]),
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.write_all(request).await.unwrap();
            client.shutdown().await.unwrap();
            assert!(run_stream_action_with_protocol(
                Box::new(server),
                &PEER,
                target(protocols),
                None,
                alpn,
                tls,
            )
            .await
            .is_err());
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn detection_uses_the_request_header_timeout_override() {
    let (_client, server) = UnixStream::pair().unwrap();
    let mut target = target(HttpProtocols::default());
    let TargetActionData::Http(http) = &mut Arc::get_mut(&mut target).unwrap().action_data else {
        unreachable!()
    };
    http.http_timeouts.request_header_timeout_secs = std::num::NonZeroU64::new(1);
    let start = tokio::time::Instant::now();
    let error = run_stream_action(Box::new(server), &PEER, target, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[tokio::test]
async fn h2_local_validation_applies_to_default_and_explicit_protocols() {
    for (protocols, allowed) in [
        (None, false),
        (Some(json!(["http1", "http2"])), false),
        (Some(json!(["http2"])), false),
        (Some(json!(["http1"])), true),
    ] {
        let mut value = json!({
            "allowlist":"127.0.0.1/32",
            "default_http_action":{
                "type":"serve-message", "status_code":200,
                "response_headers":{"proxy-connection":"keep-alive"}
            }
        });
        if let Some(protocols) = protocols {
            value["http_protocols"] = protocols;
        }
        let config = serde_json::from_value(value).unwrap();
        let result = prepare_tcp_server(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            false,
            true,
            TcpKeepaliveOption::default(),
            vec![config],
        )
        .await;
        assert_eq!(result.is_ok(), allowed);
    }
}
