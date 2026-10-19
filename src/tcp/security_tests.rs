use super::*;
use tokio::io::AsyncWriteExt;

async fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
    (listener, address)
}

async fn pair() -> (TcpStream, TcpStream, SocketAddr) {
    let (listener, address) = listener().await;
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let (server, peer) = accepted.unwrap();
    (client.unwrap(), server, peer)
}

fn raw_target(address: SocketAddr) -> Arc<TargetData> {
    Arc::new(TargetData {
        tcp_nodelay: true,
        tcp_keepalive: None,
        action_data: TargetActionData::Raw {
            location_data: vec![TargetLocationData {
                location: Location::Address(address.to_string().as_str().try_into().unwrap()),
                tls_connector: None,
                sni_hostname: NoneOrOne::Unspecified,
            }],
            next_address_index: AtomicUsize::new(0),
        },
    })
}

fn tls_target(address: SocketAddr) -> TlsTargetData {
    let mut ip_lookup_table = IpLookupTable::new();
    ip_lookup_table.insert(Ipv6Addr::UNSPECIFIED, 0, true);
    TlsTargetData {
        config_order: 0,
        handshake_timeout_secs: None,
        allow_no_alpn: false,
        allow_any_alpn: false,
        alpn_protocols: HashSet::from([b"h2".to_vec()]),
        ip_lookup_table,
        tls_mode: TlsMode::Passthrough,
        target_data: raw_target(address),
    }
}

#[test]
fn alpn_matching_uses_exact_opaque_identifiers_and_preserves_fallbacks() {
    let mut target = tls_target("127.0.0.1:1".parse().unwrap());
    assert_eq!(
        routing::alpn_match(&target, &[b"other".to_vec(), b"h2".to_vec()]),
        Some(AlpnMatch::Exact)
    );
    for offer in [
        vec![],
        vec![b"H2".to_vec()],
        vec![b"h2-extra".to_vec()],
        vec![vec![0xff]],
    ] {
        assert_eq!(routing::alpn_match(&target, &offer), None);
    }
    target.allow_no_alpn = true;
    assert_eq!(routing::alpn_match(&target, &[]), Some(AlpnMatch::Absent));
    assert_eq!(routing::alpn_match(&target, &[vec![0xff]]), None);
    target.allow_any_alpn = true;
    assert_eq!(
        routing::alpn_match(&target, &[vec![0xff]]),
        Some(AlpnMatch::Any)
    );
}

#[tokio::test(start_paused = true)]
async fn malformed_and_incomplete_tls_cannot_fall_back_to_plaintext_http() {
    for bytes in [
        b"\x16".as_slice(),
        b"\x16\x03\x03\x00\x04\x02\x00\x00\x00",
        b"\x17\x03\x03\x00\x01\x00",
    ] {
        let mut routes = RoutingTable::default();
        routes
            .insert_non_tls(
                &[IpMask::all()],
                protocol_tests::target(HttpProtocols::default()),
            )
            .unwrap();
        let (mut client, server, peer) = pair().await;
        client.write_all(bytes).await.unwrap();
        let error = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            routes.ip_targets(Ipv6Addr::LOCALHOST),
            &routes,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.kind(),
            if bytes.len() == 1 {
                std::io::ErrorKind::TimedOut
            } else {
                std::io::ErrorKind::InvalidData
            }
        );
        if bytes.len() == 1 {
            assert!(
                error
                    .to_string()
                    .starts_with("TLS ClientHello parse timed out"),
                "{error}"
            );
        }
    }
}

#[tokio::test]
async fn plaintext_and_server_first_connections_keep_their_raw_fallback() {
    for server_first in [false, true] {
        let (backend, address) = listener().await;
        let mut routes = RoutingTable::default();
        routes
            .insert_non_tls(&[IpMask::all()], raw_target(address))
            .unwrap();
        let (mut client, server, peer) = pair().await;
        if !server_first {
            client.write_all(b"G").await.unwrap();
            client.shutdown().await.unwrap();
        }
        let proxy = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            routes.ip_targets(Ipv6Addr::LOCALHOST),
            &routes,
        );
        let upstream = async {
            let (mut stream, _) = backend.accept().await.unwrap();
            if !server_first {
                assert_eq!(stream.read_u8().await.unwrap(), b'G');
            }
            stream.write_all(b"reply").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let downstream = async {
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
            client.shutdown().await.unwrap();
        };
        let (result, (), ()) = timeout(Duration::from_secs(10), async {
            tokio::join!(proxy, upstream, downstream)
        })
        .await
        .unwrap();
        result.unwrap();
    }
}

async fn check_idle_http_fallback(with_raw: bool) {
    let (backend, address) = listener().await;
    let mut routes = RoutingTable::default();
    routes
        .insert_non_tls(
            &[IpMask::try_from("127.0.0.1/32").unwrap()],
            protocol_tests::target(HttpProtocols::default()),
        )
        .unwrap();
    if with_raw {
        routes
            .insert_non_tls(&[IpMask::all()], raw_target(address))
            .unwrap();
    }
    routes.insert_tls(&Default::default(), Arc::new(tls_target(address)));
    let (mut client, server, peer) = pair().await;
    let ip = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    let ip_targets = routes.ip_targets(ip);
    assert!(ip_targets.direct_target().is_none());
    let proxy = process_tls_stream(server, &peer, ip, ip_targets, &routes);
    let downstream = async {
        tokio::time::sleep(Duration::from_secs(6)).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    };
    tokio::select! {
        accepted = backend.accept() => panic!("unexpected backend connection: {accepted:?}"),
        (result, ()) = async { tokio::join!(proxy, downstream) } => result.unwrap(),
    }
}

#[tokio::test(start_paused = true)]
async fn idle_plaintext_after_inspection_timeout_reaches_http() {
    check_idle_http_fallback(false).await;
}

#[tokio::test(start_paused = true)]
async fn idle_plaintext_after_inspection_timeout_does_not_use_raw() {
    check_idle_http_fallback(true).await;
}

#[tokio::test]
async fn fragmented_tls_replays_original_records_and_following_bytes_for_raw_and_passthrough() {
    timeout(Duration::from_secs(5), async {
        for matching_tls in [false, true] {
            let config = crate::rustls_util::create_client_config_with_cert(
                false,
                None,
                vec![b"h2".to_vec()],
                true,
                vec![],
            )
            .unwrap();
            let mut tls = rustls::ClientConnection::new(
                config,
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            )
            .unwrap();
            let mut hello = Vec::new();
            tls.write_tls(&mut hello).unwrap();
            let mut wire = Vec::new();
            for chunk in hello[5..].chunks(7) {
                wire.extend([0x16, 3, 3]);
                wire.extend((chunk.len() as u16).to_be_bytes());
                wire.extend(chunk);
            }
            wire.extend(b"following bytes");
            let (backend, address) = listener().await;
            let (mut client, server, peer) = pair().await;
            let mut routes = RoutingTable::default();
            routes
                .insert_non_tls(&[IpMask::all()], raw_target(address))
                .unwrap();
            let names = serde_json::from_value(serde_json::json!(if matching_tls {
                "localhost"
            } else {
                "other.example"
            }))
            .unwrap();
            routes.insert_tls(&names, Arc::new(tls_target(address)));
            client.write_all(&wire).await.unwrap();
            client.shutdown().await.unwrap();
            let proxy = process_tls_stream(
                server,
                &peer,
                Ipv6Addr::LOCALHOST,
                routes.ip_targets(Ipv6Addr::LOCALHOST),
                &routes,
            );
            let upstream = async {
                let (mut stream, _) = backend.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, wire);
                stream.shutdown().await.unwrap();
            };
            let (result, ()) = tokio::join!(proxy, upstream);
            result.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn raw_fallback_replays_malformed_and_timed_out_tls_without_losing_read_ahead() {
    for bytes in [
        b"\x16".as_slice(),
        b"\x16\x03\x03\x00\x01\x01\x16\x03",
        b"\x16\x03\x03\x00\x04\x02\x00\x00\x00following bytes",
        b"\x17\x03\x03\x00\x01\x00following bytes",
        b"\x16\x03\x03\xff\xfffollowing bytes",
    ] {
        let (backend, address) = listener().await;
        let mut routes = RoutingTable::default();
        routes
            .insert_non_tls(&[IpMask::all()], raw_target(address))
            .unwrap();
        let (mut client, server, peer) = pair().await;
        client.write_all(bytes).await.unwrap();
        let proxy = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            routes.ip_targets(Ipv6Addr::LOCALHOST),
            &routes,
        );
        let upstream = async {
            let (mut stream, _) = backend.accept().await.unwrap();
            let mut received = vec![0; bytes.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, bytes);
            stream.write_all(b"reply").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let downstream = async {
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
            client.shutdown().await.unwrap();
        };
        let (result, (), ()) = timeout(Duration::from_secs(10), async {
            tokio::join!(proxy, upstream, downstream)
        })
        .await
        .unwrap();
        result.unwrap();
    }
}

#[tokio::test]
async fn raw_fallback_replays_inspection_buffer_exhaustion_and_unread_trailing_bytes() {
    timeout(Duration::from_secs(5), async {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        body.extend(44004u16.to_be_bytes());
        body.extend([0x12, 0x34]);
        body.extend(44000u16.to_be_bytes());
        body.extend(vec![0x42; 44000]);
        let mut hello = vec![1];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend(body);

        // Small records exhaust the wire buffer before this valid ClientHello
        // is complete; the remaining records and suffix must still be forwarded.
        let mut wire = Vec::new();
        for chunk in hello.chunks(8) {
            wire.extend([0x16, 3, 3]);
            wire.extend((chunk.len() as u16).to_be_bytes());
            wire.extend(chunk);
        }
        assert!(hello.len() < crate::tls_reader::TLS_BUFFER_MAX_LEN);
        assert!(wire.len() > crate::tls_reader::TLS_BUFFER_MAX_LEN);
        wire.extend(b"unread trailing bytes");

        let (backend, address) = listener().await;
        let (mut client, server, peer) = pair().await;
        let mut routes = RoutingTable::default();
        routes
            .insert_non_tls(&[IpMask::all()], raw_target(address))
            .unwrap();
        routes.insert_tls(&Default::default(), Arc::new(tls_target(address)));
        let proxy = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            routes.ip_targets(Ipv6Addr::LOCALHOST),
            &routes,
        );
        let upstream = async {
            let (mut stream, _) = backend.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, wire);
            stream.write_all(b"reply").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let downstream = async {
            client.write_all(&wire).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply");
        };
        let (result, (), ()) = tokio::join!(proxy, upstream, downstream);
        result.unwrap();
    })
    .await
    .unwrap();
}

fn client_config() -> Arc<rustls::ClientConfig> {
    crate::rustls_util::create_client_config_with_cert(
        false,
        None,
        vec![b"h2".to_vec()],
        true,
        vec![],
    )
    .unwrap()
}

fn terminate_target(address: SocketAddr, require_client_cert: bool) -> TlsTargetData {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let fingerprints = if require_client_cert {
        vec!["00".repeat(32)]
    } else {
        vec![]
    };
    let (alpn_tls_config, no_alpn_tls_config) = build_rustls_configs(
        load_certs(identity.cert.pem().as_bytes()).unwrap(),
        &load_private_key(identity.signing_key.serialize_pem().as_bytes()).unwrap(),
        &serde_json::from_value(serde_json::json!(["h2"])).unwrap(),
        &crate::config::NoneOrSome::Some(fingerprints),
        &[],
    )
    .unwrap();
    let mut target = tls_target(address);
    target.handshake_timeout_secs = std::num::NonZeroU64::new(1);
    target.tls_mode = TlsMode::Terminate {
        alpn_tls_config,
        no_alpn_tls_config,
    };
    target
}

#[tokio::test]
async fn selected_tls_authentication_and_backend_failures_never_use_raw_fallback() {
    timeout(Duration::from_secs(5), async {
        for require_client_cert in [true, false] {
            let (raw_backend, raw_address) = listener().await;
            let (closed_backend, closed_address) = listener().await;
            drop(closed_backend);
            let mut routes = RoutingTable::default();
            routes
                .insert_non_tls(&[IpMask::all()], raw_target(raw_address))
                .unwrap();
            routes.insert_tls(
                &Default::default(),
                Arc::new(terminate_target(closed_address, require_client_cert)),
            );
            let (client, server, peer) = pair().await;
            let proxy = process_tls_stream(
                server,
                &peer,
                Ipv6Addr::LOCALHOST,
                routes.ip_targets(Ipv6Addr::LOCALHOST),
                &routes,
            );
            let downstream = async {
                let connector = tokio_rustls::TlsConnector::from(client_config());
                let mut stream = connector
                    .connect(
                        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                        client,
                    )
                    .await?;
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await
            };
            let (result, _) = tokio::join!(proxy, downstream);
            let error = result.unwrap_err();
            if require_client_cert {
                assert!(error.to_string().contains("certificate"), "{error}");
            } else {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
            }
            assert!(timeout(Duration::from_millis(10), raw_backend.accept())
                .await
                .is_err());
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn selected_tls_handshake_timeout_never_uses_raw_fallback() {
    let (raw_backend, raw_address) = listener().await;
    let mut routes = RoutingTable::default();
    routes
        .insert_non_tls(&[IpMask::all()], raw_target(raw_address))
        .unwrap();
    routes.insert_tls(
        &Default::default(),
        Arc::new(terminate_target(raw_address, false)),
    );
    let (mut client, server, peer) = pair().await;
    let mut tls = rustls::ClientConnection::new(
        client_config(),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    tls.write_tls(&mut hello).unwrap();
    client.write_all(&hello).await.unwrap();
    let error = process_tls_stream(
        server,
        &peer,
        Ipv6Addr::LOCALHOST,
        routes.ip_targets(Ipv6Addr::LOCALHOST),
        &routes,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "TLS handshake timed out");
    assert!(timeout(Duration::from_millis(10), raw_backend.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn selected_passthrough_backend_failure_never_uses_raw_fallback() {
    let (raw_backend, raw_address) = listener().await;
    let (closed_backend, closed_address) = listener().await;
    drop(closed_backend);
    let mut routes = RoutingTable::default();
    routes
        .insert_non_tls(&[IpMask::all()], raw_target(raw_address))
        .unwrap();
    routes.insert_tls(&Default::default(), Arc::new(tls_target(closed_address)));
    let (mut client, server, peer) = pair().await;
    let mut tls = rustls::ClientConnection::new(
        client_config(),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    tls.write_tls(&mut hello).unwrap();
    client.write_all(&hello).await.unwrap();
    let error = timeout(
        Duration::from_secs(5),
        process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            routes.ip_targets(Ipv6Addr::LOCALHOST),
            &routes,
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(timeout(Duration::from_millis(10), raw_backend.accept())
        .await
        .is_err());
}
