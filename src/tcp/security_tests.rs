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
    assert!(alpn_matches(&target, &[b"other".to_vec(), b"h2".to_vec()]));
    for offer in [
        vec![],
        vec![b"H2".to_vec()],
        vec![b"h2-extra".to_vec()],
        vec![vec![0xff]],
    ] {
        assert!(!alpn_matches(&target, &offer));
    }
    target.allow_no_alpn = true;
    assert!(alpn_matches(&target, &[]));
    assert!(!alpn_matches(&target, &[vec![0xff]]));
    target.allow_any_alpn = true;
    assert!(alpn_matches(&target, &[vec![0xff]]));
}

#[tokio::test(start_paused = true)]
async fn malformed_and_incomplete_tls_never_reach_a_plaintext_target() {
    for bytes in [
        b"\x16".as_slice(),
        b"\x16\x03\x03\x00\x04\x02\x00\x00\x00",
        b"\x17\x03\x03\x00\x01\x00",
    ] {
        let (backend, address) = listener().await;
        let (mut client, server, peer) = pair().await;
        client.write_all(bytes).await.unwrap();
        let error = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            Some(raw_target(address)),
            Arc::new(DomainTrie::new()),
            Arc::new(vec![]),
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
        assert!(timeout(Duration::from_millis(10), backend.accept())
            .await
            .is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn plaintext_and_server_first_connections_keep_their_raw_fallback() {
    for server_first in [false, true] {
        let (backend, address) = listener().await;
        let (mut client, server, peer) = pair().await;
        if !server_first {
            client.write_all(b"G").await.unwrap();
            client.shutdown().await.unwrap();
        }
        let proxy = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            Some(raw_target(address)),
            Arc::new(DomainTrie::new()),
            Arc::new(vec![]),
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
        let (result, (), ()) = tokio::join!(proxy, upstream, downstream);
        result.unwrap();
    }
}

#[tokio::test]
async fn fragmented_passthrough_replays_original_records_and_following_bytes() {
    timeout(Duration::from_secs(5), async {
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
        let mut trie = DomainTrie::new();
        trie.insert("localhost", vec![Arc::new(tls_target(address))]);
        client.write_all(&wire).await.unwrap();
        client.shutdown().await.unwrap();
        let proxy = process_tls_stream(
            server,
            &peer,
            Ipv6Addr::LOCALHOST,
            None,
            Arc::new(trie),
            Arc::new(vec![]),
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
    })
    .await
    .unwrap();
}
