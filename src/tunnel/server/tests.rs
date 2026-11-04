use super::super::test_support::{expect_create_data, harness, Tls};
use super::*;
use tokio::io::AsyncReadExt;

async fn channel(
    peer: &Peer,
    session: &Arc<Session>,
    messages: &mut tokio::sync::mpsc::Receiver<Message>,
) -> (Open, Channel, tokio_rustls::client::TlsStream<TcpStream>) {
    let (io, client) = Tls::new().pair().await;
    session.request_data(peer).unwrap();
    let channel_id = expect_create_data(messages);
    let accepted = peer.endpoint.accept().unwrap();
    let (credit, open) = session.attach(&channel_id, &[1]).unwrap();
    drop(credit._endpoint);
    (
        open,
        Channel {
            io,
            _accepted: accepted,
            _physical: credit.physical,
        },
        client,
    )
}

fn assert_released(peer: &Peer) {
    assert_eq!(peer.active.count(), 0);
    assert_eq!(peer.pending.count(), 0);
    assert_eq!(peer.physical.count(), 0);
    assert_eq!(peer.endpoint.accepted.count(), 0);
    assert_eq!(peer.endpoint.credits.count(), 0);
}

fn hub(peer: &Arc<Peer>, tls: &Tls) -> Arc<Server> {
    Arc::new(Server {
        address: "0.0.0.0:0".parse().unwrap(),
        tls: tls.server.clone(),
        gate: peer.gate.clone(),
        endpoint: peer.endpoint.clone(),
        peers: HashMap::from([("home".into(), peer.clone())]),
        identities: HashMap::from([(tls.fingerprint.clone(), "home".into())]),
        handshakes: Arc::default(),
        max_handshakes: 16,
    })
}

async fn block_server_writes(
    channel: &mut Channel,
    agent: &tokio_rustls::client::TlsStream<TcpStream>,
) {
    use tokio::io::AsyncWriteExt;
    socket2::SockRef::from(channel.io.get_ref().0)
        .set_send_buffer_size(4096)
        .unwrap();
    socket2::SockRef::from(agent.get_ref().0)
        .set_recv_buffer_size(4096)
        .unwrap();
    channel.io.get_mut().1.set_buffer_limit(Some(32768));
    assert!(timeout(
        Duration::from_millis(50),
        channel.io.write_all(&[0; 262144])
    )
    .await
    .is_err());
}

#[tokio::test]
async fn assigned_open_cancellation_closes_channel_without_ready_or_timeout() {
    let (peer, session, mut messages) = harness(1);
    let p = peer.clone();
    let caller = tokio::spawn(async move {
        p.open("web", Instant::now() + Duration::from_secs(60))
            .await
    });
    tokio::task::yield_now().await;
    let (open, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    let worker = tokio::spawn(serve_data(
        peer.clone(),
        session.clone(),
        channel,
        open,
        Instant::now() + Duration::from_secs(10),
    ));
    assert!(matches!(
        protocol::read(&mut agent).await.unwrap(),
        Message::Open { .. }
    ));
    assert_eq!(peer.pending.count(), 1);
    caller.abort();
    let _ = caller.await;
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let closed = timeout(Duration::from_secs(1), agent.read(&mut [0]))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    assert_released(&peer);
}

#[tokio::test]
async fn cancellation_after_attachment_closes_without_sending_open() {
    let (peer, session, mut messages) = harness(1);
    let p = peer.clone();
    let caller = tokio::spawn(async move {
        p.open("web", Instant::now() + Duration::from_secs(60))
            .await
    });
    tokio::task::yield_now().await;
    let (open, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    caller.abort();
    let _ = caller.await;
    timeout(
        Duration::from_secs(1),
        serve_data(
            peer.clone(),
            session.clone(),
            channel,
            open,
            Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("cancelled attachment was not closed promptly")
    .unwrap();
    let closed = timeout(Duration::from_secs(1), agent.read(&mut [0]))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    assert_released(&peer);
}

#[tokio::test]
async fn pre_open_bytes_or_eof_requeue_the_same_demand_before_later_callers() {
    use tokio::io::AsyncWriteExt;
    for early_bytes in [true, false] {
        let (peer, session, mut messages) = harness(2);
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut first = Box::pin(peer.open("web", deadline));
        assert!(futures::poll!(&mut first).is_pending());
        let (open, mut channel, mut agent) = channel(&peer, &session, &mut messages).await;
        let mut later = Box::pin(peer.open("web", deadline + Duration::from_secs(1)));
        assert!(futures::poll!(&mut later).is_pending());
        if early_bytes {
            agent.write_all(b"xy").await.unwrap();
            // Leave forbidden read-ahead buffered after consuming a prefix.
            assert_eq!(channel.io.read_u8().await.unwrap(), b'x');
        } else {
            agent.shutdown().await.unwrap();
            assert_eq!(channel.io.read(&mut [0]).await.unwrap(), 0);
        }
        assert!(timeout(
            Duration::from_secs(1),
            serve_data(
                peer.clone(),
                session.clone(),
                channel,
                open,
                Instant::now() + Duration::from_secs(10)
            ),
        )
        .await
        .unwrap()
        .is_err());
        let closed = timeout(Duration::from_secs(1), agent.read(&mut [0]))
            .await
            .unwrap();
        assert!(closed.is_err() || closed.unwrap() == 0);
        {
            let guard = session.state.lock();
            let opens = &guard.as_ref().unwrap().opens;
            assert_eq!(opens.len(), 2);
            assert_eq!(opens[0].deadline, deadline);
            assert_eq!(opens[1].deadline, deadline + Duration::from_secs(1));
        }
        assert_eq!(peer.active.count(), 2);
        assert_eq!(peer.pending.count(), 2);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.accepted.count(), 0);
        session.close();
        assert!(first.await.is_err());
        assert!(later.await.is_err());
        assert_released(&peer);
    }
}

#[tokio::test]
async fn retirement_or_replacement_after_assignment_prevents_open() {
    for retire_generation in [true, false] {
        let (peer, session, mut messages) = harness(1);
        let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
        assert!(futures::poll!(&mut caller).is_pending());
        let (open, channel, mut agent) = channel(&peer, &session, &mut messages).await;
        if retire_generation {
            peer.gate.retire();
        } else {
            let (writer, _rx) = tokio::sync::mpsc::channel(64);
            peer.install(Arc::new(Session::new(
                Id::new(),
                vec![1],
                HashSet::new(),
                writer,
            )))
            .unwrap();
        }
        assert!(timeout(
            Duration::from_secs(1),
            serve_data(
                peer.clone(),
                session.clone(),
                channel,
                open,
                Instant::now() + Duration::from_secs(10)
            ),
        )
        .await
        .unwrap()
        .is_err());
        let closed = timeout(Duration::from_secs(1), agent.read(&mut [0]))
            .await
            .unwrap();
        assert!(closed.is_err() || closed.unwrap() == 0);
        assert!(caller.await.is_err());
        assert_released(&peer);
    }
}

#[tokio::test]
async fn ready_handoff_survives_attachment_deadline_and_session_close() {
    let (peer, session, mut messages) = harness(1);
    let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
    assert!(futures::poll!(&mut caller).is_pending());
    let (open, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    let worker = tokio::spawn(serve_data(
        peer.clone(),
        session.clone(),
        channel,
        open,
        Instant::now() + Duration::from_secs(5),
    ));
    assert!(matches!(
        protocol::read(&mut agent).await.unwrap(),
        Message::Open { .. }
    ));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(!worker.is_finished());
    tokio::time::resume();
    protocol::write(&mut agent, &Message::Ready {})
        .await
        .unwrap();
    use tokio::io::AsyncWriteExt;
    agent.write_all(b"greeting").await.unwrap();
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    session.close();
    agent.write_all(b"!").await.unwrap();
    let mut stream = timeout(Duration::from_secs(1), caller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.pending.count(), 0);
    assert_eq!(peer.active.count(), 1);
    assert_eq!(peer.physical.count(), 1);
    assert_eq!(peer.endpoint.accepted.count(), 1);
    assert_eq!(peer.endpoint.credits.count(), 0);
    let mut bytes = [0; 9];
    timeout(Duration::from_secs(1), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"greeting!");
    drop(stream);
    assert_released(&peer);
}

#[tokio::test]
async fn first_open_write_keeps_the_connection_setup_deadline_under_backpressure() {
    let (peer, session, mut messages) = harness(1);
    let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
    assert!(futures::poll!(&mut caller).is_pending());
    let (open, mut channel, agent) = channel(&peer, &session, &mut messages).await;
    block_server_writes(&mut channel, &agent).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let worker = tokio::spawn(serve_data(
        peer.clone(),
        session.clone(),
        channel,
        open,
        deadline,
    ));
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now()) / 2).await;
    assert!(!worker.is_finished());
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    timeout(Duration::from_millis(1), worker)
        .await
        .expect("first Open write exceeded its attachment deadline")
        .unwrap()
        .unwrap();
    assert!(matches!(caller.await, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    assert_released(&peer);
}

#[tokio::test]
async fn cancellation_interrupts_a_backpressured_open_write() {
    let (peer, session, mut messages) = harness(1);
    let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
    assert!(futures::poll!(&mut caller).is_pending());
    let (open, mut channel, agent) = channel(&peer, &session, &mut messages).await;
    block_server_writes(&mut channel, &agent).await;
    tokio::time::pause();
    let mut worker = Box::pin(serve_data(
        peer.clone(),
        session.clone(),
        channel,
        open,
        Instant::now() + Duration::from_secs(10),
    ));
    assert!(futures::poll!(&mut worker).is_pending());
    assert_eq!(peer.pending.count(), 1);
    drop(caller);
    timeout(Duration::from_millis(1), worker)
        .await
        .expect("caller cancellation waited for the blocked Open write")
        .unwrap();
    assert!(!session.stop.is_cancelled());
    assert_released(&peer);
}

#[tokio::test]
async fn ready_after_retirement_or_session_close_cannot_handoff() {
    for retire_generation in [true, false] {
        let (peer, session, mut messages) = harness(1);
        let p = peer.clone();
        let caller = tokio::spawn(async move {
            p.open("web", Instant::now() + Duration::from_secs(60))
                .await
        });
        tokio::task::yield_now().await;
        let (open, channel, mut agent) = channel(&peer, &session, &mut messages).await;
        let worker = tokio::spawn(serve_data(
            peer.clone(),
            session.clone(),
            channel,
            open,
            Instant::now() + Duration::from_secs(10),
        ));
        assert!(matches!(
            protocol::read(&mut agent).await.unwrap(),
            Message::Open { .. }
        ));
        if retire_generation {
            peer.gate.retire();
        } else {
            session.close();
        }
        protocol::write(&mut agent, &Message::Ready {})
            .await
            .unwrap();
        assert!(timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(caller.await.unwrap().is_err());
        assert_released(&peer);
    }
}

#[tokio::test(start_paused = true)]
async fn accept_errors_retry_with_backoff_until_recovery() {
    let start = Instant::now();
    let mut attempts = 0;
    let accepted = accept_retry(
        || {
            attempts += 1;
            std::future::ready(match attempts {
                1 => Err(io::Error::from_raw_os_error(24)),
                2 => Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
                _ => Ok(42),
            })
        },
        "0.0.0.0:7443".parse().unwrap(),
    )
    .await;
    assert_eq!(accepted, 42);
    assert_eq!(attempts, 3);
    assert_eq!(start.elapsed(), Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn retirement_interrupts_accept_backoff() {
    let gate = Arc::new(Gate::default());
    gate.activate();
    let server = Arc::new(Server {
        address: "0.0.0.0:0".parse().unwrap(),
        tls: Tls::new().server,
        gate: gate.clone(),
        endpoint: Arc::new(Endpoint::new(Arc::default(), Arc::default(), 16)),
        peers: HashMap::new(),
        identities: HashMap::new(),
        handshakes: Arc::default(),
        max_handshakes: 16,
    });
    let start = Instant::now();
    let attempts = std::cell::Cell::new(0);
    let run = server.accept_connections(|| {
        attempts.set(attempts.get() + 1);
        std::future::ready(Err(io::Error::from_raw_os_error(24)))
    });
    tokio::pin!(run);
    assert!(futures::poll!(&mut run).is_pending());
    assert_eq!(attempts.get(), 1);
    gate.retire();
    assert!(matches!(futures::poll!(&mut run), Poll::Ready(Ok(()))));
    assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn matching_pongs_keep_control_alive_and_wrong_nonces_are_rejected() {
    let (peer, session, mut messages) = harness(1);
    let (input, incoming) = tokio::sync::mpsc::channel(64);
    let mut pumps = Pumps {
        incoming,
        outgoing: session.writer.clone(),
        tasks: JoinSet::new(),
    };
    pumps.tasks.spawn(std::future::pending());
    {
        let control = run_control(&peer, &session, &mut pumps);
        tokio::pin!(control);
        assert!(futures::poll!(&mut control).is_pending());
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(20)).await;
            assert!(futures::poll!(&mut control).is_pending());
            let Message::Ping { nonce } = messages.try_recv().unwrap() else {
                panic!("expected heartbeat ping")
            };
            input.try_send(Message::Pong { nonce }).unwrap();
            assert!(futures::poll!(&mut control).is_pending());
        }
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(futures::poll!(&mut control).is_pending());
        let Message::Ping { nonce } = messages.try_recv().unwrap() else {
            panic!("expected heartbeat ping")
        };
        input
            .try_send(Message::Pong {
                nonce: nonce.wrapping_add(1),
            })
            .unwrap();
        assert!(matches!(futures::poll!(&mut control),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    }
    pumps.stop().await;
}

#[tokio::test(start_paused = true)]
async fn control_deadline_preempts_ready_input_and_keeps_one_outstanding_ping() {
    let (peer, session, mut messages) = harness(1);
    let (input, incoming) = tokio::sync::mpsc::channel(64);
    let mut pumps = Pumps {
        incoming,
        outgoing: session.writer.clone(),
        tasks: JoinSet::new(),
    };
    pumps.tasks.spawn(std::future::pending());
    {
        let control = run_control(&peer, &session, &mut pumps);
        tokio::pin!(control);
        assert!(futures::poll!(&mut control).is_pending());
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(futures::poll!(&mut control).is_pending());
        assert!(matches!(messages.try_recv().unwrap(), Message::Ping { .. }));
        for _ in 0..59 {
            while input
                .try_send(Message::CreateFailed {
                    channel_id: Id::new(),
                    code: Code::ConnectFailed,
                })
                .is_ok()
            {}
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(futures::poll!(&mut control).is_pending());
            assert!(
                messages.try_recv().is_err(),
                "a second ping preceded the first pong"
            );
        }
        while input
            .try_send(Message::CreateFailed {
                channel_id: Id::new(),
                code: Code::ConnectFailed,
            })
            .is_ok()
        {}
        tokio::time::advance(Duration::from_secs(1)).await;
        let Poll::Ready(Err(error)) = futures::poll!(&mut control) else {
            panic!("pong deadline postponed by control input")
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            input.capacity(),
            0,
            "input was processed past the pong deadline"
        );
    }
    pumps.stop().await;
}

#[tokio::test]
async fn authenticated_attachment_cannot_commit_after_retirement_or_replacement() {
    for retire_generation in [true, false] {
        let tls = Tls::new();
        let (peer, _, _) = harness(1);
        let (writer, mut messages) = tokio::sync::mpsc::channel(64);
        let session = Arc::new(Session::new(
            Id::new(),
            tls.fingerprint.clone(),
            HashSet::from(["web".into()]),
            writer,
        ));
        peer.install(session.clone()).unwrap();
        let p = peer.clone();
        let caller = tokio::spawn(async move {
            p.open("web", Instant::now() + Duration::from_secs(60))
                .await
        });
        tokio::task::yield_now().await;
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        let server = hub(&peer, &tls);
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", listener.local_addr().unwrap().port()))
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let s = server.clone();
        let worker = tokio::spawn(async move {
            let permit = s.endpoint.accept().unwrap();
            let handshake = s.handshakes.acquire(s.max_handshakes).unwrap();
            s.connection(accepted, permit, handshake).await
        });
        let mut agent = tls
            .connector
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();
        // Pause after authentication, before the first metadata frame.
        timeout(Duration::from_secs(1), async {
            while server.handshakes.count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        if retire_generation {
            peer.gate.retire();
        } else {
            let (writer, _rx) = tokio::sync::mpsc::channel(64);
            peer.install(Arc::new(Session::new(
                Id::new(),
                vec![1],
                HashSet::new(),
                writer,
            )))
            .unwrap();
        }
        protocol::write(
            &mut agent,
            &Message::DataHello {
                version: protocol::VERSION,
                peer: "home".into(),
                session_id: session.id.clone(),
                channel_id,
            },
        )
        .await
        .unwrap();
        assert!(timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(protocol::read(&mut agent).await.is_err());
        session.close();
        assert!(caller.await.unwrap().is_err());
        assert_released(&peer);
    }
}

#[tokio::test]
async fn authenticated_control_replacement_closes_old_demand_and_preserves_new_session() {
    async fn register(
        tls: &Tls,
        address: SocketAddr,
    ) -> (tokio_rustls::client::TlsStream<TcpStream>, Id) {
        timeout(Duration::from_secs(5), async {
            let tcp = TcpStream::connect(address).await.unwrap();
            let mut agent = tls
                .connector
                .connect("localhost".try_into().unwrap(), tcp)
                .await
                .unwrap();
            protocol::write(
                &mut agent,
                &Message::ControlHello {
                    version: protocol::VERSION,
                    peer: "home".into(),
                    services: vec!["web".into()],
                },
            )
            .await
            .unwrap();
            let Message::ControlReady {
                session_id,
                services,
            } = protocol::read(&mut agent).await.unwrap()
            else {
                panic!("expected control registration");
            };
            assert_eq!(services, ["web"]);
            (agent, session_id)
        })
        .await
        .unwrap()
    }

    let tls = Tls::new();
    let (peer, _, _) = harness(1);
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = (
        std::net::Ipv4Addr::LOCALHOST,
        listener.local_addr().unwrap().port(),
    )
        .into();
    let server = hub(&peer, &tls);
    let worker = tokio::spawn(async move { server.accept_connections(|| listener.accept()).await });
    let (mut old_control, old_id) = register(&tls, address).await;
    let old_session = timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(session) = peer.session(&old_id) {
                break session;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut old_caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
    assert!(futures::poll!(&mut old_caller).is_pending());
    assert!(matches!(
        timeout(Duration::from_secs(1), protocol::read(&mut old_control))
            .await
            .unwrap()
            .unwrap(),
        Message::CreateData { .. }
    ));
    let (mut new_control, new_id) = register(&tls, address).await;
    assert_ne!(old_id, new_id);
    assert!(
        timeout(Duration::from_secs(1), protocol::read(&mut old_control))
            .await
            .unwrap()
            .is_err()
    );
    assert!(timeout(Duration::from_secs(1), old_caller)
        .await
        .unwrap()
        .is_err());
    assert!(old_session.stop.is_cancelled());
    assert!(peer.session(&old_id).is_err());
    assert!(!peer.session(&new_id).unwrap().stop.is_cancelled());
    let mut new_caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
    assert!(futures::poll!(&mut new_caller).is_pending());
    assert!(matches!(
        timeout(Duration::from_secs(1), protocol::read(&mut new_control))
            .await
            .unwrap()
            .unwrap(),
        Message::CreateData { .. }
    ));
    drop(new_caller);
    peer.gate.retire();
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_released(&peer);
}

#[tokio::test]
async fn silent_ingress_expires_before_and_after_tls_and_releases_capacity() {
    for authenticated in [false, true] {
        let tls = Tls::new();
        let (peer, _, _) = harness(1);
        let server = hub(&peer, &tls);
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let (tcp, accepted) = timeout(Duration::from_secs(5), async {
            let tcp = TcpStream::connect(("127.0.0.1", listener.local_addr().unwrap().port()))
                .await
                .unwrap();
            (tcp, listener.accept().await.unwrap().0)
        })
        .await
        .unwrap();
        let permit = server.endpoint.accept().unwrap();
        let handshake = server.handshakes.acquire(server.max_handshakes).unwrap();
        let s = server.clone();
        let started = Instant::now();
        let mut worker =
            tokio::spawn(async move { s.connection(accepted, permit, handshake).await });
        let _agent: Box<dyn crate::async_stream::AsyncStream> = if authenticated {
            let agent = timeout(
                Duration::from_secs(5),
                tls.connector.connect("localhost".try_into().unwrap(), tcp),
            )
            .await
            .unwrap()
            .unwrap();
            timeout(Duration::from_secs(1), async {
                while server.handshakes.count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            Box::new(agent)
        } else {
            Box::new(tcp)
        };
        tokio::time::pause();
        let before_expiry = Duration::from_secs(if authenticated { 9 } else { 2 });
        assert!(timeout_at(started + before_expiry, &mut worker)
            .await
            .is_err());
        assert_eq!(peer.endpoint.accepted.count(), 1);
        assert_eq!(server.handshakes.count(), usize::from(!authenticated));
        let result = timeout_at(started + before_expiry + Duration::from_secs(2), worker)
            .await
            .expect("silent ingress did not expire")
            .unwrap();
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(server.handshakes.count(), 0);
        assert_released(&peer);
        tokio::time::resume();
    }
}

#[tokio::test]
async fn admission_rejection_preserves_demand_and_recovers_after_capacity_is_released() {
    use tokio::io::AsyncWriteExt;
    for handshake_limit in [false, true] {
        let tls = Tls::new();
        let (mut peer, _, _) = harness(1);
        Arc::get_mut(&mut peer).unwrap().endpoint =
            Arc::new(Endpoint::new(Arc::default(), Arc::default(), 2));
        let mut server = hub(&peer, &tls);
        Arc::get_mut(&mut server).unwrap().max_handshakes = 1;
        let (writer, mut messages) = tokio::sync::mpsc::channel(64);
        let session = Arc::new(Session::new(
            Id::new(),
            tls.fingerprint.clone(),
            HashSet::from(["web".into()]),
            writer,
        ));
        peer.install(session.clone()).unwrap();
        let control_permit = peer.endpoint.accept().unwrap();
        let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
        assert!(futures::poll!(&mut caller).is_pending());
        session.request_data(&peer).unwrap();
        let rejected_id = expect_create_data(&mut messages);
        let pressure = if handshake_limit {
            server.handshakes.acquire(server.max_handshakes).unwrap()
        } else {
            peer.endpoint.accept().unwrap()
        };
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ("127.0.0.1", listener.local_addr().unwrap().port());
        let s = server.clone();
        let worker = tokio::spawn(async move { s.accept_connections(|| listener.accept()).await });
        let rejected = timeout(Duration::from_secs(2), async {
            let tcp = TcpStream::connect(address).await.unwrap();
            tls.connector
                .connect("localhost".try_into().unwrap(), tcp)
                .await
        })
        .await
        .expect("capacity rejection did not close the carrier");
        assert!(rejected.is_err());
        assert_eq!(
            peer.endpoint.accepted.count(),
            if handshake_limit { 1 } else { 2 }
        );
        assert_eq!(server.handshakes.count(), usize::from(handshake_limit));
        assert_eq!(peer.physical.count(), 1);
        assert_eq!(peer.endpoint.credits.count(), 1);
        assert!(!session.stop.is_cancelled());
        session.failed(&rejected_id, &peer);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
        assert_eq!(peer.active.count(), 1);
        assert_eq!(peer.pending.count(), 1);
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
        drop(pressure);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        assert_ne!(channel_id, rejected_id);
        tokio::time::resume();
        let mut agent = timeout(Duration::from_secs(5), async {
            let tcp = TcpStream::connect(address).await.unwrap();
            let mut agent = tls
                .connector
                .connect("localhost".try_into().unwrap(), tcp)
                .await
                .unwrap();
            protocol::write(
                &mut agent,
                &Message::DataHello {
                    version: protocol::VERSION,
                    peer: "home".into(),
                    session_id: session.id.clone(),
                    channel_id,
                },
            )
            .await
            .unwrap();
            let Message::Open { service, .. } = protocol::read(&mut agent).await.unwrap() else {
                panic!("expected Open");
            };
            assert_eq!(service, "web");
            protocol::write(&mut agent, &Message::Ready {})
                .await
                .unwrap();
            agent
        })
        .await
        .expect("listener did not recover after admission pressure");
        let mut stream = timeout(Duration::from_secs(2), caller)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.active.count(), 1);
        assert_eq!(peer.endpoint.accepted.count(), 2);
        assert_eq!(server.handshakes.count(), 0);
        agent.write_all(b"recovered").await.unwrap();
        let mut bytes = [0; 9];
        timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"recovered");
        drop((stream, agent, control_permit));
        assert!(!session.stop.is_cancelled());
        peer.gate.retire();
        timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        session.close();
        assert_released(&peer);
    }
}

#[tokio::test]
async fn stalled_origin_tls_uses_the_remaining_tunnel_setup_budget() {
    let (peer, session, mut messages) = harness(1);
    let location: crate::config::TcpTargetLocation = serde_json::from_value(serde_json::json!({
        "tunnel": {"server": "edge", "peer": "home", "service": "web"},
        "client_tls": {"verify": false, "sni_hostname": "localhost"}
    }))
    .unwrap();
    let mut target = crate::tcp::TargetLocationData::try_from(location).unwrap();
    target.tunnel = Some(super::super::Binding {
        peer: peer.clone(),
        service: "web".into(),
    });
    let mut setup = tokio::spawn(async move {
        crate::tcp::setup_target_stream(&"127.0.0.1:1".parse().unwrap(), &target, true, None).await
    });
    timeout(Duration::from_secs(2), async {
        while peer.pending.count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (open, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    let deadline = open.deadline;
    let worker = tokio::spawn(serve_data(
        peer.clone(),
        session.clone(),
        channel,
        open,
        deadline,
    ));
    assert!(matches!(
        timeout(Duration::from_secs(2), protocol::read(&mut agent))
            .await
            .unwrap()
            .unwrap(),
        Message::Open { .. }
    ));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::time::resume();
    protocol::write(&mut agent, &Message::Ready {})
        .await
        .unwrap();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut header = [0; 5];
    timeout(Duration::from_secs(2), agent.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(header[0], 22, "expected the inner TLS ClientHello");
    assert_eq!(peer.pending.count(), 0);
    assert_eq!(peer.active.count(), 1);
    tokio::time::pause();
    assert!(timeout_at(deadline - Duration::from_secs(1), &mut setup)
        .await
        .is_err());
    let result = timeout_at(deadline + Duration::from_millis(1), setup)
        .await
        .expect("origin TLS restarted or escaped the tunnel setup deadline")
        .unwrap();
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    assert_released(&peer);
}
