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
    use tokio::io::AsyncWriteExt;
    let (peer, session, mut messages) = harness(1);
    let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
    assert!(futures::poll!(&mut caller).is_pending());
    let (open, mut channel, agent) = channel(&peer, &session, &mut messages).await;
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
        let server = Arc::new(Server {
            address: "0.0.0.0:0".parse().unwrap(),
            tls: tls.server,
            gate: peer.gate.clone(),
            endpoint: peer.endpoint.clone(),
            peers: HashMap::from([("home".into(), peer.clone())]),
            identities: HashMap::from([(tls.fingerprint, "home".into())]),
            handshakes: Arc::default(),
            max_handshakes: 16,
        });
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", listener.local_addr().unwrap().port()))
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let s = server.clone();
        let worker = tokio::spawn(async move {
            let permit = s.endpoint.accept().unwrap();
            let handshake = s.handshakes.acquire(16).unwrap();
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
