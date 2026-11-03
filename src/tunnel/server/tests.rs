use super::super::test_support::{harness, Tls};
use super::*;
use tokio::io::AsyncReadExt;

async fn channel(
    peer: &Peer,
    session: &Arc<Session>,
    messages: &mut tokio::sync::mpsc::Receiver<Message>,
) -> (Idle, Channel, tokio_rustls::client::TlsStream<TcpStream>) {
    let (io, client) = Tls::new().pair().await;
    session.refill(peer).unwrap();
    let Message::CreateData { channel_id } = messages.recv().await.unwrap() else {
        panic!("expected creation credit")
    };
    let accepted = peer.endpoint.accept().unwrap();
    let credit = session.attach(&channel_id, &[1], peer).unwrap();
    drop(credit._endpoint);
    (
        Idle::new(session.clone()),
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
    let (peer, session, mut messages) = harness(1, 0);
    let p = peer.clone();
    let caller = tokio::spawn(async move {
        p.open("web", Instant::now() + Duration::from_secs(60))
            .await
    });
    tokio::task::yield_now().await;
    let (idle, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    let worker = tokio::spawn(serve_data(peer.clone(), idle, channel));
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
async fn idle_channel_shrinks_when_its_queued_caller_cancels() {
    let (peer, session, mut messages) = harness(1, 0);
    let p = peer.clone();
    let caller = tokio::spawn(async move {
        p.open("web", Instant::now() + Duration::from_secs(60))
            .await
    });
    tokio::task::yield_now().await;
    let (idle, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    caller.abort();
    let _ = caller.await;
    assert!(serve_data(peer.clone(), idle, channel).await.is_err());
    assert_eq!(session.state.lock().as_ref().unwrap().idle, 0);
    let closed = agent.read(&mut [0]).await;
    assert!(closed.is_err() || closed.unwrap() == 0);
    assert_released(&peer);
}

#[tokio::test]
async fn ready_after_retirement_or_session_close_cannot_handoff() {
    for retire_generation in [true, false] {
        let (peer, session, mut messages) = harness(1, 0);
        let p = peer.clone();
        let caller = tokio::spawn(async move {
            p.open("web", Instant::now() + Duration::from_secs(60))
                .await
        });
        tokio::task::yield_now().await;
        let (idle, channel, mut agent) = channel(&peer, &session, &mut messages).await;
        let worker = tokio::spawn(serve_data(peer.clone(), idle, channel));
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
    let gate = Gate::default();
    gate.activate();
    let start = Instant::now();
    let accept = accept_retry(
        || {
            gate.retire();
            std::future::ready(Err::<(), _>(io::Error::from_raw_os_error(24)))
        },
        "0.0.0.0:7443".parse().unwrap(),
    );
    tokio::select! {
        biased;
        _ = accept => panic!("failed accept cannot succeed"),
        _ = gate.stop.wait() => {},
    }
    assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn control_deadline_preempts_ready_input_and_keeps_one_outstanding_ping() {
    let (peer, session, mut messages) = harness(1, 0);
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
async fn idle_channel_pings_at_twenty_seconds_and_closes_after_ten_without_pong() {
    let (peer, session, mut messages) = harness(1, 1);
    let (idle, channel, mut agent) = channel(&peer, &session, &mut messages).await;
    let worker = tokio::spawn(serve_data(peer.clone(), idle, channel));
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(19)).await;
    assert!(!worker.is_finished());
    assert!(futures::poll!(std::pin::pin!(agent.read(&mut [0]))).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::time::resume();
    assert!(matches!(
        timeout(Duration::from_secs(1), protocol::read(&mut agent))
            .await
            .unwrap()
            .unwrap(),
        Message::Ping { .. }
    ));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(!worker.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        worker.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(session.state.lock().as_ref().unwrap().idle, 0);
    assert_released(&peer);
}

#[tokio::test]
async fn authenticated_attachment_cannot_commit_after_retirement_or_replacement() {
    for retire_generation in [true, false] {
        let tls = Tls::new();
        let (peer, _, _) = harness(1, 1);
        let (writer, mut messages) = tokio::sync::mpsc::channel(64);
        let session = Arc::new(Session::new(
            Id::new(),
            tls.fingerprint.clone(),
            HashSet::from(["web".into()]),
            writer,
        ));
        peer.install(session.clone()).unwrap();
        session.refill(&peer).unwrap();
        let Message::CreateData { channel_id } = messages.recv().await.unwrap() else {
            panic!()
        };
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
                version: 1,
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
        assert_released(&peer);
    }
}
