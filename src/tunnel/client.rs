use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Duration, Instant};

use super::control::Pumps;
use super::dns::Resolver;
use super::protocol::{self, invalid, Code, Id, Message};
use super::state::{timed_out, unavailable, Counter, Gate, Permit, Stop};
use super::tls;
use crate::async_stream::AsyncStream;
use crate::config::{tunnel::TunnelClientConfig, Location};

type ClientIo = tokio_rustls::client::TlsStream<TcpStream>;

pub struct Client {
    pub config: TunnelClientConfig,
    pub connector: tokio_rustls::TlsConnector,
    pub gate: Arc<Gate>,
    pub resolver: Resolver,
    pub active: Arc<Counter>,
    pub sockets: Arc<Counter>,
    pub local_dials: Arc<Counter>,
    pub data_dial_slots: Arc<Semaphore>,
    pub data_setup_jobs: Arc<Counter>,
}

struct Control {
    io: ClientIo,
    address: SocketAddr,
    session: Id,
    accepted_services: HashSet<String>,
}

struct Work {
    address: SocketAddr,
    session: Id,
    channel: Id,
    accepted_services: Arc<HashSet<String>>,
    stop: Stop,
    writer: tokio::sync::mpsc::Sender<Message>,
    socket: Permit,
    job: Permit,
    deadline: Instant,
}

impl Client {
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let mut data = JoinSet::new();
        let mut failures = 0u32;
        while !self.gate.stop.is_cancelled() {
            let result = tokio::select! {
                biased;
                _ = self.gate.stop.wait() => break,
                result = timeout(Duration::from_secs(10), self.connect_control()) => {
                    result.map_err(|_| timed_out()).and_then(|result| result)
                },
            };
            let connected_for = match result {
                Ok(control) => {
                    let connected_at = Instant::now();
                    log::info!("Tunnel client {} registered", self.config.tunnel_client);
                    if let Err(error) = self.session(control, &mut data).await {
                        log::warn!(
                            "Tunnel client {} disconnected: {error}",
                            self.config.tunnel_client
                        );
                    }
                    Some(connected_at.elapsed())
                }
                Err(error) => {
                    log::warn!(
                        "Tunnel client {} connection failed: {error}",
                        self.config.tunnel_client
                    );
                    None
                }
            };
            let delay = reconnect_delay(&mut failures, connected_for);
            tokio::select! {
                _ = self.gate.stop.wait() => break,
                _ = tokio::time::sleep(delay) => {},
            }
            while let Some(result) = data.try_join_next() {
                report_child(result);
            }
        }
        data.shutdown().await;
        Ok(())
    }

    async fn dial(&self, address: SocketAddr) -> io::Result<ClientIo> {
        drop(self.gate.enter()?);
        let stream = TcpStream::connect(address).await?;
        tls::socket_options(&stream)?;
        let name = rustls::pki_types::ServerName::try_from(self.config.server_name().to_owned())
            .map_err(|_| invalid())?;
        let stream = self
            .connector
            .connect_with(name, stream, |connection| {
                connection.set_buffer_limit(Some(32768))
            })
            .await?;
        tls::require_alpn(stream.get_ref().1.alpn_protocol())?;
        Ok(stream)
    }

    async fn connect_control(&self) -> io::Result<Control> {
        let address = self
            .resolver
            .resolve(&self.config.server.address, self.config.server.port)
            .await?;
        let mut io = self.dial(address).await?;
        let mut services: Vec<_> = self.config.services.keys().cloned().collect();
        services.sort();
        protocol::write(
            &mut io,
            &Message::ControlHello {
                version: protocol::VERSION,
                peer: self.config.tunnel_client.clone(),
                services,
            },
        )
        .await?;
        let Message::ControlReady {
            session_id,
            services: accepted_services,
        } = protocol::read(&mut io).await?
        else {
            return Err(invalid());
        };
        if accepted_services
            .iter()
            .any(|name| !self.config.services.contains_key(name))
        {
            return Err(invalid());
        }
        if accepted_services.len() != self.config.services.len() {
            log::warn!(
                "Tunnel client {} has exports not accepted by the hub",
                self.config.tunnel_client
            );
        }
        Ok(Control {
            io,
            address,
            session: session_id,
            accepted_services: accepted_services.into_iter().collect(),
        })
    }

    async fn session(self: &Arc<Self>, control: Control, data: &mut JoinSet<()>) -> io::Result<()> {
        let mut pumps = Pumps::new(control.io, Some(Duration::from_secs(60)));
        let stop = Stop::default();
        let accepted_services = Arc::new(control.accepted_services);
        let result = loop {
            tokio::select! {
                biased;
                _ = self.gate.stop.wait() => break Ok(()),
                _ = stop.wait() => break Err(unavailable()),
                _ = pumps.tasks.join_next() => break Err(unavailable()),
                result = data.join_next(), if !data.is_empty() => {
                    if let Some(result) = result {
                        report_child(result);
                    }
                },
                message = pumps.incoming.recv() => match message {
                    Some(Message::Ping { nonce }) => {
                        if let Err(error) = pumps.send(Message::Pong { nonce }) {
                            break Err(error);
                        }
                    }
                    Some(Message::CreateData { channel_id }) => {
                        let Ok((socket, job)) = self.reserve_data_channel() else {
                            if let Err(error) = pumps.send(Message::CreateFailed {
                                channel_id,
                                code: Code::Busy,
                            }) {
                                break Err(error);
                            }
                            continue;
                        };
                        let client = self.clone();
                        let work = Work {
                            address: control.address,
                            session: control.session.clone(),
                            channel: channel_id,
                            accepted_services: accepted_services.clone(),
                            stop: stop.clone(),
                            writer: pumps.outgoing.clone(),
                            socket,
                            job,
                            deadline: Instant::now() + Duration::from_secs(10),
                        };
                        data.spawn(async move {
                            client.data(work).await;
                        });
                    }
                    _ => break Err(invalid()),
                },
            }
        };
        stop.cancel();
        pumps.stop().await;
        result
    }

    fn reserve_data_channel(&self) -> io::Result<(Permit, Permit)> {
        let socket = self.sockets.acquire(self.config.max_data_connections)?;
        let job = self.data_setup_jobs.acquire(8)?;
        Ok((socket, job))
    }

    async fn attach_data(
        &self,
        address: SocketAddr,
        session: Id,
        channel: &Id,
        job: Permit,
    ) -> io::Result<(ClientIo, String, u32)> {
        let dial = self
            .data_dial_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let mut stream = self.dial(address).await?;
        protocol::write(
            &mut stream,
            &Message::DataHello {
                version: protocol::VERSION,
                peer: self.config.tunnel_client.clone(),
                session_id: session,
                channel_id: channel.clone(),
            },
        )
        .await?;
        drop(dial);
        drop(job);
        match protocol::read(&mut stream).await? {
            Message::Open { service, budget_ms } => Ok((stream, service, budget_ms)),
            _ => Err(invalid()),
        }
    }

    async fn connect_export(
        &self,
        service: &str,
        accepted_services: &HashSet<String>,
    ) -> io::Result<(Box<dyn AsyncStream>, Permit)> {
        if !accepted_services.contains(service) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unaccepted tunnel service",
            ));
        }
        let export = self.config.services.get(service).ok_or_else(unavailable)?;
        let active = self.active.acquire(self.config.max_active_connections)?;
        let dial = self
            .local_dials
            .acquire(self.config.max_concurrent_local_dials)?;
        let (location, _) = export.location.clone().into_components();
        let backend: Box<dyn AsyncStream> = match location {
            Location::Address(address) => {
                let address = self
                    .resolver
                    .resolve(&address.address, address.port)
                    .await?;
                drop(self.gate.enter()?);
                Box::new(TcpStream::connect(address).await?)
            }
            Location::Path(path) => Box::new(UnixStream::connect(path).await?),
            Location::Tunnel(_) => return Err(invalid()),
        };
        drop(dial);
        Ok((backend, active))
    }

    async fn answer_open(
        &self,
        mut stream: ClientIo,
        service: &str,
        budget_ms: u32,
        accepted_services: &HashSet<String>,
    ) -> io::Result<(ClientIo, Box<dyn AsyncStream>, Permit)> {
        let connecting = self.connect_export(service, accepted_services);
        let open_deadline =
            Instant::now() + Duration::from_millis(u64::from(budget_ms.min(10_000)));
        let mut byte = [0];
        let result = tokio::select! {
            result = timeout_at(open_deadline, connecting) => {
                result.map_err(|_| timed_out()).and_then(|result| result)
            },
            _ = stream.read(&mut byte) => return Err(unavailable()),
        };
        let (backend, active) = match result {
            Ok(value) => value,
            Err(error) => {
                let code = match error.kind() {
                    io::ErrorKind::WouldBlock => Code::Busy,
                    io::ErrorKind::TimedOut => Code::Timeout,
                    io::ErrorKind::PermissionDenied => Code::Unauthorized,
                    _ => Code::ConnectFailed,
                };
                let _ = timeout(
                    Duration::from_secs(1),
                    protocol::write(&mut stream, &Message::OpenFailed { code }),
                )
                .await;
                return Err(error);
            }
        };
        timeout_at(
            open_deadline,
            protocol::write(&mut stream, &Message::Ready {}),
        )
        .await
        .map_err(|_| timed_out())??;
        Ok((stream, backend, active))
    }

    async fn data(&self, work: Work) {
        let Work {
            address,
            session,
            channel,
            accepted_services,
            stop,
            writer,
            socket,
            job,
            deadline: attach_deadline,
        } = work;
        let _socket = socket;
        let mut attached = false;
        let setup = async {
            let (stream, service, budget_ms) = timeout_at(
                attach_deadline,
                self.attach_data(address, session, &channel, job),
            )
            .await
            .map_err(|_| timed_out())??;
            attached = true;
            self.answer_open(stream, &service, budget_ms, &accepted_services)
                .await
        };
        let result = tokio::select! {
            biased;
            _ = stop.wait() => return,
            result = setup => result,
        };
        let (mut stream, mut backend, _active) = match result {
            Ok(streams) => streams,
            Err(error) => {
                log::debug!("Tunnel data setup failed: {error}");
                if !attached
                    && writer
                        .try_send(Message::CreateFailed {
                            channel_id: channel,
                            code: Code::ConnectFailed,
                        })
                        .is_err()
                {
                    stop.cancel();
                }
                return;
            }
        };
        if let Err(error) =
            crate::copy_bidirectional::copy_bidirectional(&mut stream, &mut *backend, false, false)
                .await
        {
            log::debug!("Tunnel local copy ended: {error}");
        }
    }
}

fn reconnect_delay(failures: &mut u32, connected_for: Option<Duration>) -> Duration {
    if connected_for.is_some_and(|duration| duration >= Duration::from_secs(60)) {
        *failures = 0;
    }
    let cap = (1u64 << (*failures).min(6)).min(60);
    *failures = failures.saturating_add(1);
    Duration::from_millis(rand::random_range(
        (cap * 500).max(1000)..=(cap * 1000).max(1000),
    ))
}

fn report_child(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        log::warn!("Tunnel client task failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::Tls;
    use super::*;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    async fn harness() -> (Arc<Client>, TcpListener, Tls) {
        let tls = Tls::new();
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let config = serde_json::from_value(serde_json::json!({
            "tunnel_client":"home", "server":address,
            "client_tls":{"cert":"unused", "key":"unused", "sni_hostname":"localhost"},
            "services":{"web":{"location":"localhost:1"}}
        }))
        .unwrap();
        let gate = Arc::new(Gate::default());
        gate.activate();
        (
            Arc::new(Client {
                config,
                connector: tls.connector.clone(),
                gate,
                resolver: Resolver::default(),
                active: Arc::default(),
                sockets: Arc::default(),
                local_dials: Arc::default(),
                data_dial_slots: Arc::new(Semaphore::new(4)),
                data_setup_jobs: Arc::default(),
            }),
            listener,
            tls,
        )
    }

    #[tokio::test]
    async fn dial_rejects_a_hub_that_does_not_negotiate_alpn() {
        let (client, listener, mut tls) = harness().await;
        Arc::get_mut(&mut tls.server)
            .unwrap()
            .alpn_protocols
            .clear();
        let address = (
            std::net::Ipv4Addr::LOCALHOST,
            listener.local_addr().unwrap().port(),
        )
            .into();
        let (server, agent) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let (socket, _) = listener.accept().await.unwrap();
                    tokio_rustls::TlsAcceptor::from(tls.server)
                        .accept(socket)
                        .await
                },
                client.dial(address),
            )
        })
        .await
        .unwrap();
        assert!(server.is_ok(), "TLS itself must succeed without ALPN");
        assert!(matches!(agent, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[tokio::test(start_paused = true)]
    async fn occupied_data_dial_slots_do_not_extend_the_work_deadline() {
        let (client, listener, _tls) = harness().await;
        let slots = client
            .data_dial_slots
            .clone()
            .acquire_many_owned(4)
            .await
            .unwrap();
        let (writer, mut messages) = mpsc::channel(1);
        let stop = Stop::default();
        let channel = Id::new();
        let work = Work {
            address: (
                std::net::Ipv4Addr::LOCALHOST,
                listener.local_addr().unwrap().port(),
            )
                .into(),
            session: Id::new(),
            channel: channel.clone(),
            accepted_services: Arc::new(HashSet::from(["web".into()])),
            stop: stop.clone(),
            writer,
            socket: client.sockets.acquire(256).unwrap(),
            job: client.data_setup_jobs.acquire(8).unwrap(),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let mut task = Box::pin(client.data(work));
        assert!(futures::poll!(&mut task).is_pending());
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(futures::poll!(&mut task).is_pending());
        assert_eq!(client.sockets.count(), 1);
        assert_eq!(client.data_setup_jobs.count(), 1);
        assert_eq!(client.local_dials.count(), 0);
        assert_eq!(client.active.count(), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        timeout(Duration::from_millis(1), task).await.unwrap();
        assert!(matches!(messages.try_recv().unwrap(),
            Message::CreateFailed { channel_id, .. } if channel_id == channel));
        assert!(!stop.is_cancelled());
        assert_eq!(client.sockets.count(), 0);
        assert_eq!(client.data_setup_jobs.count(), 0);
        assert_eq!(client.data_dial_slots.available_permits(), 0);
        drop(slots);
        assert_eq!(client.data_dial_slots.available_permits(), 4);
    }

    // Requires a running clock; paused time can expire before socket I/O completes.
    async fn start_data(
        client: &Arc<Client>,
        listener: &TcpListener,
        tls: &Tls,
        full_writer: bool,
        deadline: Instant,
    ) -> (
        tokio::task::JoinHandle<()>,
        super::super::stream::ServerIo,
        Stop,
        mpsc::Receiver<Message>,
    ) {
        let (writer, receiver) = mpsc::channel(1);
        if full_writer {
            writer.try_send(Message::Pong { nonce: 7 }).unwrap();
        }
        let stop = Stop::default();
        let work = Work {
            address: (
                std::net::Ipv4Addr::LOCALHOST,
                listener.local_addr().unwrap().port(),
            )
                .into(),
            session: Id::new(),
            channel: Id::new(),
            accepted_services: Arc::new(HashSet::from(["web".into()])),
            stop: stop.clone(),
            writer,
            socket: client.sockets.acquire(256).unwrap(),
            job: client.data_setup_jobs.acquire(8).unwrap(),
            deadline,
        };
        let c = client.clone();
        let task = tokio::spawn(async move {
            c.data(work).await;
        });
        let stream = timeout(Duration::from_secs(5), async {
            let (socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(tls.server.clone())
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(tls::identity(stream.get_ref().1).unwrap(), tls.fingerprint);
            assert!(matches!(
                protocol::read(&mut stream).await.unwrap(),
                Message::DataHello { .. }
            ));
            stream
        })
        .await
        .expect("data-channel TLS and DataHello setup timed out");
        (task, stream, stop, receiver)
    }

    #[tokio::test]
    async fn exhausted_data_limits_report_busy_without_leaking_permits() {
        for sockets_full in [true, false] {
            let (mut client, listener, tls) = harness().await;
            Arc::get_mut(&mut client)
                .unwrap()
                .config
                .max_data_connections = 1;
            let held: Vec<_> = if sockets_full {
                vec![client.sockets.acquire(1).unwrap()]
            } else {
                (0..8)
                    .map(|_| client.data_setup_jobs.acquire(8).unwrap())
                    .collect()
            };
            let (mut hub, agent) = timeout(Duration::from_secs(5), tls.pair()).await.unwrap();
            let control = Control {
                io: agent,
                address: listener.local_addr().unwrap(),
                session: Id::new(),
                accepted_services: HashSet::from(["web".into()]),
            };
            let c = client.clone();
            let task = tokio::spawn(async move {
                let mut data = JoinSet::new();
                let result = c.session(control, &mut data).await;
                assert!(data.is_empty());
                result
            });
            let channel_id = Id::new();
            timeout(
                Duration::from_secs(1),
                protocol::write(
                    &mut hub,
                    &Message::CreateData {
                        channel_id: channel_id.clone(),
                    },
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(
                timeout(Duration::from_secs(1), protocol::read(&mut hub))
                    .await
                    .unwrap()
                    .unwrap(),
                Message::CreateFailed { channel_id: failed, code: Code::Busy }
                    if failed == channel_id
            ));
            assert_eq!(client.sockets.count(), usize::from(sockets_full));
            assert_eq!(
                client.data_setup_jobs.count(),
                if sockets_full { 0 } else { 8 }
            );
            timeout(
                Duration::from_secs(1),
                protocol::write(&mut hub, &Message::Ping { nonce: 11 }),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(
                timeout(Duration::from_secs(1), protocol::read(&mut hub))
                    .await
                    .unwrap()
                    .unwrap(),
                Message::Pong { nonce: 11 }
            ));
            client.gate.retire();
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            drop(held);
            assert_eq!(client.sockets.count(), 0);
            assert_eq!(client.data_setup_jobs.count(), 0);
        }
    }

    #[tokio::test]
    async fn attached_failures_do_not_send_create_failed_or_stop_control() {
        let (client, listener, tls) = harness().await;
        for full_writer in [false, true] {
            let (task, mut stream, stop, mut messages) = start_data(
                &client,
                &listener,
                &tls,
                full_writer,
                Instant::now() + Duration::from_secs(10),
            )
            .await;
            protocol::write(
                &mut stream,
                &Message::Open {
                    service: "unauthorized".into(),
                    budget_ms: 30_000,
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                protocol::read(&mut stream).await.unwrap(),
                Message::OpenFailed {
                    code: Code::Unauthorized
                }
            ));
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert!(!stop.is_cancelled());
            if full_writer {
                assert!(matches!(
                    messages.try_recv().unwrap(),
                    Message::Pong { nonce: 7 }
                ));
            }
            assert!(messages.try_recv().is_err());
            assert_eq!(client.sockets.count(), 0);
            assert_eq!(client.data_setup_jobs.count(), 0);
        }
    }

    #[tokio::test]
    async fn preattachment_failures_still_notify_control_or_stop_on_overflow() {
        let (client, listener, tls) = harness().await;
        for full_writer in [false, true] {
            for message in [
                Some(Message::Ready {}),
                Some(Message::Ping { nonce: 1 }),
                Some(Message::Pong { nonce: 1 }),
                None,
            ] {
                let (task, mut stream, stop, mut messages) = start_data(
                    &client,
                    &listener,
                    &tls,
                    full_writer,
                    Instant::now() + Duration::from_secs(10),
                )
                .await;
                if let Some(message) = message {
                    protocol::write(&mut stream, &message).await.unwrap();
                } else {
                    drop(stream);
                }
                timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(stop.is_cancelled(), full_writer);
                if !full_writer {
                    assert!(matches!(
                        messages.try_recv().unwrap(),
                        Message::CreateFailed { .. }
                    ));
                }
            }
        }
    }

    #[tokio::test]
    async fn flushed_data_hello_releases_dial_slots_before_open() {
        let (client, listener, tls) = harness().await;
        let mut pending = Vec::new();
        for _ in 0..5 {
            pending.push(
                start_data(
                    &client,
                    &listener,
                    &tls,
                    false,
                    Instant::now() + Duration::from_secs(10),
                )
                .await,
            );
            assert_eq!(client.data_dial_slots.available_permits(), 4);
            assert_eq!(client.data_setup_jobs.count(), 0);
        }
        assert_eq!(client.sockets.count(), 5);
        for (task, stream, stop, _) in pending {
            stop.cancel();
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            drop(stream);
        }
        assert_eq!(client.sockets.count(), 0);
    }

    #[test]
    fn reconnect_backoff_is_bounded_and_resets_only_after_a_stable_session() {
        let mut failures = 0;
        for exponent in 0..100 {
            let cap = (1u64 << exponent.min(6)).min(60);
            let delay = reconnect_delay(&mut failures, Some(Duration::from_secs(59)));
            assert!(delay >= Duration::from_millis((cap * 500).max(1000)));
            assert!(delay <= Duration::from_secs(cap));
        }
        assert_eq!(
            reconnect_delay(&mut failures, Some(Duration::from_secs(60))),
            Duration::from_secs(1)
        );
        assert_eq!(failures, 1);
        failures = u32::MAX;
        assert!(reconnect_delay(&mut failures, None) <= Duration::from_secs(60));
        assert_eq!(failures, u32::MAX);
    }

    #[tokio::test]
    async fn missing_open_expires_within_the_original_attachment_deadline() {
        let (client, listener, tls) = harness().await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let (task, _stream, stop, mut messages) =
            start_data(&client, &listener, &tls, false, deadline).await;
        tokio::time::pause();
        tokio::time::advance(deadline.saturating_duration_since(Instant::now()) / 2).await;
        assert!(!task.is_finished());
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        timeout(Duration::from_millis(1), task)
            .await
            .expect("attachment restarted its deadline while waiting for Open")
            .unwrap();
        assert!(!stop.is_cancelled());
        assert!(matches!(
            messages.try_recv().unwrap(),
            Message::CreateFailed { .. }
        ));
        assert_eq!(client.sockets.count(), 0);
        assert_eq!(client.active.count(), 0);
        assert_eq!(client.local_dials.count(), 0);
    }

    #[tokio::test]
    async fn origin_is_not_dialed_until_open_and_control_loss_preserves_copying() {
        let (mut client, listener, tls) = harness().await;
        let origin = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = format!("127.0.0.1:{}", origin.local_addr().unwrap().port());
        let config = &mut Arc::get_mut(&mut client).unwrap().config;
        config.services.get_mut("web").unwrap().location =
            serde_json::from_value(serde_json::json!(address)).unwrap();
        let (task, mut stream, stop, mut messages) = start_data(
            &client,
            &listener,
            &tls,
            false,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        assert!(timeout(Duration::from_millis(50), origin.accept())
            .await
            .is_err());
        assert_eq!(client.active.count(), 0);
        protocol::write(
            &mut stream,
            &Message::Open {
                service: "web".into(),
                budget_ms: 10_000,
            },
        )
        .await
        .unwrap();
        let (mut local, _) = timeout(Duration::from_secs(1), origin.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            protocol::read(&mut stream).await.unwrap(),
            Message::Ready {}
        ));
        stop.cancel();
        use tokio::io::AsyncWriteExt;
        local.write_all(b"greeting").await.unwrap();
        let mut bytes = [0; 8];
        timeout(Duration::from_secs(1), stream.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"greeting");
        assert_eq!(client.active.count(), 1);
        assert_eq!(client.sockets.count(), 1);
        assert_eq!(client.local_dials.count(), 0);
        drop((stream, local));
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client.active.count(), 0);
        assert_eq!(client.sockets.count(), 0);
        assert!(messages.try_recv().is_err());
    }

    #[tokio::test]
    async fn control_receive_deadline_resets_on_frames_then_expires_after_sixty_seconds() {
        let (client, listener, tls) = harness().await;
        let (mut hub, agent) = tls.pair().await;
        let control = Control {
            io: agent,
            address: listener.local_addr().unwrap(),
            session: Id::new(),
            accepted_services: HashSet::new(),
        };
        let mut task =
            tokio::spawn(async move { client.session(control, &mut JoinSet::new()).await });
        protocol::write(&mut hub, &Message::Ping { nonce: 5 })
            .await
            .unwrap();
        assert!(matches!(
            protocol::read(&mut hub).await.unwrap(),
            Message::Pong { nonce: 5 }
        ));
        tokio::time::pause();
        assert!(timeout(Duration::from_secs(50), &mut task).await.is_err());
        tokio::time::resume();
        protocol::write(&mut hub, &Message::Ping { nonce: 6 })
            .await
            .unwrap();
        assert!(matches!(
            timeout(Duration::from_secs(5), protocol::read(&mut hub))
                .await
                .unwrap()
                .unwrap(),
            Message::Pong { nonce: 6 }
        ));
        tokio::time::pause();
        assert!(timeout(Duration::from_secs(59), &mut task).await.is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(timeout(Duration::from_millis(1), task)
            .await
            .expect("control exceeded its sixty-second receive deadline")
            .unwrap()
            .is_err());
    }

    #[tokio::test]
    async fn active_origin_limit_reports_busy_after_open_and_recovers_after_release() {
        let (mut client, listener, tls) = harness().await;
        let origin = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let config = &mut Arc::get_mut(&mut client).unwrap().config;
        config.max_active_connections = 1;
        config.max_concurrent_local_dials = 1;
        config.services.get_mut("web").unwrap().location = serde_json::from_value(
            serde_json::json!(format!("127.0.0.1:{}", origin.local_addr().unwrap().port())),
        )
        .unwrap();
        let (backend, active) = timeout(
            Duration::from_secs(2),
            client.connect_export("web", &HashSet::from(["web".into()])),
        )
        .await
        .unwrap()
        .unwrap();
        let local = timeout(Duration::from_secs(2), origin.accept())
            .await
            .unwrap()
            .unwrap()
            .0;
        let mut retained = Some((backend, active, local));
        assert_eq!(client.active.count(), 1);
        assert_eq!(client.local_dials.count(), 0);
        for busy in [true, false] {
            if !busy {
                drop(retained.take());
            }
            let (task, mut stream, stop, mut messages) = start_data(
                &client,
                &listener,
                &tls,
                false,
                Instant::now() + Duration::from_secs(10),
            )
            .await;
            protocol::write(
                &mut stream,
                &Message::Open {
                    service: "web".into(),
                    budget_ms: 10_000,
                },
            )
            .await
            .unwrap();
            let reply = timeout(Duration::from_secs(2), protocol::read(&mut stream))
                .await
                .unwrap()
                .unwrap();
            if busy {
                assert!(matches!(reply, Message::OpenFailed { code: Code::Busy }));
                let mut unexpected_origin = Box::pin(origin.accept());
                assert!(futures::poll!(&mut unexpected_origin).is_pending());
            } else {
                assert!(matches!(reply, Message::Ready {}));
                let (mut local, _) = timeout(Duration::from_secs(2), origin.accept())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(client.active.count(), 1);
                use tokio::io::AsyncWriteExt;
                local.write_all(b"restored").await.unwrap();
                let mut bytes = [0; 8];
                timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes, b"restored");
                drop(local);
            }
            drop(stream);
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(client.active.count(), usize::from(busy));
            assert_eq!(client.local_dials.count(), 0);
            assert_eq!(client.sockets.count(), 0);
            assert_eq!(client.data_setup_jobs.count(), 0);
            assert!(!stop.is_cancelled());
            assert!(messages.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn local_dial_limit_rejects_with_active_headroom_and_recovers_after_cancellation() {
        let (mut client, _listener, _tls) = harness().await;
        let settings = Arc::get_mut(&mut client).unwrap();
        settings.config.max_active_connections = 2;
        settings.config.max_concurrent_local_dials = 1;
        settings.resolver = Resolver::with_capacity(0);
        let accepted = HashSet::from(["web".into()]);
        let mut first = Box::pin(client.connect_export("web", &accepted));
        assert!(futures::poll!(&mut first).is_pending());
        let mut rejected = Box::pin(client.connect_export("web", &accepted));
        assert!(matches!(futures::poll!(&mut rejected),
            std::task::Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock));
        drop(rejected);
        assert_eq!(client.active.count(), 1);
        assert_eq!(client.local_dials.count(), 1);
        drop(first);
        assert_eq!(client.active.count(), 0);
        assert_eq!(client.local_dials.count(), 0);
        let mut next = Box::pin(client.connect_export("web", &accepted));
        assert!(futures::poll!(&mut next).is_pending());
        assert_eq!(client.active.count(), 1);
        assert_eq!(client.local_dials.count(), 1);
        drop(next);
        assert_eq!(client.active.count(), 0);
        assert_eq!(client.local_dials.count(), 0);
    }

    #[tokio::test]
    async fn local_dial_observes_hub_closure_and_clamps_valid_long_budgets() {
        for close_hub in [true, false] {
            let (mut client, listener, tls) = harness().await;
            Arc::get_mut(&mut client).unwrap().resolver = Resolver::with_capacity(0);
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut task, mut stream, stop, mut messages) =
                start_data(&client, &listener, &tls, false, deadline).await;
            tokio::time::pause();
            tokio::time::advance(
                deadline
                    .saturating_duration_since(Instant::now())
                    .saturating_sub(Duration::from_secs(1)),
            )
            .await;
            assert!(!task.is_finished());
            assert_eq!(client.local_dials.count(), 0);
            assert_eq!(client.active.count(), 0);
            tokio::time::resume();
            protocol::write(
                &mut stream,
                &Message::Open {
                    service: "web".into(),
                    budget_ms: 30_000,
                },
            )
            .await
            .unwrap();
            timeout(Duration::from_secs(1), async {
                while client.local_dials.count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(client.active.count(), 1);
            if close_hub {
                drop(stream);
            } else {
                tokio::time::pause();
                assert!(timeout(Duration::from_secs(9), &mut task).await.is_err());
                assert_eq!(client.local_dials.count(), 1);
                assert_eq!(client.active.count(), 1);
                tokio::time::advance(Duration::from_secs(1)).await;
                tokio::time::resume();
                assert!(matches!(
                    timeout(Duration::from_secs(1), protocol::read(&mut stream))
                        .await
                        .unwrap()
                        .unwrap(),
                    Message::OpenFailed {
                        code: Code::Timeout
                    }
                ));
            }
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(client.local_dials.count(), 0);
            assert_eq!(client.active.count(), 0);
            assert_eq!(client.sockets.count(), 0);
            assert!(!stop.is_cancelled());
            assert!(messages.try_recv().is_err());
        }
    }
}
