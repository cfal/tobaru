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
        data.abort_all();
        while data.join_next().await.is_some() {}
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
                version: 1,
                peer: self.config.tunnel_client.clone(),
                services,
            },
        )
        .await?;
        match protocol::read(&mut io).await? {
            Message::ControlReady {
                session_id,
                services,
            } => {
                if services
                    .iter()
                    .any(|name| !self.config.services.contains_key(name))
                {
                    return Err(invalid());
                }
                if services.len() != self.config.services.len() {
                    log::warn!(
                        "Tunnel client {} has exports not accepted by the hub",
                        self.config.tunnel_client
                    );
                }
                Ok(Control {
                    io,
                    address,
                    session: session_id,
                    accepted_services: services.into_iter().collect(),
                })
            }
            _ => Err(invalid()),
        }
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
                        let permits = self.sockets
                            .acquire(self.config.max_data_connections)
                            .and_then(|socket| self.data_setup_jobs.acquire(8).map(|job| (socket, job)));
                        match permits {
                            Ok((socket, job)) => {
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
                            Err(_) => {
                                if let Err(error) = pumps.send(Message::CreateFailed {
                                    channel_id,
                                    code: Code::Busy,
                                }) {
                                    break Err(error);
                                }
                            }
                        }
                    }
                    _ => break Err(invalid()),
                },
            }
        };
        stop.cancel();
        pumps.stop().await;
        result
    }

    async fn attach_data(
        &self,
        address: SocketAddr,
        session: Id,
        channel: &Id,
        job: Permit,
    ) -> io::Result<ClientIo> {
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
                version: 1,
                peer: self.config.tunnel_client.clone(),
                session_id: session,
                channel_id: channel.clone(),
            },
        )
        .await?;
        drop(dial);
        drop(job);
        if !matches!(protocol::read(&mut stream).await?, Message::DataReady {}) {
            return Err(invalid());
        }
        Ok(stream)
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
            let mut stream = timeout_at(
                attach_deadline,
                self.attach_data(address, session, &channel, job),
            )
            .await
            .map_err(|_| timed_out())??;
            attached = true;
            let (service, budget_ms) = loop {
                match timeout(Duration::from_secs(40), protocol::read(&mut stream))
                    .await
                    .map_err(|_| timed_out())??
                {
                    Message::Ping { nonce } => {
                        timeout(
                            Duration::from_secs(10),
                            protocol::write(&mut stream, &Message::Pong { nonce }),
                        )
                        .await
                        .map_err(|_| timed_out())??;
                    }
                    Message::Open { service, budget_ms } => break (service, budget_ms),
                    _ => return Err(invalid()),
                }
            };
            let local = self.connect_export(&service, &accepted_services);
            let open_deadline =
                Instant::now() + Duration::from_millis(u64::from(budget_ms.min(10_000)));
            let mut byte = [0];
            let local = tokio::select! {
                result = timeout_at(open_deadline, local) => {
                    result.map_err(|_| timed_out()).and_then(|result| result)
                },
                _ = stream.read(&mut byte) => return Err(unavailable()),
            };
            let (backend, active) = match local {
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
            Ok::<_, io::Error>((stream, backend, active))
        };
        let result = tokio::select! {
            biased;
            _ = stop.wait() => return,
            result = setup => result,
        };
        match result {
            Ok((mut stream, mut backend, _active)) => {
                if let Err(error) = crate::copy_bidirectional::copy_bidirectional(
                    &mut stream,
                    &mut *backend,
                    false,
                    false,
                )
                .await
                {
                    log::debug!("Tunnel local copy ended: {error}");
                }
            }
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
            }
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

    async fn start_data(
        client: &Arc<Client>,
        listener: &TcpListener,
        tls: &Tls,
        full_writer: bool,
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
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let c = client.clone();
        let task = tokio::spawn(async move {
            c.data(work).await;
        });
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
        (task, stream, stop, receiver)
    }

    #[tokio::test]
    async fn attached_failures_do_not_send_create_failed_or_stop_control() {
        let (client, listener, tls) = harness().await;
        for full_writer in [false, true] {
            let (task, mut stream, stop, mut messages) =
                start_data(&client, &listener, &tls, full_writer).await;
            protocol::write(&mut stream, &Message::DataReady {})
                .await
                .unwrap();
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
            let (task, mut stream, stop, mut messages) =
                start_data(&client, &listener, &tls, full_writer).await;
            protocol::write(&mut stream, &Message::Ready {})
                .await
                .unwrap();
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

    #[tokio::test]
    async fn flushed_data_hello_releases_dial_slots_before_data_ready() {
        let (client, listener, tls) = harness().await;
        let mut pending = Vec::new();
        for _ in 0..5 {
            pending.push(start_data(&client, &listener, &tls, false).await);
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
    async fn idle_data_receive_deadline_closes_without_eof_or_control_failure() {
        let (client, listener, tls) = harness().await;
        let (task, mut stream, stop, mut messages) =
            start_data(&client, &listener, &tls, false).await;
        protocol::write(&mut stream, &Message::DataReady {})
            .await
            .unwrap();
        protocol::write(&mut stream, &Message::Ping { nonce: 5 })
            .await
            .unwrap();
        assert!(matches!(
            protocol::read(&mut stream).await.unwrap(),
            Message::Pong { nonce: 5 }
        ));
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(39)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        timeout(Duration::from_millis(1), task)
            .await
            .expect("idle data exceeded its forty-second receive deadline")
            .unwrap();
        assert!(!stop.is_cancelled());
        assert!(messages.try_recv().is_err());
        assert_eq!(client.sockets.count(), 0);
    }

    #[tokio::test]
    async fn silent_control_expires_after_sixty_seconds() {
        let (client, listener, tls) = harness().await;
        let (mut hub, agent) = tls.pair().await;
        let control = Control {
            io: agent,
            address: listener.local_addr().unwrap(),
            session: Id::new(),
            accepted_services: HashSet::new(),
        };
        let task = tokio::spawn(async move { client.session(control, &mut JoinSet::new()).await });
        protocol::write(&mut hub, &Message::Ping { nonce: 5 })
            .await
            .unwrap();
        assert!(matches!(
            protocol::read(&mut hub).await.unwrap(),
            Message::Pong { nonce: 5 }
        ));
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(timeout(Duration::from_millis(1), task)
            .await
            .expect("control exceeded its sixty-second receive deadline")
            .unwrap()
            .is_err());
    }

    #[tokio::test]
    async fn local_dial_observes_hub_closure_and_clamps_valid_long_budgets() {
        for close_hub in [true, false] {
            let (mut client, listener, tls) = harness().await;
            Arc::get_mut(&mut client).unwrap().resolver = Resolver::with_capacity(0);
            let (task, mut stream, stop, mut messages) =
                start_data(&client, &listener, &tls, false).await;
            protocol::write(&mut stream, &Message::DataReady {})
                .await
                .unwrap();
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
                tokio::time::advance(Duration::from_secs(9)).await;
                assert!(!task.is_finished());
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
