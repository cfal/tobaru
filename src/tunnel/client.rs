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
    pub dials: Arc<Semaphore>,
    pub jobs: Arc<Counter>,
}

struct Control {
    io: ClientIo,
    address: SocketAddr,
    session: Id,
    services: HashSet<String>,
}

struct Work {
    address: SocketAddr,
    session: Id,
    channel: Id,
    services: Arc<HashSet<String>>,
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
                result = timeout(Duration::from_secs(10), self.connect_control()) => result.map_err(|_| timed_out()).and_then(|r| r),
            };
            match result {
                Ok(control) => {
                    let connected_at = Instant::now();
                    log::info!("Tunnel client {} registered", self.config.tunnel_client);
                    if let Err(error) = self.session(control, &mut data).await {
                        log::warn!(
                            "Tunnel client {} disconnected: {error}",
                            self.config.tunnel_client
                        );
                    }
                    if connected_at.elapsed() >= Duration::from_secs(60) {
                        failures = 0;
                    }
                }
                Err(error) => log::warn!(
                    "Tunnel client {} connection failed: {error}",
                    self.config.tunnel_client
                ),
            }
            let cap = (1u64 << failures.min(6)).min(60);
            failures = failures.saturating_add(1);
            let delay = Duration::from_millis(rand::random_range(
                (cap * 500).max(1000)..=(cap * 1000).max(1000),
            ));
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
        {
            let _gate = self.gate.enter()?;
        }
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
                    services: services.into_iter().collect(),
                })
            }
            _ => Err(invalid()),
        }
    }

    async fn session(self: &Arc<Self>, control: Control, data: &mut JoinSet<()>) -> io::Result<()> {
        let mut pumps = Pumps::new(control.io, Some(Duration::from_secs(60)));
        let stop = Stop::default();
        let services = Arc::new(control.services);
        let result = loop {
            tokio::select! {
                biased;
                _ = self.gate.stop.wait() => break Ok(()),
                _ = stop.wait() => break Err(unavailable()),
                _ = pumps.tasks.join_next() => break Err(unavailable()),
                result = data.join_next(), if !data.is_empty() => { if let Some(result) = result { report_child(result); } },
                message = pumps.incoming.recv() => {
                    match message {
                        Some(Message::Ping { nonce }) => if let Err(error) = pumps.send(Message::Pong { nonce }) { break Err(error); },
                        Some(Message::CreateData { channel_id }) => {
                            let permits = self.sockets.acquire(self.config.max_data_connections)
                                .and_then(|socket| self.jobs.acquire(8).map(|job| (socket, job)));
                            match permits {
                                Ok((socket, job)) => {
                                    let client = self.clone();
                                    let work = Work { address: control.address, session: control.session.clone(), channel: channel_id,
                                        services: services.clone(), stop: stop.clone(), writer: pumps.outgoing.clone(), socket, job,
                                        deadline: Instant::now() + Duration::from_secs(10) };
                                    data.spawn(async move { client.data(work).await; });
                                }
                                Err(_) => if let Err(error) = pumps.send(Message::CreateFailed { channel_id, code: Code::Busy }) { break Err(error); },
                            }
                        }
                        _ => break Err(invalid()),
                    }
                }
            }
        };
        stop.cancel();
        pumps.stop().await;
        result
    }

    async fn data(&self, work: Work) {
        let Work {
            address,
            session,
            channel,
            services,
            stop,
            writer,
            socket,
            job,
            deadline,
        } = work;
        let _socket = socket;
        let setup = async {
            let mut stream = timeout_at(deadline, async {
                let dial = self
                    .dials
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
                Ok::<_, io::Error>(stream)
            })
            .await
            .map_err(|_| timed_out())??;
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
            let local = async {
                if !services.contains(&service) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Unaccepted tunnel service",
                    ));
                }
                let export = self.config.services.get(&service).ok_or_else(unavailable)?;
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
                        {
                            let _gate = self.gate.enter()?;
                        }
                        Box::new(TcpStream::connect(address).await?)
                    }
                    Location::Path(path) => Box::new(UnixStream::connect(path).await?),
                    Location::Tunnel(_) => return Err(invalid()),
                };
                drop(dial);
                Ok((backend, active))
            };
            let deadline = Instant::now() + Duration::from_millis(u64::from(budget_ms.min(10_000)));
            let mut byte = [0];
            let local = tokio::select! {
                result = timeout_at(deadline, local) => result.map_err(|_| timed_out()).and_then(|r| r),
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
            timeout_at(deadline, protocol::write(&mut stream, &Message::Ready {}))
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
                if writer
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

fn report_child(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        log::warn!("Tunnel client task failed: {error}");
    }
}
