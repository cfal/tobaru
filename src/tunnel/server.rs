use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Duration, Instant};

use super::broker::{Endpoint, Idle, Peer, Session};
use super::control::Pumps;
use super::protocol::{self, invalid, Code, Id, Message};
use super::state::{timed_out, unavailable, Counter, Gate, Permit};
use super::stream::{Channel, DataStream, ServerIo};
use super::tls;

#[cfg(test)]
mod tests;

pub struct Server {
    pub address: SocketAddr,
    pub tls: Arc<rustls::ServerConfig>,
    pub gate: Arc<Gate>,
    pub endpoint: Arc<Endpoint>,
    pub peers: HashMap<String, Arc<Peer>>,
    pub identities: HashMap<Vec<u8>, String>,
    pub handshakes: Arc<Counter>,
    pub max_handshakes: usize,
}

impl Server {
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let listener = TcpListener::bind(self.address).await?;
        self.accept_connections(|| listener.accept()).await
    }

    async fn accept_connections<F: Future<Output = io::Result<(TcpStream, SocketAddr)>>>(
        self: Arc<Self>,
        accept: impl FnMut() -> F + Copy,
    ) -> io::Result<()> {
        let pending_accept = accept_retry(accept, self.address);
        tokio::pin!(pending_accept);
        let mut children = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = self.gate.stop.wait() => break Ok(()),
                result = children.join_next(), if !children.is_empty() => {
                    if let Some(Err(error)) = result { log::warn!("Tunnel connection task failed: {error}"); }
                }
                (stream, _) = &mut pending_accept => {
                    pending_accept.set(accept_retry(accept, self.address));
                    let Ok(permit) = self.endpoint.accept() else { continue; };
                    let Ok(handshake) = self.handshakes.acquire(self.max_handshakes) else { continue; };
                    let server = self.clone();
                    children.spawn(async move {
                        if let Err(error) = server.connection(stream, permit, handshake).await {
                            log::debug!("Tunnel connection ended: {error}");
                        }
                    });
                }
            }
        };
        children.abort_all();
        while children.join_next().await.is_some() {}
        result
    }

    async fn connection(
        &self,
        stream: TcpStream,
        accepted: Permit,
        handshake: Permit,
    ) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        tls::socket_options(&stream)?;
        let acceptor =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
        let start = timeout(Duration::from_secs(3), acceptor)
            .await
            .map_err(|_| timed_out())??;
        let mut stream = timeout_at(
            deadline,
            start.into_stream_with(self.tls.clone(), |connection| {
                connection.set_buffer_limit(Some(32768));
            }),
        )
        .await
        .map_err(|_| timed_out())??;
        drop(handshake);
        let fingerprint = tls::identity(stream.get_ref().1)?;
        let identity = self.identities.get(&fingerprint).ok_or_else(unavailable)?;
        let first = timeout_at(deadline, protocol::read(&mut stream))
            .await
            .map_err(|_| timed_out())??;
        match first {
            Message::ControlHello { peer, services, .. } if peer == *identity => {
                let peer = self.peers.get(&peer).ok_or_else(unavailable)?.clone();
                self.control(peer, fingerprint, services, stream, accepted)
                    .await
            }
            Message::DataHello {
                peer,
                session_id,
                channel_id,
                ..
            } if peer == *identity => {
                let peer = self.peers.get(&peer).ok_or_else(unavailable)?.clone();
                let (session, credit) = {
                    let _gate = peer.gate.enter()?;
                    let session = peer.session(&session_id)?;
                    let credit = session.attach(&channel_id, &fingerprint, &peer)?;
                    (session, credit)
                };
                let idle = Idle::new(session.clone());
                drop(credit._endpoint);
                let mut channel = Channel {
                    io: stream,
                    _accepted: accepted,
                    _physical: credit.physical,
                };
                timeout_at(
                    deadline,
                    protocol::write(&mut channel.io, &Message::DataReady {}),
                )
                .await
                .map_err(|_| timed_out())??;
                tokio::select! {
                    biased;
                    _ = session.stop.wait() => Err(unavailable()),
                    result = serve_data(peer, idle, channel) => result,
                }
            }
            _ => Err(invalid()),
        }
    }

    async fn control(
        &self,
        peer: Arc<Peer>,
        fingerprint: Vec<u8>,
        offered: Vec<String>,
        mut stream: ServerIo,
        _accepted: Permit,
    ) -> io::Result<()> {
        let services: HashSet<_> = offered
            .iter()
            .filter(|s| peer.config.services.contains(s))
            .cloned()
            .collect();
        if services.len() != offered.len() {
            log::warn!("Tunnel peer offered services outside its authorization");
        }
        let id = Id::new();
        let mut names: Vec<_> = services.iter().cloned().collect();
        names.sort();
        timeout(
            Duration::from_secs(10),
            protocol::write(
                &mut stream,
                &Message::ControlReady {
                    session_id: id.clone(),
                    services: names,
                },
            ),
        )
        .await
        .map_err(|_| timed_out())??;
        let mut pumps = Pumps::new(stream, None);
        let session = Arc::new(Session::new(
            id,
            fingerprint,
            services,
            pumps.outgoing.clone(),
        ));
        peer.install(session.clone())?;
        let _cleanup = SessionCleanup {
            peer: peer.clone(),
            session: session.clone(),
        };
        let result = run_control(&peer, &session, &mut pumps).await;
        peer.remove(&session);
        pumps.stop().await;
        result
    }
}

async fn accept_retry<T, F: Future<Output = io::Result<T>>>(
    mut accept: impl FnMut() -> F,
    address: SocketAddr,
) -> T {
    let mut failed = false;
    loop {
        match accept().await {
            Ok(accepted) => {
                if failed {
                    log::info!("Tunnel accept recovered on {address}");
                }
                return accepted;
            }
            Err(error) => {
                if !failed {
                    log::warn!("Tunnel accept failed on {address}: {error}; retrying");
                    failed = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

struct SessionCleanup {
    peer: Arc<Peer>,
    session: Arc<Session>,
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.peer.remove(&self.session);
    }
}

async fn run_control(peer: &Peer, session: &Session, pumps: &mut Pumps) -> io::Result<()> {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_ping = Instant::now();
    let mut ping = None;
    loop {
        let wake = session.wake.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        session.refill(peer)?;
        tokio::select! {
            biased;
            _ = peer.gate.stop.wait() => return Ok(()),
            _ = session.stop.wait() => return Ok(()),
            _ = pumps.tasks.join_next() => return Err(unavailable()),
            _ = tick.tick() => {
                if ping.is_some_and(|(_, deadline)| Instant::now() >= deadline) { return Err(timed_out()); }
                if ping.is_none() && last_ping.elapsed() >= Duration::from_secs(20) {
                    let nonce = rand::random();
                    session.send(Message::Ping { nonce })?;
                    ping = Some((nonce, Instant::now() + Duration::from_secs(60)));
                    last_ping = Instant::now();
                }
            },
            message = pumps.incoming.recv() => match message.ok_or_else(unavailable)? {
                Message::Pong { nonce } if ping.is_some_and(|(expected, _)| nonce == expected) => { ping = None; }
                Message::CreateFailed { channel_id, .. } => session.failed(&channel_id, peer),
                _ => return Err(invalid()),
            },
            _ = &mut wake => {},
        }
    }
}

async fn clean_idle(stream: &mut ServerIo) -> bool {
    std::future::poll_fn(|cx| {
        let mut byte = [0];
        let mut buf = ReadBuf::new(&mut byte);
        Poll::Ready(Pin::new(&mut *stream).poll_read(cx, &mut buf).is_pending())
    })
    .await
}

async fn serve_data(peer: Arc<Peer>, mut idle: Idle, mut channel: Channel) -> io::Result<()> {
    let session = idle.session.clone();
    let mut heartbeat_at = Instant::now() + Duration::from_secs(20);
    loop {
        let wake = session.wake.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        if let Some(mut open) = idle.claim(&peer)? {
            if !clean_idle(&mut channel.io).await {
                let _gate = peer.gate.enter()?;
                if let Some(state) = session.state.lock().as_mut() {
                    state.opens.push_front(open);
                }
                session.wake.notify_waiters();
                return Err(unavailable());
            }
            let exchange = timeout_at(open.deadline, async {
                let remaining = open
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis();
                if remaining == 0 {
                    return Err(timed_out());
                }
                protocol::write(
                    &mut channel.io,
                    &Message::Open {
                        service: open.service.clone(),
                        budget_ms: remaining.min(protocol::MAX_BUDGET_MS as u128) as u32,
                    },
                )
                .await?;
                match protocol::read(&mut channel.io).await? {
                    Message::Ready {} => Ok(()),
                    Message::OpenFailed { code } => Err(io::Error::new(
                        match code {
                            Code::Busy => io::ErrorKind::WouldBlock,
                            Code::Timeout => io::ErrorKind::TimedOut,
                            Code::ConnectFailed => io::ErrorKind::ConnectionRefused,
                            _ => io::ErrorKind::NotConnected,
                        },
                        "Tunnel origin setup failed",
                    )),
                    _ => Err(invalid()),
                }
            });
            let result = tokio::select! {
                biased;
                _ = open.reply.closed() => return Ok(()),
                result = exchange => result.map_err(|_| timed_out()).and_then(|result| result),
            };
            if let Err(error) = result {
                let _ = open.reply.send(Err(error));
                return Ok(());
            }
            let revocation = {
                let mut gate = peer.gate.enter()?;
                let state = session.state.lock();
                if state.is_none() {
                    return Err(unavailable());
                }
                peer.gate.register(&mut gate, channel.io.get_ref().0)?
            };
            let stream = DataStream {
                channel,
                _active: open.active,
                _revocation: revocation,
            };
            drop(open._pending);
            let _ = open.reply.send(Ok(stream));
            return Ok(());
        }
        tokio::select! {
            _ = &mut wake => {},
            _ = tokio::time::sleep_until(heartbeat_at) => {
                let nonce = rand::random();
                timeout(Duration::from_secs(10), async {
                    protocol::write(&mut channel.io, &Message::Ping { nonce }).await?;
                    match protocol::read(&mut channel.io).await? {
                        Message::Pong { nonce: reply } if reply == nonce => Ok(()),
                        _ => Err(invalid()),
                    }
                }).await.map_err(|_| timed_out())??;
                heartbeat_at = Instant::now() + Duration::from_secs(20);
            }
        }
    }
}
