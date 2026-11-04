use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{Duration, Instant};

use super::protocol::{Id, Message};
use super::state::{busy, timed_out, unavailable, Counter, Gate, Permit, Stop};
use super::stream::DataStream;
use crate::config::tunnel::TunnelPeerConfig;

pub struct Endpoint {
    pub accepted: Arc<Counter>,
    pub credits: Arc<Counter>,
    pub limit: usize,
    scheduling: Mutex<()>,
}

impl Endpoint {
    pub fn new(accepted: Arc<Counter>, credits: Arc<Counter>, limit: usize) -> Self {
        Self {
            accepted,
            credits,
            limit,
            scheduling: Mutex::new(()),
        }
    }
    pub fn accept(&self) -> io::Result<Permit> {
        let _lock = self.scheduling.lock();
        self.accepted.acquire(self.limit)
    }
    fn reserve(&self) -> io::Result<Permit> {
        let _lock = self.scheduling.lock();
        if self.accepted.count() + self.credits.count() >= self.limit {
            return Err(busy());
        }
        self.credits.acquire(self.limit)
    }
}

pub struct Peer {
    pub gate: Arc<Gate>,
    pub config: TunnelPeerConfig,
    pub endpoint: Arc<Endpoint>,
    pub active: Arc<Counter>,
    pub pending: Arc<Counter>,
    pub physical: Arc<Counter>,
    current: Mutex<Option<Arc<Session>>>,
}

impl Peer {
    pub fn new(
        gate: Arc<Gate>,
        config: TunnelPeerConfig,
        endpoint: Arc<Endpoint>,
        active: Arc<Counter>,
        pending: Arc<Counter>,
        physical: Arc<Counter>,
    ) -> Self {
        Self {
            gate,
            config,
            endpoint,
            active,
            pending,
            physical,
            current: Mutex::new(None),
        }
    }

    pub fn install(&self, session: Arc<Session>) -> io::Result<()> {
        let _gate = self.gate.enter()?;
        if let Some(old) = self.current.lock().replace(session) {
            old.close();
        }
        Ok(())
    }

    pub fn session(&self, id: &Id) -> io::Result<Arc<Session>> {
        let current = self.current.lock();
        current
            .as_ref()
            .filter(|s| s.id == *id)
            .cloned()
            .ok_or_else(unavailable)
    }

    pub fn remove(&self, session: &Session) {
        let mut current = self.current.lock();
        if current.as_ref().is_some_and(|s| s.id == session.id) {
            current.take();
        }
        session.close();
    }

    pub async fn open(&self, service: &str, deadline: Instant) -> io::Result<DataStream> {
        let (rx, session) = {
            let _gate = self.gate.enter()?;
            let session = self.current.lock().clone().ok_or_else(unavailable)?;
            if !session.services.contains(service) {
                return Err(unavailable());
            }
            let active = self.active.acquire(self.config.max_active_connections)?;
            let pending = self.pending.acquire(self.config.max_pending_opens)?;
            let (tx, rx) = oneshot::channel();
            session
                .state
                .lock()
                .as_mut()
                .ok_or_else(unavailable)?
                .opens
                .push_back(Open {
                    service: service.into(),
                    deadline,
                    active,
                    _pending: pending,
                    reply: tx,
                });
            session.wake.notify_waiters();
            (rx, session)
        };
        let _wake = WakeOnDrop(session);
        tokio::time::timeout_at(deadline, rx)
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| unavailable())?
    }
}

struct WakeOnDrop(Arc<Session>);
impl Drop for WakeOnDrop {
    fn drop(&mut self) {
        self.0.wake.notify_waiters();
    }
}

pub struct Open {
    pub service: String,
    pub deadline: Instant,
    pub active: Permit,
    pub _pending: Permit,
    pub reply: oneshot::Sender<io::Result<DataStream>>,
}

pub struct Credit {
    pub deadline: Instant,
    pub physical: Permit,
    pub _endpoint: Permit,
}

pub struct Session {
    pub id: Id,
    pub fingerprint: Vec<u8>,
    pub services: HashSet<String>,
    pub stop: Stop,
    pub wake: Notify,
    pub state: Mutex<Option<SessionState>>,
    pub writer: mpsc::Sender<Message>,
}

pub struct SessionState {
    pub opens: VecDeque<Open>,
    pub credits: HashMap<Id, Credit>,
    failures: u32,
    retry_at: Instant,
}

impl Session {
    pub fn new(
        id: Id,
        fingerprint: Vec<u8>,
        services: HashSet<String>,
        writer: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            id,
            fingerprint,
            services,
            writer,
            stop: Stop::default(),
            wake: Notify::new(),
            state: Mutex::new(Some(SessionState {
                opens: VecDeque::new(),
                credits: HashMap::new(),
                failures: 0,
                retry_at: Instant::now(),
            })),
        }
    }

    pub fn close(&self) {
        self.stop.cancel();
        self.state.lock().take();
        self.wake.notify_waiters();
    }

    pub fn send(&self, message: Message) -> io::Result<()> {
        self.writer.try_send(message).map_err(|_| unavailable())
    }

    pub fn failed(&self, id: &Id, peer: &Peer) {
        if let Some(state) = self.state.lock().as_mut() {
            if state.credits.remove(id).is_some() {
                state.backoff(peer);
            }
        }
        self.wake.notify_waiters();
    }

    pub fn attach(&self, id: &Id, fingerprint: &[u8]) -> io::Result<(Credit, Open)> {
        if self.fingerprint != fingerprint {
            return Err(unavailable());
        }
        let mut guard = self.state.lock();
        let state = guard.as_mut().ok_or_else(unavailable)?;
        let credit = state.credits.remove(id).ok_or_else(unavailable)?;
        if credit.deadline <= Instant::now() {
            return Err(timed_out());
        }
        state.failures = 0;
        state.retry_at = Instant::now();
        state.prune_opens();
        let open = state.opens.pop_front().ok_or_else(unavailable)?;
        self.wake.notify_waiters();
        Ok((credit, open))
    }

    pub fn request_data(&self, peer: &Peer) -> io::Result<()> {
        let _gate = peer.gate.enter()?;
        let mut guard = self.state.lock();
        let state = guard.as_mut().ok_or_else(unavailable)?;
        let queued = state.opens.len();
        state.prune_opens();
        if state.opens.len() != queued {
            self.wake.notify_waiters();
        }
        let before = state.credits.len();
        state
            .credits
            .retain(|_, credit| credit.deadline > Instant::now());
        if state.credits.len() < before {
            state.backoff(peer);
        }
        if state.retry_at > Instant::now() || self.services.is_empty() {
            return Ok(());
        }
        let wanted = state.opens.len().saturating_sub(state.credits.len());
        for _ in 0..wanted.min(4usize.saturating_sub(state.credits.len())) {
            let Ok(physical) = peer.physical.acquire(peer.config.max_active_connections) else {
                break;
            };
            let Ok(endpoint) = peer.endpoint.reserve() else {
                break;
            };
            let id = Id::new();
            self.send(Message::CreateData {
                channel_id: id.clone(),
            })?;
            state.credits.insert(
                id,
                Credit {
                    deadline: Instant::now() + Duration::from_secs(10),
                    physical,
                    _endpoint: endpoint,
                },
            );
        }
        Ok(())
    }
}

impl SessionState {
    fn prune_opens(&mut self) {
        self.opens
            .retain(|open| !open.reply.is_closed() && open.deadline > Instant::now());
    }

    fn backoff(&mut self, peer: &Peer) {
        self.failures = self.failures.saturating_add(1);
        let cap = (1u64 << self.failures.min(4))
            .min(peer.config.open_timeout_secs)
            .min(10);
        self.retry_at = Instant::now() + Duration::from_secs(rand::random_range(1..=cap));
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{expect_create_data, harness};
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn demand_at_active_limit_can_create_its_first_channel() {
        let (peer, session, mut messages) = harness(1);
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
        let p = peer.clone();
        let pending = tokio::spawn(async move {
            p.open("web", Instant::now() + Duration::from_secs(10))
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(peer.active.count(), 1);
        assert_eq!(peer.physical.count(), 0);
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        assert_eq!(peer.physical.count(), 1);
        let _accepted = peer.endpoint.accept().unwrap();
        let (credit, opening) = session.attach(&channel_id, &[1]).unwrap();
        drop(credit._endpoint);
        session.request_data(&peer).unwrap();
        assert!(
            messages.try_recv().is_err(),
            "Opening is not additional unassigned demand"
        );
        pending.abort();
        let _ = pending.await;
        drop(opening);
        drop(credit.physical);
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.physical.count(), 0);
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn attachments_claim_live_demand_in_fifo_order_not_credit_order() {
        let (peer, session, mut messages) = harness(3);
        let first_deadline = Instant::now() + Duration::from_secs(60);
        let last_deadline = first_deadline + Duration::from_secs(2);
        let mut first = Box::pin(peer.open("web", first_deadline));
        let mut cancelled = Box::pin(peer.open("web", first_deadline + Duration::from_secs(1)));
        let mut last = Box::pin(peer.open("web", last_deadline));
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut cancelled).is_pending());
        assert!(futures::poll!(&mut last).is_pending());
        session.request_data(&peer).unwrap();
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(expect_create_data(&mut messages));
        }
        drop(cancelled);
        let (first_credit, first_open) = session.attach(&ids[2], &[1]).unwrap();
        assert_eq!(first_open.deadline, first_deadline);
        assert!(session.attach(&ids[2], &[1]).is_err());
        let (last_credit, last_open) = session.attach(&ids[0], &[1]).unwrap();
        assert_eq!(last_open.deadline, last_deadline);
        assert!(session.attach(&ids[1], &[1]).is_err());
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
        assert_eq!(peer.active.count(), 2);
        assert_eq!(peer.pending.count(), 2);
        assert_eq!(peer.physical.count(), 2);
        drop((first_open, last_open, first_credit, last_credit));
        assert!(first.await.is_err());
        assert!(last.await.is_err());
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_demand_rejects_late_attachment_and_releases_capacity() {
        let (peer, session, mut messages) = harness(1);
        let p = peer.clone();
        let caller = tokio::spawn(async move {
            p.open("web", Instant::now() + Duration::from_secs(60))
                .await
        });
        tokio::task::yield_now().await;
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        caller.abort();
        let _ = caller.await;
        let accepted = peer.endpoint.accept().unwrap();
        assert!(session.attach(&channel_id, &[1]).is_err());
        drop(accepted);
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
        assert!(session.state.lock().as_ref().unwrap().opens.is_empty());
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.accepted.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
        assert!(!session.stop.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn outstanding_credits_are_bounded_and_assignment_wakes_more_demand() {
        let (peer, session, mut messages) = harness(6);
        let mut callers: Vec<_> = (0..6)
            .map(|_| Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60))))
            .collect();
        for caller in &mut callers {
            assert!(futures::poll!(caller).is_pending());
        }
        session.request_data(&peer).unwrap();
        session.request_data(&peer).unwrap();
        let mut ids = Vec::new();
        for _ in 0..4 {
            ids.push(expect_create_data(&mut messages));
        }
        assert!(messages.try_recv().is_err());
        let wake = session.wake.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        let assigned = session.attach(&ids[0], &[1]).unwrap();
        assert!(futures::poll!(&mut wake).is_ready());
        session.request_data(&peer).unwrap();
        assert!(matches!(
            messages.try_recv().unwrap(),
            Message::CreateData { .. }
        ));
        assert!(messages.try_recv().is_err());
        assert_eq!(session.state.lock().as_ref().unwrap().credits.len(), 4);
        drop((callers, assigned));
        session.close();
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_callers_credit_can_serve_new_demand_and_ignores_late_failure() {
        let (peer, session, mut messages) = harness(1);
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut cancelled = Box::pin(peer.open("web", deadline));
        assert!(futures::poll!(&mut cancelled).is_pending());
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        drop(cancelled);
        session.request_data(&peer).unwrap();
        let mut caller = Box::pin(peer.open("web", deadline));
        assert!(futures::poll!(&mut caller).is_pending());
        session.request_data(&peer).unwrap();
        assert!(messages.try_recv().is_err());
        assert!(session.attach(&channel_id, &[2]).is_err());
        assert_eq!(session.state.lock().as_ref().unwrap().credits.len(), 1);
        let assigned = session.attach(&channel_id, &[1]).unwrap();
        session.failed(&channel_id, &peer);
        assert_eq!(session.state.lock().as_ref().unwrap().failures, 0);
        assert!(!session.stop.is_cancelled());
        assert_eq!(peer.active.count(), 1);
        drop(assigned);
        assert!(caller.await.is_err());
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_attachment_releases_credit_without_consuming_live_demand() {
        let (peer, session, mut messages) = harness(1);
        let mut caller = Box::pin(peer.open("web", Instant::now() + Duration::from_secs(60)));
        assert!(futures::poll!(&mut caller).is_pending());
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(
            matches!(session.attach(&channel_id, &[1]), Err(error) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert_eq!(session.state.lock().as_ref().unwrap().opens.len(), 1);
        assert_eq!(peer.active.count(), 1);
        assert_eq!(peer.pending.count(), 1);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        drop(session.attach(&channel_id, &[1]).unwrap());
        assert!(caller.await.is_err());
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn visitor_burst_rejects_only_excess_opens_and_cancellation_restores_capacity() {
        let (peer, session, _messages) = harness(2);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let peer = peer.clone();
            tasks.spawn(async move {
                peer.open("web", Instant::now() + Duration::from_secs(10))
                    .await
            });
        }
        tokio::task::yield_now().await;
        assert_eq!(
            peer.open("web", Instant::now() + Duration::from_secs(10))
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!session.stop.is_cancelled());
        tasks.shutdown().await;
        session.request_data(&peer).unwrap();
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
        assert!(!session.stop.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_credits_and_late_failures_do_not_flap_control() {
        let (peer, session, mut messages) = harness(2);
        let p = peer.clone();
        let caller = tokio::spawn(async move {
            p.open("web", Instant::now() + Duration::from_secs(60))
                .await
        });
        tokio::task::yield_now().await;
        session.request_data(&peer).unwrap();
        let channel_id = expect_create_data(&mut messages);
        tokio::time::advance(Duration::from_secs(11)).await;
        session.request_data(&peer).unwrap();
        let failures = session.state.lock().as_ref().unwrap().failures;
        session.failed(&channel_id, &peer);
        session.failed(&Id::new(), &peer);
        assert_eq!(session.state.lock().as_ref().unwrap().failures, failures);
        assert!(!session.stop.is_cancelled());
        assert_eq!(peer.physical.count(), 0);
        assert_eq!(peer.endpoint.credits.count(), 0);
        caller.abort();
        let _ = caller.await;
        session.request_data(&peer).unwrap();
        assert_eq!(peer.active.count(), 0);
        assert_eq!(peer.pending.count(), 0);
    }

    #[tokio::test]
    async fn replacement_fences_old_cleanup_and_retirement_rejects_late_commits() {
        let (peer, old, _messages) = harness(2);
        let (writer, _rx) = mpsc::channel(64);
        let new = Arc::new(Session::new(
            Id::new(),
            vec![1],
            HashSet::from(["web".into()]),
            writer,
        ));
        peer.install(new.clone()).unwrap();
        peer.remove(&old);
        assert!(peer.session(&new.id).is_ok());
        assert!(old.stop.is_cancelled());
        peer.gate.retire();
        assert!(peer.install(old).is_err());
        assert!(new.request_data(&peer).is_err());
        assert!(peer
            .open("web", Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
    }

    #[test]
    fn endpoint_headroom_counts_credits_unidentified_and_retained_sockets() {
        let endpoint = Endpoint::new(Arc::default(), Arc::default(), 2);
        let credit = endpoint.reserve().unwrap();
        let unidentified = endpoint.accept().unwrap();
        assert!(endpoint.reserve().is_err());
        let second = endpoint.accept().unwrap();
        assert!(endpoint.accept().is_err());
        drop(credit);
        assert!(endpoint.reserve().is_err());
        drop(unidentified);
        assert!(endpoint.reserve().is_ok());
        drop(second);
    }
}
