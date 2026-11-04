use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::{Mutex, MutexGuard};
use socket2::{SockRef, Socket};
use tokio::net::TcpStream;
use tokio::sync::watch;

pub fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Reverse tunnel unavailable")
}
pub fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "Reverse tunnel capacity exhausted",
    )
}
pub fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Reverse tunnel setup timed out")
}

#[derive(Clone)]
pub struct Stop(watch::Sender<bool>);

impl Default for Stop {
    fn default() -> Self {
        Self(watch::channel(false).0)
    }
}

impl Stop {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    pub async fn wait(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|stopped| *stopped).await;
    }
}

#[derive(Default)]
pub struct Counter {
    used: AtomicUsize,
}

impl Counter {
    pub fn count(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    #[allow(deprecated)] // fetch_update supports the Rust 1.88 MSRV.
    pub fn acquire(self: &Arc<Self>, limit: usize) -> io::Result<Permit> {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < limit).then_some(n + 1)
            })
            .map_err(|_| busy())?;
        Ok(Permit(self.clone()))
    }
}

pub struct Permit(Arc<Counter>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Counters(HashMap<String, Weak<Counter>>);

impl Counters {
    pub fn get(&mut self, key: String) -> Arc<Counter> {
        self.0.retain(|_, value| value.strong_count() != 0);
        if let Some(counter) = self.0.get(&key).and_then(Weak::upgrade) {
            return counter;
        }
        let counter = Arc::new(Counter::default());
        self.0.insert(key, Arc::downgrade(&counter));
        counter
    }
}

#[derive(Default)]
pub struct Gate {
    state: Mutex<GateState>,
    pub stop: Stop,
}

#[derive(Default)]
pub struct GateState {
    active: bool,
    next: u64,
    sockets: HashMap<u64, Weak<Socket>>,
}

impl Gate {
    pub fn activate(&self) {
        let mut state = self.state.lock();
        if !self.stop.is_cancelled() {
            state.active = true;
        }
    }

    pub fn enter(&self) -> io::Result<MutexGuard<'_, GateState>> {
        let state = self.state.lock();
        if state.active {
            Ok(state)
        } else {
            Err(unavailable())
        }
    }

    pub fn retire(&self) {
        let mut state = self.state.lock();
        state.active = false;
        self.stop.cancel();
        for socket in state.sockets.values().filter_map(Weak::upgrade) {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    pub fn register(
        self: &Arc<Self>,
        state: &mut GateState,
        stream: &TcpStream,
    ) -> io::Result<Revocation> {
        let socket = Arc::new(SockRef::from(stream).try_clone()?);
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        state.sockets.insert(id, Arc::downgrade(&socket));
        Ok(Revocation {
            gate: self.clone(),
            id,
            _socket: socket,
        })
    }
}

pub struct Revocation {
    gate: Arc<Gate>,
    id: u64,
    _socket: Arc<Socket>,
}

impl Drop for Revocation {
    fn drop(&mut self) {
        self.gate.state.lock().sockets.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_survive_removal_readdition_and_lower_limits() {
        let mut counters = Counters::default();
        let old = counters.get("peer/home".into());
        let first = old.acquire(2).unwrap();
        let second = old.acquire(2).unwrap();
        drop(old);
        let new = counters.get("peer/home".into());
        assert!(new.acquire(1).is_err());
        drop(first);
        assert!(new.acquire(1).is_err());
        drop(second);
        assert!(new.acquire(1).is_ok());
    }

    #[tokio::test]
    async fn retiring_gate_revokes_unpolled_socket_and_never_reactivates() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", listener.local_addr().unwrap().port()))
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let gate = Arc::new(Gate::default());
        gate.activate();
        let registration = gate.register(&mut gate.enter().unwrap(), &server).unwrap();
        gate.retire();
        gate.activate();
        assert!(gate.enter().is_err());
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        drop(registration);
    }
}
