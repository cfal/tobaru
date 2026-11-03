mod broker;
mod client;
mod control;
mod dns;
mod protocol;
mod server;
mod state;
mod stream;
mod tls;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};

use crate::config::{tunnel::TunnelReference, RuntimeConfig, TargetConfigs};
use broker::{Endpoint, Peer};
use state::{Counters, Gate};

type Task = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

#[derive(Default)]
pub struct Store {
    counters: Counters,
    resolver: dns::Resolver,
}

#[derive(Default)]
pub struct Registry(HashMap<(String, String), Arc<Peer>>);

pub struct Binding {
    peer: Arc<Peer>,
    service: String,
}

impl Registry {
    pub fn bind(&self, reference: &TunnelReference) -> io::Result<Binding> {
        let peer = self
            .0
            .get(&(reference.server.clone(), reference.peer.clone()))
            .filter(|peer| peer.config.services.contains(&reference.service))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unresolved or unauthorized tunnel destination",
                )
            })?;
        Ok(Binding {
            peer: peer.clone(),
            service: reference.service.clone(),
        })
    }
}

impl Binding {
    pub fn setup_timeout(&self) -> Duration {
        Duration::from_secs(self.peer.config.open_timeout_secs)
    }
    pub async fn open(&self, deadline: Instant) -> io::Result<stream::DataStream> {
        self.peer.open(&self.service, deadline).await
    }
}

pub struct Prepared {
    pub registry: Registry,
    pub gate: Arc<Gate>,
    tasks: Vec<Task>,
}

impl Store {
    pub fn prepare(&mut self, config: &RuntimeConfig) -> io::Result<Prepared> {
        let gate = Arc::new(Gate::default());
        let mut prepared = Prepared {
            registry: Registry::default(),
            gate: gate.clone(),
            tasks: Vec::new(),
        };
        let mut names = HashSet::new();
        let mut addresses: HashSet<_> = config
            .servers
            .iter()
            .filter(|server| matches!(server.target_configs, TargetConfigs::Tcp { .. }))
            .map(|server| server.address)
            .collect();
        for server in &config.tunnel_servers {
            server.validate()?;
            if !names.insert(&server.tunnel_server) || !addresses.insert(server.address) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Duplicate tunnel server name or TCP listener",
                ));
            }
            let endpoint = Arc::new(Endpoint::new(
                self.counters
                    .get(format!("endpoint/{}/accepted", server.address)),
                self.counters
                    .get(format!("endpoint/{}/credits", server.address)),
                server.max_connections,
            ));
            let mut peers = HashMap::new();
            let mut identities = HashMap::new();
            for (name, policy) in &server.peers {
                let key = format!("peer/{}/{name}", server.tunnel_server);
                let peer = Arc::new(Peer::new(
                    gate.clone(),
                    policy.clone(),
                    endpoint.clone(),
                    self.counters.get(format!("{key}/active")),
                    self.counters.get(format!("{key}/pending")),
                    self.counters.get(format!("{key}/physical")),
                ));
                for pin in crate::rustls_util::process_fingerprints(&policy.client_fingerprints)? {
                    identities.insert(pin, name.clone());
                }
                prepared
                    .registry
                    .0
                    .insert((server.tunnel_server.clone(), name.clone()), peer.clone());
                peers.insert(name.clone(), peer);
            }
            let runtime = Arc::new(server::Server {
                address: server.address,
                tls: tls::server(server)?,
                gate: gate.clone(),
                endpoint,
                peers,
                identities,
                handshakes: self
                    .counters
                    .get(format!("endpoint/{}/handshakes", server.address)),
                max_handshakes: server.max_handshakes,
            });
            prepared.tasks.push(Box::pin(runtime.run()));
        }
        let mut names = HashSet::new();
        for client in &config.tunnel_clients {
            client.validate()?;
            if !names.insert(&client.tunnel_client) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Duplicate tunnel client name",
                ));
            }
            let key = format!("client/{}", client.tunnel_client);
            let runtime = Arc::new(client::Client {
                config: client.clone(),
                connector: tls::client(client)?,
                gate: gate.clone(),
                resolver: self.resolver.clone(),
                active: self.counters.get(format!("{key}/active")),
                sockets: self.counters.get(format!("{key}/sockets")),
                local_dials: self.counters.get(format!("{key}/local_dials")),
                dials: Arc::new(tokio::sync::Semaphore::new(4)),
                jobs: self.counters.get(format!("{key}/jobs")),
            });
            prepared.tasks.push(Box::pin(runtime.run()));
        }
        Ok(prepared)
    }
}

impl Prepared {
    pub fn start(self, supervised: &mut JoinSet<io::Result<()>>) -> Arc<Gate> {
        self.gate.activate();
        let gate = self.gate.clone();
        if !self.tasks.is_empty() {
            supervised.spawn(self.run());
        }
        gate
    }

    async fn run(self) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        for task in self.tasks {
            tasks.spawn(task);
        }
        let result = tokio::select! {
            biased;
            _ = self.gate.stop.wait() => Ok(()),
            finished = tasks.join_next() => match finished {
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => Err(io::Error::other(error)),
                _ => Err(io::Error::other("Tunnel supervisor stopped unexpectedly")),
            },
        };
        self.gate.retire();
        if tokio::time::timeout(Duration::from_secs(5), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        result
    }
}
