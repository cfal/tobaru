use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use futures::join;
use ip_network_table_deps_treebitmap::IpLookupTable;
use log::{debug, error, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{interval_at, Duration, Instant};

use crate::config::{IpMask, IpMaskSelection, NetLocation, UdpTargetConfig};
use crate::iptables_util::{configure_iptables, Protocol};
use crate::tokio_util::resolve_host;

const MAX_UDP_PACKET_SIZE: usize = 65536;

const MIN_ASSOCIATION_TIMEOUT_SECS: u32 = 5;

// Informed by https://stackoverflow.com/questions/14856639/udp-hole-punching-timeout
const DEFAULT_ASSOCIATION_TIMEOUT_SECS: u32 = 200;

struct UdpTargetData {
    addresses: Vec<NetLocation>,
    next_address_index: AtomicUsize,
    association_timeout_secs: u32,
}

#[inline]
fn get_timestamp_secs() -> u32 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() as u32
}

pub fn prepare_udp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    max_associations: Option<NonZeroUsize>,
    target_configs: Vec<UdpTargetConfig>,
    mut stop: oneshot::Receiver<()>,
) -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>> + Send> {
    let mut lookup_table = IpLookupTable::new();

    let mut min_association_timeout_secs: u32 = 0;

    for target_config in target_configs {
        let UdpTargetConfig {
            addresses,
            allowlist,
            association_timeout_secs,
        } = target_config;

        let association_timeout_secs = std::cmp::max(
            MIN_ASSOCIATION_TIMEOUT_SECS,
            association_timeout_secs.unwrap_or(DEFAULT_ASSOCIATION_TIMEOUT_SECS),
        );
        if min_association_timeout_secs == 0 {
            min_association_timeout_secs = association_timeout_secs;
        } else {
            min_association_timeout_secs =
                std::cmp::min(min_association_timeout_secs, association_timeout_secs);
        }

        let target_data = Arc::new(UdpTargetData {
            addresses: addresses.into_vec(),
            next_address_index: AtomicUsize::new(0),
            association_timeout_secs,
        });

        for IpMask(addr, masklen) in allowlist.into_iter().map(IpMaskSelection::unwrap_literal) {
            if lookup_table
                .insert(addr, masklen, target_data.clone())
                .is_some()
            {
                return Err(std::io::Error::other(format!(
                    "Address {}/{} is duplicated in another target.",
                    addr, masklen
                )));
            }
        }
    }

    Ok(async move {
        if lookup_table.is_empty() {
            warn!(
                "Server does not accept any addresses, skipping: {}",
                server_address
            );
            return Ok(());
        }

        let server_socket = Arc::new(UdpSocket::bind(&server_address).await?);
        if use_iptables {
            let ip_masks: Vec<IpMask> = lookup_table
                .iter()
                .map(|(addr, masklen, _)| IpMask(addr, masklen))
                .collect();
            configure_iptables(Protocol::Udp, server_address, &ip_masks).await?;
        }

        for entry in lookup_table.iter() {
            debug!("Lookup table entry: {:?} (masklen {})", entry.0, entry.1);
        }

        println!("Listening (UDP): {}", server_address);

        let mut buf = [0u8; MAX_UDP_PACKET_SIZE];

        let mut associations = HashMap::new();
        let mut tasks = JoinSet::new();
        let cleanup_interval = Duration::from_secs(min_association_timeout_secs as u64);
        let mut cleanup = interval_at(Instant::now() + cleanup_interval, cleanup_interval);

        let result = loop {
            let received = tokio::select! {
                _ = cleanup.tick() => {
                    cleanup_associations(&mut associations);
                    continue;
                }
                _ = tasks.join_next(), if !tasks.is_empty() => continue,
                received = receive_until_stopped(server_socket.recv_from(&mut buf), &mut stop) => received,
            };
            let (len, addr) = match received {
                Ok(Some(packet)) => packet,
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            };

            let ip = match addr.ip() {
                IpAddr::V4(a) => a.to_ipv6_mapped(),
                IpAddr::V6(a) => a,
            };

            let target_data = match lookup_table.longest_match(ip) {
                Some((_, _, d)) => d,
                None => {
                    // Not allowed.
                    warn!("Unknown address, ignoring: {}", addr.ip());
                    continue;
                }
            };

            let send_result = forward_packet(
                &mut associations,
                max_associations,
                addr,
                &server_socket,
                target_data,
                &buf[..len],
                &mut tasks,
            );

            // Sends can fail if the channel is full.
            if let Err(e) = send_result {
                error!("Failed to send: {}", e);
            }
        };
        // Association tasks retain the listening socket, including expired tasks
        // whose cancellation has not completed yet. Join all before rebinding.
        tasks.shutdown().await;
        result
    })
}

async fn receive_until_stopped<T>(
    receive: impl std::future::Future<Output = std::io::Result<T>>,
    stop: &mut oneshot::Receiver<()>,
) -> std::io::Result<Option<T>> {
    tokio::select! {
        biased;
        result = receive => {
            let packet = result?;
            // Preserve ready errors, but do not let successful traffic starve shutdown.
            match stop.try_recv() {
                Err(oneshot::error::TryRecvError::Empty) => Ok(Some(packet)),
                _ => Ok(None),
            }
        }
        _ = &mut *stop => Ok(None),
    }
}

fn forward_packet(
    associations: &mut HashMap<SocketAddr, Association>,
    max_associations: Option<NonZeroUsize>,
    addr: SocketAddr,
    server_socket: &Arc<UdpSocket>,
    target_data: &UdpTargetData,
    packet: &[u8],
    tasks: &mut JoinSet<()>,
) -> std::io::Result<()> {
    let at_capacity = max_associations.is_some_and(|limit| associations.len() >= limit.get());
    let association = match associations.entry(addr) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(_) if at_capacity => return Ok(()),
        Entry::Vacant(entry) => {
            // fetch_add wraps around on overflow.
            let index = target_data
                .next_address_index
                .fetch_add(1, Ordering::Relaxed);
            let target_address = &target_data.addresses[index % target_data.addresses.len()];
            debug!("Creating new association: {} -> {}", addr, target_address);
            entry.insert(Association::new(
                addr,
                server_socket.clone(),
                target_address.clone(),
                target_data.association_timeout_secs,
                tasks,
            ))
        }
    };
    association.try_send(packet.to_vec().into_boxed_slice())
}

#[cfg(test)]
struct TaskDropGuard<T>(tokio::task::JoinHandle<T>);
#[cfg(test)]
impl<T> Drop for TaskDropGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn cleanup_associations(associations: &mut HashMap<SocketAddr, Association>) {
    let current_timestamp = get_timestamp_secs();
    associations.retain(|address, association| {
        let last_active = association.last_active.load(Ordering::SeqCst);
        if current_timestamp - last_active < association.timeout_secs {
            true
        } else {
            debug!("Removing association: {:?}", address);
            false
        }
    });
}

struct Association {
    last_active: Arc<AtomicU32>,
    tx: Sender<Box<[u8]>>,
    join_handle: AbortHandle,
    timeout_secs: u32,
}

impl Association {
    fn new(
        client_address: SocketAddr,
        server_socket: Arc<UdpSocket>,
        target_address: NetLocation,
        timeout_secs: u32,
        tasks: &mut JoinSet<()>,
    ) -> Self {
        let last_active = Arc::new(AtomicU32::new(get_timestamp_secs()));
        let cloned_last_active = last_active.clone();

        let (tx, rx) = channel::<Box<[u8]>>(1024);
        let join_handle = tasks.spawn(async move {
            if let Err(e) = run_forward_tasks(
                client_address,
                server_socket,
                target_address,
                cloned_last_active,
                rx,
            )
            .await
            {
                error!("Forward task finished with error: {}", e);
            }
        });

        Self {
            last_active,
            tx,
            join_handle,
            timeout_secs,
        }
    }

    fn try_send(&self, data: Box<[u8]>) -> std::io::Result<()> {
        self.tx.try_send(data).map_err(std::io::Error::other)
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

async fn run_forward_to_target_task(
    mut rx: Receiver<Box<[u8]>>,
    forward_socket: Arc<UdpSocket>,
    last_active: Arc<AtomicU32>,
) {
    while let Some(data) = rx.recv().await {
        // This previously did a try_send, but it seemed to skip a lot of messages
        // depending on udp buffer size (on linux, this defaults to 212992).
        if let Err(e) = forward_socket.send(&data).await {
            error!("Failed to forward data: {}", e);
        }

        last_active.store(get_timestamp_secs(), Ordering::Relaxed);
    }
}

async fn run_forward_from_target_task(
    forward_socket: Arc<UdpSocket>,
    server_socket: Arc<UdpSocket>,
    client_address: SocketAddr,
    last_active: Arc<AtomicU32>,
) {
    let mut buf = [0u8; MAX_UDP_PACKET_SIZE];
    while let Ok(len) = forward_socket.recv(&mut buf).await {
        if let Err(e) = server_socket.send_to(&buf[0..len], client_address).await {
            error!("Failed to relay response: {}", e);
        }
        last_active.store(get_timestamp_secs(), Ordering::Relaxed);
    }
}

async fn run_forward_tasks(
    client_address: SocketAddr,
    server_socket: Arc<UdpSocket>,
    target_address: NetLocation,
    last_active: Arc<AtomicU32>,
    rx: Receiver<Box<[u8]>>,
) -> std::io::Result<()> {
    let forward_addr = resolve_host((target_address.address.as_str(), target_address.port)).await?;
    let bind_address = if forward_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let forward_socket = UdpSocket::bind(bind_address).await.map(Arc::new)?;
    forward_socket.connect(forward_addr).await?;

    join!(
        run_forward_to_target_task(rx, forward_socket.clone(), last_active.clone()),
        run_forward_from_target_task(forward_socket, server_socket, client_address, last_active)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_preserves_ready_receive_errors_but_not_successful_packets() {
        for fail in [false, true] {
            let (send_stop, mut stop) = oneshot::channel();
            send_stop.send(()).unwrap();
            let received = if fail {
                Err(std::io::Error::other("receive failed"))
            } else {
                Ok(42)
            };
            let result = receive_until_stopped(std::future::ready(received), &mut stop).await;
            if fail {
                assert_eq!(result.unwrap_err().to_string(), "receive failed");
            } else {
                assert_eq!(result.unwrap(), None);
            }
        }
        let (send_stop, mut stop) = oneshot::channel();
        drop(send_stop);
        assert_eq!(
            receive_until_stopped(std::future::pending::<std::io::Result<()>>(), &mut stop)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn association_cap_preserves_existing_clients_and_recovers_after_cleanup() {
        let backend = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let server = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let target = UdpTargetData {
            addresses: vec![NetLocation::try_from(
                format!("127.0.0.1:{}", backend.local_addr().unwrap().port()).as_str(),
            )
            .unwrap()],
            next_address_index: AtomicUsize::new(0),
            association_timeout_secs: 5,
        };
        let mut associations = HashMap::new();
        let mut tasks = JoinSet::new();
        let first = "127.0.0.1:1".parse().unwrap();
        let second = "127.0.0.1:2".parse().unwrap();
        let cap = NonZeroUsize::new(1);
        let mut bytes = [0; 32];

        forward_packet(
            &mut associations,
            cap,
            first,
            &server,
            &target,
            b"first",
            &mut tasks,
        )
        .unwrap();
        let (length, peer) = backend.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"first");
        forward_packet(
            &mut associations,
            cap,
            second,
            &server,
            &target,
            b"dropped",
            &mut tasks,
        )
        .unwrap();
        assert!(!associations.contains_key(&second));
        forward_packet(
            &mut associations,
            cap,
            first,
            &server,
            &target,
            b"existing",
            &mut tasks,
        )
        .unwrap();
        let (length, same_peer) = backend.recv_from(&mut bytes).await.unwrap();
        assert_eq!(peer, same_peer);
        assert_eq!(&bytes[..length], b"existing");

        associations[&first]
            .last_active
            .store(get_timestamp_secs() - 10, Ordering::SeqCst);
        cleanup_associations(&mut associations);
        assert!(associations.is_empty());
        forward_packet(
            &mut associations,
            cap,
            second,
            &server,
            &target,
            b"new",
            &mut tasks,
        )
        .unwrap();
        let (length, _) = backend.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"new");

        forward_packet(
            &mut associations,
            None,
            first,
            &server,
            &target,
            b"unlimited",
            &mut tasks,
        )
        .unwrap();
        assert_eq!(associations.len(), 2);
        let (length, _) = backend.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"unlimited");
    }

    #[tokio::test]
    async fn associations_relay_to_ipv4_and_ipv6_targets() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for bind_address in ["0.0.0.0:0", "[::]:0"] {
                let backend = UdpSocket::bind(bind_address).await.unwrap();
                let bound = backend.local_addr().unwrap();
                let upstream = SocketAddr::new(
                    if bound.is_ipv4() {
                        "127.0.0.1".parse().unwrap()
                    } else {
                        "::1".parse().unwrap()
                    },
                    bound.port(),
                );
                let server = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
                let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                let client_address = SocketAddr::new(
                    "127.0.0.1".parse().unwrap(),
                    client.local_addr().unwrap().port(),
                );
                let (tx, rx) = channel(1);
                let task = TaskDropGuard(tokio::spawn(run_forward_tasks(
                    client_address,
                    server,
                    NetLocation::try_from(upstream.to_string().as_str()).unwrap(),
                    Arc::new(AtomicU32::new(get_timestamp_secs())),
                    rx,
                )));
                tx.send(b"request".to_vec().into_boxed_slice())
                    .await
                    .unwrap();
                let mut bytes = [0; 32];
                let (length, peer) = backend.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..length], b"request");
                assert_eq!(peer.is_ipv4(), bound.is_ipv4());
                backend.send_to(b"response", peer).await.unwrap();
                let length = client.recv(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..length], b"response");
                drop(task);
            }
        })
        .await
        .expect("UDP relay timed out");
    }
}
