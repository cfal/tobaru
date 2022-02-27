use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use futures::join;
use log::{debug, error, warn};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use treebitmap::IpLookupTable;

use crate::config::{UdpTargetAddress, UdpTargetConfig};
use crate::iptables_util::{configure_iptables, Protocol};
use crate::tokio_util::resolve_host;

const MAX_UDP_PACKET_SIZE: usize = 65536;

const MIN_ASSOCIATION_TIMEOUT_SECS: u32 = 5;

// Informed by https://stackoverflow.com/questions/14856639/udp-hole-punching-timeout
const DEFAULT_ASSOCIATION_TIMEOUT_SECS: u32 = 200;

struct UdpTargetData {
    addresses: Vec<UdpTargetAddress>,
    next_address_index: AtomicUsize,
    association_timeout_secs: u32,
}

#[inline]
fn get_timestamp_secs() -> u32 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() as u32
}

pub async fn run_udp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    target_configs: Vec<UdpTargetConfig>,
) -> std::io::Result<()> {
    let mut lookup_table = IpLookupTable::new();
    let associations: Arc<Mutex<HashMap<(SocketAddr, UdpTargetAddress), Association>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut min_association_timeout_secs: u32 = 0;

    for target_config in target_configs {
        let association_timeout_secs = std::cmp::max(
            MIN_ASSOCIATION_TIMEOUT_SECS,
            target_config
                .association_timeout_secs
                .unwrap_or(DEFAULT_ASSOCIATION_TIMEOUT_SECS),
        );
        if min_association_timeout_secs == 0 {
            min_association_timeout_secs = association_timeout_secs;
        } else {
            min_association_timeout_secs =
                std::cmp::min(min_association_timeout_secs, association_timeout_secs);
        }

        let target_data = Arc::new(UdpTargetData {
            addresses: target_config.target_addresses,
            next_address_index: AtomicUsize::new(0),
            association_timeout_secs,
        });

        for (addr, masklen) in target_config.allowed_ips.into_iter() {
            if lookup_table
                .insert(addr, masklen, target_data.clone())
                .is_some()
            {
                panic!(
                    "Address {}/{} is duplicated in another target.",
                    addr, masklen
                );
            }
        }
    }

    if lookup_table.is_empty() {
        warn!(
            "Server does not accept any addresses, skipping: {}",
            server_address
        );
        return Ok(());
    }

    if use_iptables {
        let ip_masks: Vec<(std::net::Ipv6Addr, u32)> = lookup_table
            .iter()
            .map(|(addr, masklen, _)| (addr, masklen))
            .collect();
        configure_iptables(Protocol::Udp, server_address, &ip_masks);
    }

    for entry in lookup_table.iter() {
        debug!("Lookup table entry: {:?} (masklen {})", &entry.0, &entry.1);
    }

    let server_socket = Arc::new(UdpSocket::bind(&server_address).await?);
    println!("Listening (UDP): {}", server_address);

    let mut buf = [0u8; MAX_UDP_PACKET_SIZE];

    start_cleanup_task(associations.clone(), min_association_timeout_secs);

    loop {
        let (len, addr) = server_socket
            .recv_from(&mut buf)
            .await
            .expect("Could not read from server socket");

        let ip = match addr.ip() {
            IpAddr::V4(a) => a.to_ipv6_mapped(),
            IpAddr::V6(a) => a,
        };

        let target_data = match lookup_table.longest_match(ip) {
            Some((_, _, d)) => d.clone(),
            None => {
                // Not allowed.
                warn!("Unknown address, ignoring: {}", addr.ip());
                continue;
            }
        };

        let copied_msg = buf[0..len].to_vec().into_boxed_slice();

        let target_address = if target_data.addresses.len() > 1 {
            // fetch_add wraps around on overflow.
            let index = target_data
                .next_address_index
                .fetch_add(1, Ordering::Relaxed);
            &target_data.addresses[index % target_data.addresses.len()]
        } else {
            &target_data.addresses[0]
        };

        // Use `addr` here for the key, we only need `ip` for the lookup.
        let key = (addr, target_address.clone());
        let send_result = match associations.lock().entry(key) {
            Entry::Occupied(o) => o.get().try_send(copied_msg),
            Entry::Vacant(v) => {
                debug!("Creating new association: {} -> {}", &addr, &target_address);
                let new_assoc = Association::new(
                    addr,
                    server_socket.clone(),
                    target_address.clone(),
                    target_data.association_timeout_secs,
                );
                v.insert(new_assoc).try_send(copied_msg)
            }
        };

        // Sends can fail if the channel is full.
        if let Err(e) = send_result {
            error!("Failed to send: {}", e);
        }
    }
}

fn start_cleanup_task(
    associations: Arc<Mutex<HashMap<(SocketAddr, UdpTargetAddress), Association>>>,
    min_association_timeout_secs: u32,
) {
    let cleanup_interval = Duration::from_secs(min_association_timeout_secs as u64);

    tokio::spawn(async move {
        loop {
            sleep(cleanup_interval).await;
            let current_timestamp = get_timestamp_secs();
            associations.lock().retain(|k, val| {
                let last_active = val.last_active.load(Ordering::SeqCst);
                if current_timestamp - last_active < val.timeout_secs {
                    true
                } else {
                    debug!("Removing association: {:?}", k);
                    false
                }
            });
        }
    });
}

struct Association {
    last_active: Arc<AtomicU32>,
    tx: Sender<Box<[u8]>>,
    join_handle: JoinHandle<()>,
    timeout_secs: u32,
}

impl Association {
    fn new(
        client_address: SocketAddr,
        server_socket: Arc<UdpSocket>,
        target_address: UdpTargetAddress,
        timeout_secs: u32,
    ) -> Self {
        let last_active = Arc::new(AtomicU32::new(get_timestamp_secs()));
        let cloned_last_active = last_active.clone();

        let (tx, rx) = channel::<Box<[u8]>>(1024);
        let join_handle = tokio::spawn(async move {
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
        self.tx
            .try_send(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
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
    let mut buf: [u8; MAX_UDP_PACKET_SIZE] =
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
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
    target_address: UdpTargetAddress,
    last_active: Arc<AtomicU32>,
    rx: Receiver<Box<[u8]>>,
) -> std::io::Result<()> {
    let forward_addr = resolve_host((target_address.address.as_str(), target_address.port)).await?;
    // TODO: bind to local interface only if forwarding to one.
    let forward_socket = UdpSocket::bind("0.0.0.0:0").await.map(Arc::new)?;
    forward_socket.connect(forward_addr).await?;

    join!(
        run_forward_to_target_task(rx, forward_socket.clone(), last_active.clone()),
        run_forward_from_target_task(forward_socket, server_socket, client_address, last_active)
    );
    Ok(())
}
