use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use log::{debug, error, info, warn};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::timeout;
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

fn get_timestamp_secs() -> u32 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() as u32
}

fn create_boxed_slice(len: usize) -> Box<[u8]> {
    let mut buf = Vec::with_capacity(len);
    unsafe {
        buf.set_len(len);
    }
    buf.into_boxed_slice()
}

pub async fn run_udp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    target_configs: Vec<UdpTargetConfig>,
) -> std::io::Result<()> {
    let mut lookup_table = IpLookupTable::new();
    let mut associations: HashMap<(SocketAddr, UdpTargetAddress), Association> = HashMap::new();

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

        for (addr, masklen) in target_config.allowlist.into_iter() {
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

    let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(
        min_association_timeout_secs as u64,
    ));

    loop {
        select! {
            res = server_socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, addr)) => {
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

                        let mut copied_msg = create_boxed_slice(len);
                        copied_msg.copy_from_slice(&buf[0..len]);

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
                        let send_result = match associations.entry(key) {
                            Entry::Occupied(o) => {
                                o.get().try_send(copied_msg)
                            }
                            Entry::Vacant(v) => {
                                debug!("Creating new association: {} -> {}", &addr, &target_address);
                                let new_assoc = Association::new(
                                    addr,
                                    server_socket.clone(),
                                    target_address.clone(),
                                    target_data.association_timeout_secs,
                                );
                                v.insert(new_assoc)
                                    .try_send(copied_msg)
                            }
                        };
                        // Sends can fail if the channel is full.
                        if let Err(e) = send_result {
                            error!("Failed to send: {}", e);
                        }
                    }
                    Err(e) => {
                        panic!("Failed to receive from server socket: {}", e);
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                // TODO: use drain_filter when stabilized.
                let current_timestamp = get_timestamp_secs();
                let mut cleanup_keys = vec![];
                for (key, val) in associations.iter() {
                    if val.maybe_abort(current_timestamp) {
                        cleanup_keys.push(key.clone());
                    }
                }
                for key in cleanup_keys {
                    debug!("Removing association: {} -> {}", &key.0, &key.1);
                    associations.remove(&key).unwrap();
                }
            }
        }
    }
}

#[derive(Debug)]
enum AssociationMessage {
    Data(Box<[u8]>),
    Finish,
}

struct Association {
    last_active: Arc<AtomicU32>,
    tx: Sender<AssociationMessage>,
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

        let (tx, rx) = channel::<AssociationMessage>(1024);
        let join_handle = tokio::spawn(async move {
            if let Err(e) = run_forward_task(
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

    fn maybe_abort(&self, current_timestamp: u32) -> bool {
        let last_active = self.last_active.load(Ordering::SeqCst);
        if current_timestamp - last_active >= self.timeout_secs {
            self.abort();
            true
        } else {
            false
        }
    }

    fn abort(&self) {
        if let Err(e) = self.tx.try_send(AssociationMessage::Finish) {
            // There must be a ton of messages on the backlog?
            match e {
                TrySendError::Full(_) => {
                    // Set last active to 0, which is used as another indicator
                    // to break.
                    self.last_active.store(0, Ordering::Relaxed);
                }
                TrySendError::Closed(_) => {
                    // If the channel is already closed, then the task must
                    // already have ended and it got dropped.
                }
            }
        }
    }

    fn try_send(&self, data: Box<[u8]>) -> std::io::Result<()> {
        self.tx
            .try_send(AssociationMessage::Data(data))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

async fn run_forward_task(
    client_address: SocketAddr,
    server_socket: Arc<UdpSocket>,
    target_address: UdpTargetAddress,
    last_active: Arc<AtomicU32>,
    mut rx: Receiver<AssociationMessage>,
) -> std::io::Result<()> {
    let mut buf: [u8; MAX_UDP_PACKET_SIZE] =
        unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    let forward_send_timeout = tokio::time::Duration::from_millis(40);
    let forward_addr = resolve_host((target_address.address.as_str(), target_address.port)).await?;
    // TODO: bind to local interface only if forwarding to one.
    let forward_socket = UdpSocket::bind("0.0.0.0:0").await?;
    forward_socket.connect(forward_addr).await?;
    loop {
        select! {
            client_msg = rx.recv() => {
                match client_msg {
                    Some(AssociationMessage::Data(data)) => {
                        // This previously did a try_send, but it seemed to skip a lot of messages
                        // depending on udp buffer size (on linux, this defaults to 212992).

                        let send_future = timeout(
                            forward_send_timeout,
                            forward_socket.send(&data)
                        );

                        match send_future.await {
                            Ok(Ok(_)) => (),
                            Ok(Err(e)) => {
                                error!("Failed to forward data: {}", e);
                            },
                            Err(elapsed) => {
                                error!("Data forwarding timed out: {}", elapsed);
                            }
                        }

                        if last_active.swap(get_timestamp_secs(), Ordering::Relaxed) == 0 {
                            break;
                        }
                    }
                    Some(AssociationMessage::Finish) => {
                        break;
                    }
                    None => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "socket closed"));
                    }
                }
            }
            res = forward_socket.recv(&mut buf) => {
                let len = res?;
                // This could happen if things are congested, which is fine since we expect lossy
                // behavior with udp.
                // TODO: Unlike above, this doesn't seem to fail often with a try_send, perhaps due
                // to the Arc?
                if let Err(e) = server_socket.try_send_to(&buf[0..len], client_address) {
                    error!("Failed to relay response: {}", e);
                }
                if last_active.swap(get_timestamp_secs(), Ordering::Relaxed) == 0 {
                    break;
                }
            }
        }
    }
    debug!("Finishing forward task.");
    Ok(())
}
