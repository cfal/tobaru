use std::collections::hash_map::{Entry, RandomState};
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash};
use std::lazy::SyncOnceCell;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::join;
use ip_network_table_deps_treebitmap::IpLookupTable;
use log::{debug, error, warn};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio_rustls::LazyConfigAcceptor;

use crate::async_stream::AsyncStream;
use crate::config::{
    ClientTlsConfig, IpMask, IpMaskSelection, Location, NetLocation, ServerTlsConfig,
    TcpTargetConfig, TlsOption,
};
use crate::copy_bidirectional::copy_bidirectional;
use crate::iptables_util::{configure_iptables, Protocol};
use crate::rustls_util::{
    create_connector, create_server_config, get_dummy_server_name, load_certs, load_private_key,
};
use crate::tokio_util::resolve_host;

struct TargetLocationData {
    pub location: Location,
    pub tls_connector: Option<tokio_rustls::TlsConnector>,
}

struct TargetData {
    pub location_data: Vec<TargetLocationData>,
    pub next_address_index: AtomicUsize,
    pub tcp_nodelay: bool,
}

struct TlsTargetData {
    pub allow_no_alpn: bool,
    pub allow_any_alpn: bool,
    pub alpn_protocol_hashes: HashSet<u64>,
    pub ip_lookup_table: IpLookupTable<Ipv6Addr, bool>,
    pub alpn_tls_config: Arc<rustls::ServerConfig>,
    pub no_alpn_tls_config: Arc<rustls::ServerConfig>,
    pub target_data: Arc<TargetData>,
}

const BUFFER_SIZE: usize = 8192;

fn hash_alpn<T: Hash>(x: T) -> u64 {
    static ALPN_HASHER: SyncOnceCell<RandomState> = SyncOnceCell::new();
    ALPN_HASHER.get_or_init(RandomState::new).hash_one(x)
}

pub async fn run_tcp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    target_configs: Vec<TcpTargetConfig>,
) -> std::io::Result<()> {
    let mut non_tls_lookup_table: IpLookupTable<Ipv6Addr, Arc<TargetData>> = IpLookupTable::new();

    let mut tls_lookup_table: IpLookupTable<Ipv6Addr, bool> = IpLookupTable::new();
    let mut sni_lookup_map: HashMap<TlsOption, Vec<Arc<TlsTargetData>>> = HashMap::new();

    let mut iptable_masks = vec![];

    for target_config in target_configs {
        let TcpTargetConfig {
            allowlist,
            locations,
            server_tls,
            tcp_nodelay,
        } = target_config;

        let allowlist = allowlist
            .into_iter()
            .map(IpMaskSelection::unwrap_literal)
            .collect::<Vec<_>>();

        let location_data = locations
            .into_iter()
            .map(|target_location| {
                let (location, client_tls) = target_location.into_components();
                TargetLocationData {
                    location: location,
                    tls_connector: match client_tls {
                        ClientTlsConfig::Enabled => Some(create_connector(true)),
                        ClientTlsConfig::EnabledWithoutVerify => Some(create_connector(false)),
                        ClientTlsConfig::Disabled => None,
                    },
                }
            })
            .collect();

        let target_data = Arc::new(TargetData {
            location_data,
            next_address_index: AtomicUsize::new(0),
            tcp_nodelay,
        });

        let is_non_tls_target = match server_tls {
            Some(ServerTlsConfig {
                sni_hostnames,
                alpn_protocols,
                cert,
                key,
                optional,
            }) => {
                let mut cert_file = File::open(&cert).await?;
                let mut cert_bytes = vec![];
                cert_file.read_to_end(&mut cert_bytes).await?;
                let certs = load_certs(&cert_bytes);

                let mut key_file = File::open(&key).await?;
                let mut key_bytes = vec![];
                key_file.read_to_end(&mut key_bytes).await?;
                let private_key = load_private_key(&key_bytes);

                let mut allow_no_alpn = false;
                let mut allow_any_alpn = false;
                let mut alpn_protocol_hashes = HashSet::new();
                let mut alpn_protocol_bytes = vec![];

                let alpn_protocols = if alpn_protocols.is_empty() {
                    vec![TlsOption::Any, TlsOption::None]
                } else {
                    alpn_protocols.into_vec()
                };

                for alpn_protocol in alpn_protocols.into_iter() {
                    match alpn_protocol {
                        TlsOption::None => {
                            allow_no_alpn = true;
                        }
                        TlsOption::Any => {
                            allow_any_alpn = true;
                        }
                        TlsOption::Specified(s) => {
                            let alpn_bytes = s.into_bytes();
                            alpn_protocol_hashes.insert(hash_alpn(&alpn_bytes));
                            alpn_protocol_bytes.push(alpn_bytes);
                        }
                    }
                }

                let (alpn_tls_config, no_alpn_tls_config) = if alpn_protocol_hashes.is_empty() {
                    let tls_config = Arc::new(create_server_config(
                        certs,
                        &private_key,
                        alpn_protocol_bytes,
                    ));
                    (tls_config.clone(), tls_config)
                } else {
                    let alpn_tls_config =
                        create_server_config(certs, &private_key, alpn_protocol_bytes);
                    let mut no_alpn_tls_config = alpn_tls_config.clone();
                    no_alpn_tls_config.alpn_protocols = vec![];
                    (Arc::new(alpn_tls_config), Arc::new(no_alpn_tls_config))
                };

                let mut config_lookup_table = IpLookupTable::new();
                for IpMask(addr, masklen) in allowlist.iter() {
                    // addresses can be the same across different TLS configs
                    let _ = tls_lookup_table.insert(addr.clone(), *masklen, true);

                    // .. but shouldn't be duplicated in a single config.
                    if config_lookup_table
                        .insert(addr.clone(), *masklen, true)
                        .is_some()
                    {
                        panic!(
                            "Address {}/{} is duplicated in the TLS config.",
                            addr, masklen
                        );
                    }
                }

                let tls_target_data = Arc::new(TlsTargetData {
                    allow_no_alpn,
                    allow_any_alpn,
                    alpn_protocol_hashes,
                    ip_lookup_table: config_lookup_table,
                    alpn_tls_config,
                    no_alpn_tls_config,
                    target_data: target_data.clone(),
                });

                let sni_hostnames = if sni_hostnames.is_empty() {
                    vec![TlsOption::Any, TlsOption::None]
                } else {
                    sni_hostnames.into_vec()
                };

                for sni_hostname in sni_hostnames.into_iter() {
                    match sni_lookup_map.entry(sni_hostname) {
                        Entry::Occupied(mut o) => {
                            o.get_mut().push(tls_target_data.clone());
                        }
                        Entry::Vacant(v) => {
                            v.insert(vec![tls_target_data.clone()]);
                        }
                    }
                }

                optional
            }
            None => true,
        };

        if is_non_tls_target {
            for IpMask(addr, masklen) in allowlist.iter() {
                if non_tls_lookup_table
                    .insert(addr.clone(), *masklen, target_data.clone())
                    .is_some()
                {
                    panic!(
                        "Address {}/{} is duplicated in another non-tls target.",
                        addr, masklen
                    );
                }
            }
        }

        iptable_masks.extend(allowlist.into_iter());
    }

    if use_iptables {
        configure_iptables(Protocol::Tcp, server_address.clone(), &iptable_masks).await;
    }

    // TODO: check that there is only a single item under TlsOption::None and TlsOption::Any
    let sni_lookup_map = Arc::new(sni_lookup_map);

    let listener = TcpListener::bind(server_address).await.unwrap();
    println!("Listening (TCP): {}", listener.local_addr().unwrap());

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {:?}", e);
                continue;
            }
        };

        let ip = match addr.ip() {
            IpAddr::V4(a) => a.to_ipv6_mapped(),
            IpAddr::V6(a) => a,
        };

        let non_tls_data = non_tls_lookup_table
            .longest_match(ip.clone())
            .map(|(_, _, m)| m.clone());
        let has_tls_data = tls_lookup_table.longest_match(ip).is_some();

        if non_tls_data.is_none() && !has_tls_data {
            warn!("Unknown address, not allowing: {}", addr.ip());
            continue;
        }

        if has_tls_data {
            let cloned_sni_map = sni_lookup_map.clone();
            // TODO: determine if it's a TLS connection, and act accordingly.
            // if non_tls_data is None, then it's definitely a TLS connection.
            tokio::spawn(async move {
                if let Err(e) =
                    process_tls_stream(stream, &addr, ip, non_tls_data, cloned_sni_map).await
                {
                    error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
                } else {
                    debug!("{}:{} finished successfully", addr.ip(), addr.port());
                }
            });
        } else {
            tokio::spawn(async move {
                if let Err(e) =
                    process_generic_stream(Box::new(stream), &addr, non_tls_data.unwrap()).await
                {
                    error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
                } else {
                    debug!("{}:{} finished successfully", addr.ip(), addr.port());
                }
            });
        }
    }
}

async fn process_tls_stream(
    stream: TcpStream,
    addr: &std::net::SocketAddr,
    ip: Ipv6Addr,
    non_tls_data: Option<Arc<TargetData>>,
    sni_lookup_map: Arc<HashMap<TlsOption, Vec<Arc<TlsTargetData>>>>,
) -> std::io::Result<()> {
    if non_tls_data.is_some() {
        let is_tls_client_hello = peek_tls_client_hello(&stream).await?;
        if !is_tls_client_hello {
            return process_generic_stream(Box::new(stream), addr, non_tls_data.unwrap()).await;
        }
    }

    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::new().unwrap(), stream);
    let start_handshake = acceptor.await?;
    let client_hello = start_handshake.client_hello();
    let sni_hostname = client_hello
        .server_name()
        .map(|s| TlsOption::Specified(s.to_string()))
        .unwrap_or(TlsOption::None);

    let sni_data_vec = match sni_lookup_map.get(&sni_hostname) {
        Some(v) => {
            debug!("Matched SNI option: {:?}", sni_hostname);
            v
        }
        None => {
            if !sni_hostname.is_specified() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no matching SNI hostname",
                ));
            }
            match sni_lookup_map.get(&TlsOption::Any) {
                Some(v) => v,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "no matching SNI hostname: {}",
                            sni_hostname.unwrap_specified()
                        ),
                    ));
                }
            }
        }
    };

    let alpn_protocol_hashes: HashSet<u64> = client_hello
        .alpn()
        .map(|alpn_iter| alpn_iter.map(hash_alpn).collect())
        .unwrap_or_else(HashSet::new);

    for sni_data in sni_data_vec {
        if sni_data.ip_lookup_table.longest_match(ip.clone()).is_some() {
            let tls_config = if alpn_protocol_hashes.is_empty() {
                if !sni_data.allow_no_alpn {
                    continue;
                }
                sni_data.no_alpn_tls_config.clone()
            } else {
                if !alpn_protocol_hashes.is_disjoint(&sni_data.alpn_protocol_hashes) {
                    sni_data.alpn_tls_config.clone()
                } else if sni_data.allow_any_alpn {
                    // allow any ALPN - don't do ALPN negotiation since the requested ALPNs don't
                    // match any of the specified ones.
                    sni_data.no_alpn_tls_config.clone()
                } else {
                    continue;
                }
            };

            let tls_stream = start_handshake
                .into_stream_with(tls_config, |server_conn| {
                    server_conn.set_buffer_limit(Some(32768));
                })
                .await?;

            return process_generic_stream(
                Box::new(tls_stream),
                addr,
                sni_data.target_data.clone(),
            )
            .await;
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!(
            "no matching alpn ({})",
            client_hello
                .alpn()
                .map(|alpn_iter| {
                    alpn_iter
                        .map(|alpn_bytes| {
                            std::str::from_utf8(alpn_bytes)
                                .map(String::from)
                                .unwrap_or(format!("{:?}", alpn_bytes))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .as_ref()
                .map(String::as_str)
                .unwrap_or("not negotiated")
        ),
    ))
}

async fn process_generic_stream(
    mut source_stream: Box<dyn AsyncStream>,
    addr: &std::net::SocketAddr,
    target_data: Arc<TargetData>,
) -> std::io::Result<()> {
    let target_location = if target_data.location_data.len() > 1 {
        // fetch_add wraps around on overflow.
        let index = target_data
            .next_address_index
            .fetch_add(1, Ordering::Relaxed);
        &target_data.location_data[index % target_data.location_data.len()]
    } else {
        &target_data.location_data[0]
    };

    let mut target_stream =
        match setup_target_stream(addr, &target_location, target_data.tcp_nodelay).await {
            Ok(s) => s,
            Err(e) => {
                source_stream.try_shutdown().await?;
                return Err(e);
            }
        };

    debug!(
        "Copying: {}:{} to {}",
        addr.ip(),
        addr.port(),
        &target_location.location,
    );

    let copy_result = copy_bidirectional(&mut source_stream, &mut target_stream, BUFFER_SIZE).await;

    debug!(
        "Shutdown: {}:{} to {}",
        addr.ip(),
        addr.port(),
        &target_location.location,
    );

    let (_, _) = join!(source_stream.try_shutdown(), target_stream.try_shutdown());

    debug!(
        "Done: {}:{} to {}",
        addr.ip(),
        addr.port(),
        &target_location.location,
    );

    copy_result?;

    Ok(())
}

async fn peek_tls_client_hello(stream: &TcpStream) -> std::io::Result<bool> {
    // Logic was taken from boost docs:
    // https://www.boost.org/doc/libs/1_70_0/libs/beast/doc/html/beast/using_io/writing_composed_operations/detect_ssl.html

    let mut buf = [0u8; 9];
    for _ in 0..3 {
        let count = stream.peek(&mut buf).await?;

        if count >= 1 {
            // Require the first byte to be 0x16, indicating a TLS handshake record
            if buf[0] != 0x16 {
                return Ok(false);
            }

            if count >= 5 {
                // Calculate the record payload size
                let length: u32 = ((buf[3] as u32) << 8) + (buf[4] as u32);

                // A ClientHello message payload is at least 34 bytes.
                // There can be multiple handshake messages in the same record.
                if length < 34 {
                    return Ok(false);
                }

                if count >= 6 {
                    // The handshake_type must be 0x01 == client_hello
                    if buf[5] != 0x01 {
                        return Ok(false);
                    }

                    if count >= 9 {
                        // Calculate the message payload size
                        let size: u32 =
                            ((buf[6] as u32) << 16) + ((buf[7] as u32) << 8) + (buf[8] as u32);

                        // The message payload can't be bigger than the enclosing record
                        if size + 4 > length {
                            return Ok(false);
                        }

                        // This can only be a TLS client_hello message
                        return Ok(true);
                    }
                }
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    debug!("Unable to fetch all bytes to determine TLS.");

    // If we get here, then we didn't have enough bytes after several iterations
    // of the for loop. It could be possible that the client expects a server response
    // first before sending more bytes, so just assume it's not a TLS connection.
    Ok(false)
}

async fn setup_target_stream(
    addr: &std::net::SocketAddr,
    target_location: &TargetLocationData,
    tcp_nodelay: bool,
) -> std::io::Result<Box<dyn AsyncStream>> {
    match target_location.location {
        Location::Address(NetLocation { ref address, port }) => {
            let target_addr = resolve_host((address.as_str(), port)).await?;
            let tcp_stream = TcpStream::connect(target_addr).await?;
            if tcp_nodelay {
                if let Err(e) = tcp_stream.set_nodelay(true) {
                    error!("Failed to set tcp_nodelay: {}", e);
                }
            }
            debug!(
                "Connected to remote: {} using local addr {}",
                addr,
                tcp_stream.local_addr().unwrap()
            );

            if let Some(ref connector) = target_location.tls_connector {
                // TODO: allow specifying or disabling SNI
                let server_name = match rustls::ServerName::try_from(address.as_str()) {
                    Ok(s) => s,
                    Err(_) => get_dummy_server_name(),
                };
                let tls_stream = connector
                    .connect_with(server_name, tcp_stream, |server_conn| {
                        server_conn.set_buffer_limit(Some(32768));
                    })
                    .await?;
                Ok(Box::new(tls_stream))
            } else {
                Ok(Box::new(tcp_stream))
            }
        }
        Location::Path(ref path_buf) => {
            let unix_stream = UnixStream::connect(path_buf.as_path()).await?;
            debug!(
                "Connected to unix domain socket: {} using local addr {:?}",
                path_buf.as_path().display(),
                unix_stream.local_addr().unwrap()
            );

            if let Some(ref connector) = target_location.tls_connector {
                // TODO: allow specifying or disabling SNI
                let server_name = get_dummy_server_name();
                let tls_stream = connector
                    .connect_with(server_name, unix_stream, |server_conn| {
                        server_conn.set_buffer_limit(Some(32768));
                    })
                    .await?;
                Ok(Box::new(tls_stream))
            } else {
                Ok(Box::new(unix_stream))
            }
        }
    }
}
