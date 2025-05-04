use std::collections::hash_map::{Entry, RandomState};
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use futures::join;
use ip_network_table_deps_treebitmap::IpLookupTable;
use log::{debug, error, warn};
use radix_trie::Trie;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::time::{sleep, timeout, Duration};
use tokio_rustls::LazyConfigAcceptor;

use crate::async_stream::AsyncStream;
use crate::config::{
    ClientTlsConfig, HttpForwardConfig, HttpHeaderPatch, HttpPathAction, HttpServeDirectoryConfig,
    HttpServeMessageConfig, HttpTcpActionConfig, HttpValueMatch, IpMask, IpMaskSelection, Location,
    NetLocation, RawTcpActionConfig, ServerTlsConfig, TcpAction, TcpTargetConfig,
    TcpTargetLocation, TlsOption,
};
use crate::copy_bidirectional::copy_bidirectional;
use crate::http::handle_http_stream;
use crate::iptables_util::{configure_iptables, Protocol};
use crate::rustls_util::{
    create_connector, create_server_config, get_dummy_server_name, load_certs, load_private_key,
};
use crate::tokio_util::resolve_host;

pub struct TargetLocationData {
    pub location: Location,
    pub tls_connector: Option<tokio_rustls::TlsConnector>,
}

impl From<TcpTargetLocation> for TargetLocationData {
    fn from(tcp_target_location: TcpTargetLocation) -> Self {
        let (location, client_tls) = tcp_target_location.into_components();
        Self {
            location,
            tls_connector: match client_tls {
                ClientTlsConfig::Enabled => Some(create_connector(true)),
                ClientTlsConfig::EnabledWithoutVerify => Some(create_connector(false)),
                ClientTlsConfig::Disabled => None,
            },
        }
    }
}

pub struct TargetData {
    pub tcp_nodelay: bool,
    pub action_data: TargetActionData,
}

pub enum TargetActionData {
    Raw {
        location_data: Vec<TargetLocationData>,
        next_address_index: AtomicUsize,
    },
    Http {
        path_configs: Trie<String, Vec<TargetHttpPathData>>,
        default_http_action: TargetHttpActionData,
    },
}

pub struct TargetHttpPathData {
    pub required_request_headers: Option<HashMap<String, HttpValueMatch>>,
    pub http_action: TargetHttpActionData,
}

// TODO: preprocess some of these fields, eg status_code/status_message/content into a single
// prepared response.
pub enum TargetHttpActionData {
    CloseConnection,
    ServeMessage {
        status_code: u16,
        status_message: Option<String>,
        content: String,
        response_headers: HashMap<String, String>,
        response_id_header_name: Option<String>,
    },
    ServeDirectory {
        path: String,
        response_headers: HashMap<String, String>,
        response_id_header_name: Option<String>,
    },
    Forward {
        location_data: Vec<TargetLocationData>,
        next_address_index: AtomicUsize,
        // replacement paths are best effort - it's entirely possible that absolute paths are specified
        // in the returned content and it would break.
        replacement_path: Option<String>,
        request_header_patch: Option<HttpHeaderPatch>,
        response_header_patch: Option<HttpHeaderPatch>,
        request_id_header_name: Option<String>,
        response_id_header_name: Option<String>,
    },
}

impl From<HttpPathAction> for TargetHttpActionData {
    fn from(http_path_action: HttpPathAction) -> Self {
        match http_path_action {
            HttpPathAction::CloseConnection => TargetHttpActionData::CloseConnection,
            HttpPathAction::ServeMessage(HttpServeMessageConfig {
                status_code,
                status_message,
                content,
                response_headers,
                response_id_header_name,
            }) => TargetHttpActionData::ServeMessage {
                status_code,
                status_message,
                content,
                response_headers,
                response_id_header_name,
            },
            HttpPathAction::ServeDirectory(HttpServeDirectoryConfig {
                path,
                response_headers,
                response_id_header_name,
            }) => TargetHttpActionData::ServeDirectory {
                path,
                response_headers,
                response_id_header_name,
            },
            HttpPathAction::Forward(HttpForwardConfig {
                locations,
                replacement_path,
                request_header_patch,
                response_header_patch,
                request_id_header_name,
                response_id_header_name,
            }) => TargetHttpActionData::Forward {
                location_data: locations
                    .into_iter()
                    .map(TargetLocationData::from)
                    .collect(),
                next_address_index: AtomicUsize::new(0),
                replacement_path,
                request_header_patch,
                response_header_patch,
                request_id_header_name,
                response_id_header_name,
            },
        }
    }
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

fn hash_alpn<T: Hash>(x: T) -> u64 {
    static ALPN_HASHER: OnceLock<RandomState> = OnceLock::new();
    ALPN_HASHER.get_or_init(RandomState::new).hash_one(x)
}

pub async fn run_tcp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    tcp_nodelay: bool,
    target_configs: Vec<TcpTargetConfig>,
) -> std::io::Result<()> {
    let mut non_tls_lookup_table: IpLookupTable<Ipv6Addr, Arc<TargetData>> = IpLookupTable::new();

    let mut tls_lookup_table: IpLookupTable<Ipv6Addr, bool> = IpLookupTable::new();
    let mut sni_lookup_map: HashMap<TlsOption, Vec<Arc<TlsTargetData>>> = HashMap::new();

    let mut iptable_masks = vec![];

    for target_config in target_configs {
        let TcpTargetConfig {
            allowlist,
            server_tls,
            tcp_nodelay,
            action,
            ..
        } = target_config;

        let allowlist = allowlist
            .into_iter()
            .map(IpMaskSelection::unwrap_literal)
            .collect::<Vec<_>>();

        let action_data = match action {
            TcpAction::Raw(RawTcpActionConfig { locations }) => TargetActionData::Raw {
                location_data: locations
                    .into_iter()
                    .map(TargetLocationData::from)
                    .collect(),
                next_address_index: AtomicUsize::new(0),
            },
            TcpAction::Http(HttpTcpActionConfig {
                http_paths,
                default_http_action,
            }) => {
                let mut path_configs = Trie::new();
                for (path, path_config_vec) in http_paths {
                    let path_data_vec = path_config_vec
                        .into_iter()
                        .map(|path_config| TargetHttpPathData {
                            required_request_headers: path_config.required_request_headers,
                            http_action: path_config.http_action.into(),
                        })
                        .collect();
                    path_configs.insert(path, path_data_vec);
                }
                TargetActionData::Http {
                    path_configs,
                    default_http_action: default_http_action.into(),
                }
            }
        };

        let target_data = Arc::new(TargetData {
            tcp_nodelay,
            action_data,
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
                    let _ = tls_lookup_table.insert(*addr, *masklen, true);

                    // .. but shouldn't be duplicated in a single config.
                    if config_lookup_table.insert(*addr, *masklen, true).is_some() {
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
                    .insert(*addr, *masklen, target_data.clone())
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
        configure_iptables(Protocol::Tcp, server_address, &iptable_masks).await;
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
            .longest_match(ip)
            .map(|(_, _, m)| m.clone());
        let has_tls_data = tls_lookup_table.longest_match(ip).is_some();

        if non_tls_data.is_none() && !has_tls_data {
            warn!("Unknown address, not allowing: {}", addr.ip());
            continue;
        }

        if tcp_nodelay {
            if let Err(e) = stream.set_nodelay(true) {
                error!("Failed to set tcp_nodelay on server stream: {}", e);
            }
        }

        if has_tls_data {
            let cloned_sni_map = sni_lookup_map.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    process_tls_stream(stream, &addr, ip, non_tls_data, cloned_sni_map).await
                {
                    error!("{} finished with error: {:?}", addr, e);
                } else {
                    debug!("{} finished successfully", addr);
                }
            });
        } else {
            tokio::spawn(async move {
                if let Err(e) =
                    run_stream_action(Box::new(stream), &addr, non_tls_data.unwrap()).await
                {
                    error!("{} finished with error: {:?}", addr, e);
                } else {
                    debug!("{} finished successfully", addr);
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
        let peek_client_hello_timeout =
            timeout(Duration::from_secs(5), peek_tls_client_hello(&stream));
        match peek_client_hello_timeout.await {
            Ok(peek_result) => {
                let is_tls_client_hello = peek_result?;
                if !is_tls_client_hello {
                    return run_stream_action(Box::new(stream), addr, non_tls_data.unwrap()).await;
                }
            }
            Err(_) => {
                warn!("TLS client hello read timed out, assuming non-TLS connection.");
                return run_stream_action(Box::new(stream), addr, non_tls_data.unwrap()).await;
            }
        }
    }

    let tls_handshake_timeout = timeout(
        Duration::from_secs(5),
        handle_tls_handshake(stream, addr, ip, sni_lookup_map),
    );

    let (tls_stream, target_data) = match tls_handshake_timeout.await {
        Ok(handshake_result) => handshake_result?,
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("tls handshake timed out: {}", elapsed),
            ));
        }
    };

    run_stream_action(tls_stream, addr, target_data).await
}

async fn handle_tls_handshake(
    stream: TcpStream,
    addr: &std::net::SocketAddr,
    ip: Ipv6Addr,
    sni_lookup_map: Arc<HashMap<TlsOption, Vec<Arc<TlsTargetData>>>>,
) -> std::io::Result<(Box<dyn AsyncStream>, Arc<TargetData>)> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start_handshake = acceptor.await?;
    let client_hello = start_handshake.client_hello();
    let sni_hostname = client_hello
        .server_name()
        .map(|s| TlsOption::Specified(s.to_string()))
        .unwrap_or(TlsOption::None);

    let sni_data_vec = match sni_lookup_map.get(&sni_hostname) {
        Some(v) => {
            debug!("matched requested SNI from {}: {:?}", addr, sni_hostname);
            v
        }
        None => {
            if !sni_hostname.is_specified() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("no SNI hostname unspecified by {}", addr),
                ));
            }
            match sni_lookup_map.get(&TlsOption::Any) {
                Some(v) => v,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "no matching SNI hostname from {}: {}",
                            addr,
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
        if sni_data.ip_lookup_table.longest_match(ip).is_some() {
            let tls_config = if alpn_protocol_hashes.is_empty() {
                if !sni_data.allow_no_alpn {
                    continue;
                }
                sni_data.no_alpn_tls_config.clone()
            } else if !alpn_protocol_hashes.is_disjoint(&sni_data.alpn_protocol_hashes) {
                sni_data.alpn_tls_config.clone()
            } else if sni_data.allow_any_alpn {
                // allow any ALPN - don't do ALPN negotiation since the requested ALPNs don't
                // match any of the specified ones.
                sni_data.no_alpn_tls_config.clone()
            } else {
                continue;
            };

            let tls_stream = start_handshake
                .into_stream_with(tls_config, |server_conn| {
                    server_conn.set_buffer_limit(Some(32768));
                })
                .await?;

            return Ok((Box::new(tls_stream), sni_data.target_data.clone()));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!(
            "no matching alpn from {} ({})",
            addr,
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
                .as_deref()
                .unwrap_or("not negotiated")
        ),
    ))
}

async fn run_stream_action(
    mut source_stream: Box<dyn AsyncStream>,
    addr: &std::net::SocketAddr,
    target_data: Arc<TargetData>,
) -> std::io::Result<()> {
    match &target_data.action_data {
        TargetActionData::Raw {
            location_data,
            next_address_index,
        } => {
            let target_location = if location_data.len() > 1 {
                // fetch_add wraps around on overflow.
                let index = next_address_index.fetch_add(1, Ordering::Relaxed);
                &location_data[index % location_data.len()]
            } else {
                &location_data[0]
            };
            let mut target_stream =
                match setup_target_stream(addr, target_location, target_data.tcp_nodelay).await {
                    Ok(s) => s,
                    Err(e) => {
                        source_stream.try_shutdown().await?;
                        return Err(e);
                    }
                };

            debug!("Copying: {} to {}", addr, &target_location.location,);

            let copy_result =
                copy_bidirectional(&mut source_stream, &mut target_stream, false, false).await;

            debug!("Shutdown: {} to {}", addr, &target_location.location,);

            let (_, _) = join!(source_stream.try_shutdown(), target_stream.try_shutdown());

            debug!("Done: {} to {}", addr, &target_location.location,);

            copy_result?;

            Ok(())
        }
        TargetActionData::Http {
            path_configs,
            default_http_action,
        } => {
            handle_http_stream(
                target_data.tcp_nodelay,
                path_configs,
                default_http_action,
                source_stream,
                addr,
            )
            .await
        }
    }
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
        sleep(Duration::from_millis(50)).await;
    }

    debug!("Unable to fetch all bytes to determine TLS.");

    // If we get here, then we didn't have enough bytes after several iterations
    // of the for loop. It could be possible that the client expects a server response
    // first before sending more bytes, so just assume it's not a TLS connection.
    Ok(false)
}

pub async fn setup_target_stream(
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
                    error!("Failed to set tcp_nodelay on target stream: {}", e);
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
