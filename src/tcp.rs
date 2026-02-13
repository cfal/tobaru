use std::collections::hash_map::RandomState;
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
use tokio::time::{timeout, Duration};

use crate::async_stream::AsyncStream;
use crate::config::{
    HttpForwardConfig, HttpHeaderPatch, HttpPathAction, HttpServeDirectoryConfig,
    HttpServeMessageConfig, HttpTcpActionConfig, HttpValueMatch, IpMask, IpMaskSelection, Location,
    NetLocation, NoneOrOne, RawTcpActionConfig, TcpAction, TcpKeepaliveConfig, TcpKeepaliveOption,
    TcpTargetConfig, TcpTargetLocation, TlsOption,
};
use crate::domain_trie::DomainTrie;
use crate::copy_bidirectional::copy_bidirectional;
use crate::http::handle_http_stream;
use crate::iptables_util::{configure_iptables, Protocol};
use crate::rustls_util::{
    create_server_config, get_dummy_server_name, load_certs, load_private_key,
};
use crate::tokio_util::resolve_host;

pub struct TargetLocationData {
    pub location: Location,
    pub tls_connector: Option<tokio_rustls::TlsConnector>,
    pub sni_hostname: NoneOrOne<String>,
}

impl From<TcpTargetLocation> for TargetLocationData {
    fn from(tcp_target_location: TcpTargetLocation) -> Self {
        let (location, client_tls) = tcp_target_location.into_components();

        // Load client certificate if specified
        let client_cert = if client_tls.has_client_cert() {
            let key_path = client_tls.key().unwrap();
            let cert_path = client_tls.cert().unwrap();

            // Read cert and key files synchronously during initialization
            // This is OK since we're in the setup phase
            let cert_bytes = std::fs::read(cert_path)
                .unwrap_or_else(|e| panic!("Failed to read client cert {}: {}", cert_path, e));
            let key_bytes = std::fs::read(key_path)
                .unwrap_or_else(|e| panic!("Failed to read client key {}: {}", key_path, e));

            Some((cert_bytes, key_bytes))
        } else {
            None
        };

        // Extract SNI hostname
        let sni_hostname = client_tls.sni_hostname().clone();

        // Extract and convert ALPN protocols to bytes
        let alpn_protocols: Vec<Vec<u8>> = client_tls
            .alpn_protocols()
            .clone()
            .into_vec()
            .into_iter()
            .map(|s| s.into_bytes())
            .collect();

        // Extract server fingerprints
        let server_fingerprints: Vec<String> = client_tls.server_fingerprints().clone().into_vec();

        // Determine if SNI should be enabled
        // Only disable SNI when explicitly set to None (via YAML null)
        let enable_sni = !matches!(sni_hostname, NoneOrOne::None);

        Self {
            location,
            tls_connector: if client_tls.is_enabled() {
                Some(
                    crate::rustls_util::create_client_config_with_cert(
                        client_tls.should_verify(),
                        client_cert,
                        alpn_protocols,
                        enable_sni,
                        server_fingerprints,
                    )
                    .into(),
                )
            } else {
                None
            },
            sni_hostname,
        }
    }
}

pub struct TargetData {
    pub tcp_nodelay: bool,
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
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

enum TlsMode {
    Terminate {
        alpn_tls_config: Arc<rustls::ServerConfig>,
        no_alpn_tls_config: Arc<rustls::ServerConfig>,
    },
    Passthrough,
}

struct TlsTargetData {
    pub allow_no_alpn: bool,
    pub allow_any_alpn: bool,
    pub alpn_protocol_hashes: HashSet<u64>,
    pub ip_lookup_table: IpLookupTable<Ipv6Addr, bool>,
    pub tls_mode: TlsMode,
    pub target_data: Arc<TargetData>,
}

fn hash_alpn<T: Hash>(x: T) -> u64 {
    static ALPN_HASHER: OnceLock<RandomState> = OnceLock::new();
    ALPN_HASHER.get_or_init(RandomState::new).hash_one(x)
}

/// Parse ALPN configuration into flags and hashes (common for both modes)
fn parse_alpn_config(
    alpn_protocols: &crate::config::NoneOrSome<TlsOption>,
) -> (bool, bool, HashSet<u64>) {
    let mut allow_no_alpn = false;
    let mut allow_any_alpn = false;
    let mut alpn_protocol_hashes = HashSet::new();

    let alpn_list = if alpn_protocols.is_empty() {
        vec![TlsOption::Any, TlsOption::None]
    } else {
        alpn_protocols.clone().into_vec()
    };

    for alpn_protocol in alpn_list {
        match alpn_protocol {
            TlsOption::None => allow_no_alpn = true,
            TlsOption::Any => allow_any_alpn = true,
            TlsOption::Specified(s) => {
                alpn_protocol_hashes.insert(hash_alpn(s.as_bytes()));
            }
        }
    }

    (allow_no_alpn, allow_any_alpn, alpn_protocol_hashes)
}

/// Build rustls configs for terminate mode
fn build_rustls_configs(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: &rustls::pki_types::PrivateKeyDer<'static>,
    alpn_protocols: &crate::config::NoneOrSome<TlsOption>,
    client_fingerprints: &crate::config::NoneOrSome<String>,
) -> (Arc<rustls::ServerConfig>, Arc<rustls::ServerConfig>) {
    let mut alpn_protocol_bytes = vec![];
    for proto in alpn_protocols.iter() {
        if let TlsOption::Specified(s) = proto {
            alpn_protocol_bytes.push(s.as_bytes().to_vec());
        }
    }

    let client_fingerprint_vec: Vec<String> = client_fingerprints.clone().into_vec();

    if alpn_protocol_bytes.is_empty() {
        let tls_config = Arc::new(create_server_config(
            certs,
            private_key,
            alpn_protocol_bytes,
            &client_fingerprint_vec,
        ));
        (tls_config.clone(), tls_config)
    } else {
        let alpn_tls_config = create_server_config(
            certs,
            private_key,
            alpn_protocol_bytes.clone(),
            &client_fingerprint_vec,
        );
        let mut no_alpn_tls_config = alpn_tls_config.clone();
        no_alpn_tls_config.alpn_protocols = vec![];
        (Arc::new(alpn_tls_config), Arc::new(no_alpn_tls_config))
    }
}

pub async fn run_tcp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    tcp_nodelay: bool,
    tcp_keepalive: TcpKeepaliveOption,
    target_configs: Vec<TcpTargetConfig>,
) -> std::io::Result<()> {
    let mut non_tls_lookup_table: IpLookupTable<Ipv6Addr, Arc<TargetData>> = IpLookupTable::new();

    let mut tls_lookup_table: IpLookupTable<Ipv6Addr, bool> = IpLookupTable::new();
    let mut sni_trie: DomainTrie<Vec<Arc<TlsTargetData>>> = DomainTrie::new();
    let mut no_sni_targets: Vec<Arc<TlsTargetData>> = Vec::new();

    let mut iptable_masks = vec![];

    for target_config in target_configs {
        let TcpTargetConfig {
            allowlist,
            server_tls,
            tcp_nodelay,
            tcp_keepalive: target_tcp_keepalive,
            action,
            ..
        } = target_config;

        let allowlist = allowlist
            .into_iter()
            .map(IpMaskSelection::unwrap_literal)
            .collect::<Vec<_>>();

        // Validate passthrough + client_tls combination BEFORE moving action
        if let Some(ref tls_config) = server_tls {
            if let Err(e) = tls_config.validate_with_action(&action) {
                panic!("Invalid TLS configuration: {}", e);
            }
        }

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

        // Create target_data (needed for both TLS and non-TLS targets)
        // Resolve keepalive config for target-side connections
        let resolved_keepalive = target_tcp_keepalive.resolve_for_target();
        let target_data = Arc::new(TargetData {
            tcp_nodelay,
            tcp_keepalive: resolved_keepalive,
            action_data,
        });

        let is_non_tls_target = match server_tls {
            Some(ref tls_config) => {
                // Validate the config
                if let Err(e) = tls_config.validate() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid server_tls config: {}", e),
                    ));
                }

                // Parse ALPN configuration (common for both modes)
                let (allow_no_alpn, allow_any_alpn, alpn_protocol_hashes) =
                    parse_alpn_config(&tls_config.alpn_protocols);

                // Build mode-specific TLS configuration
                let tls_mode = if tls_config.is_passthrough() {
                    TlsMode::Passthrough
                } else {
                    // Terminate mode: load certs and build rustls configs
                    let cert = tls_config.cert.as_ref().unwrap();
                    let key = tls_config.key.as_ref().unwrap();

                    let mut cert_file = File::open(cert).await?;
                    let mut cert_bytes = vec![];
                    cert_file.read_to_end(&mut cert_bytes).await?;
                    let certs = load_certs(&cert_bytes);

                    let mut key_file = File::open(key).await?;
                    let mut key_bytes = vec![];
                    key_file.read_to_end(&mut key_bytes).await?;
                    let private_key = load_private_key(&key_bytes);

                    let (alpn_tls_config, no_alpn_tls_config) = build_rustls_configs(
                        certs,
                        &private_key,
                        &tls_config.alpn_protocols,
                        &tls_config.client_fingerprints,
                    );

                    TlsMode::Terminate {
                        alpn_tls_config,
                        no_alpn_tls_config,
                    }
                };

                // Build IP lookup table (common for both modes)
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

                // Create unified TlsTargetData
                let tls_target_data = Arc::new(TlsTargetData {
                    allow_no_alpn,
                    allow_any_alpn,
                    alpn_protocol_hashes,
                    ip_lookup_table: config_lookup_table,
                    tls_mode,
                    target_data: target_data.clone(),
                });

                // Register SNI hostnames (common for both modes)
                let sni_hostnames = if tls_config.sni_hostnames.is_empty() {
                    vec![TlsOption::Any, TlsOption::None]
                } else {
                    tls_config.sni_hostnames.clone().into_vec()
                };

                for sni_hostname in sni_hostnames.into_iter() {
                    match sni_hostname {
                        TlsOption::None => {
                            no_sni_targets.push(tls_target_data.clone());
                        }
                        TlsOption::Any => {
                            sni_trie.entry_or_default("*").push(tls_target_data.clone());
                        }
                        TlsOption::Specified(pattern) => {
                            sni_trie.entry_or_default(&pattern).push(tls_target_data.clone());
                        }
                    }
                }

                tls_config.optional
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

    let sni_trie = Arc::new(sni_trie);
    let no_sni_targets = Arc::new(no_sni_targets);

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

        // Apply TCP keepalive on server-side (client-facing) connection
        if let Some(keepalive_config) = tcp_keepalive.resolve_for_server() {
            if let Err(e) = crate::socket_util::set_tcp_keepalive(
                &stream,
                Duration::from_secs(keepalive_config.idle_secs),
                Duration::from_secs(keepalive_config.interval_secs),
            ) {
                error!("Failed to set tcp_keepalive on server stream: {}", e);
            }
        }

        if has_tls_data {
            let cloned_sni_trie = sni_trie.clone();
            let cloned_no_sni = no_sni_targets.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    process_tls_stream(stream, &addr, ip, non_tls_data, cloned_sni_trie, cloned_no_sni).await
                {
                    error!("{} finished with error: {:?}", addr, e);
                } else {
                    debug!("{} finished successfully", addr);
                }
            });
        } else {
            tokio::spawn(async move {
                if let Err(e) =
                    run_stream_action(Box::new(stream), &addr, non_tls_data.unwrap(), None).await
                {
                    error!("{} finished with error: {:?}", addr, e);
                } else {
                    debug!("{} finished successfully", addr);
                }
            });
        }
    }
}

/// Find matching terminate target based on SNI and ALPN from parsed ClientHello
fn find_matching_terminate_target(
    parsed: &crate::tls_parser::ParsedClientHello,
    ip: Ipv6Addr,
    sni_trie: &DomainTrie<Vec<Arc<TlsTargetData>>>,
    no_sni_targets: &[Arc<TlsTargetData>],
) -> Option<(Arc<TlsTargetData>, Arc<rustls::ServerConfig>)> {
    let candidates = match &parsed.server_name {
        Some(hostname) => sni_trie.lookup(hostname)?,
        None => {
            if no_sni_targets.is_empty() {
                return None;
            }
            no_sni_targets
        }
    };

    // Match ALPN
    let alpn_hashes: HashSet<u64> = parsed
        .alpn_protocols
        .iter()
        .map(|s| hash_alpn(s.as_bytes()))
        .collect();

    for candidate in candidates {
        // Only consider terminate targets
        let (alpn_tls_config, no_alpn_tls_config) = match &candidate.tls_mode {
            TlsMode::Terminate {
                alpn_tls_config,
                no_alpn_tls_config,
            } => (alpn_tls_config, no_alpn_tls_config),
            TlsMode::Passthrough => continue,
        };

        // Check IP allowlist
        if candidate.ip_lookup_table.longest_match(ip).is_none() {
            continue;
        }

        // Check ALPN matching and determine which config to use
        if alpn_hashes.is_empty() {
            if candidate.allow_no_alpn {
                return Some((candidate.clone(), no_alpn_tls_config.clone()));
            }
        } else if !alpn_hashes.is_disjoint(&candidate.alpn_protocol_hashes) {
            // Specific protocol match - use ALPN config
            return Some((candidate.clone(), alpn_tls_config.clone()));
        } else if candidate.allow_any_alpn {
            // Any ALPN allowed but no specific match - use no-ALPN config
            return Some((candidate.clone(), no_alpn_tls_config.clone()));
        }
    }

    None
}

/// Feed data into rustls ServerConnection
fn feed_server_connection(
    server_conn: &mut rustls::ServerConnection,
    data: &[u8],
) -> std::io::Result<()> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = server_conn.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to feed server connection: {e}"),
            )
        })?;
        i += n;
    }
    Ok(())
}

/// Handle terminate mode with parsed ClientHello - use TlsAcceptor directly
async fn handle_terminate_with_parsed(
    stream: TcpStream,
    addr: &std::net::SocketAddr,
    client_hello_frame: Vec<u8>,
    target_data: Arc<TlsTargetData>,
    tls_config: Arc<rustls::ServerConfig>,
) -> std::io::Result<(Box<dyn AsyncStream>, Arc<TargetData>)> {
    use tokio_rustls::TlsAcceptor;

    debug!("Terminate TLS for {}", addr);

    // Use TlsAcceptor directly - no need for LazyConfigAcceptor since we've already
    // parsed the ClientHello and selected the correct config
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let accept_future = {
        let mut accept_error: Option<std::io::Error> = None;

        let accept_future = tls_acceptor.accept_with(stream, |server_conn| {
            server_conn.set_buffer_limit(Some(32768));

            // Feed the ClientHello we already parsed for routing
            if let Err(e) = feed_server_connection(server_conn, &client_hello_frame) {
                let _ = accept_error.insert(std::io::Error::other(format!(
                    "Failed to feed ClientHello to server connection: {e}"
                )));
                return;
            }

            // Process the fed data
            if let Err(e) = server_conn.process_new_packets() {
                let _ = accept_error.insert(std::io::Error::other(format!(
                    "Failed to process new packets: {e}"
                )));
            }
        });

        if let Some(e) = accept_error {
            return Err(e);
        }

        accept_future
    };

    let tls_stream = Box::new(accept_future.await?);

    debug!("Completed TLS handshake for {}", addr);

    Ok((tls_stream, target_data.target_data.clone()))
}

/// Find matching TLS target based on SNI and ALPN
fn find_matching_passthrough_target(
    parsed: &crate::tls_parser::ParsedClientHello,
    ip: Ipv6Addr,
    sni_trie: &DomainTrie<Vec<Arc<TlsTargetData>>>,
    no_sni_targets: &[Arc<TlsTargetData>],
) -> Option<Arc<TlsTargetData>> {
    let candidates = match &parsed.server_name {
        Some(hostname) => sni_trie.lookup(hostname)?,
        None => {
            if no_sni_targets.is_empty() {
                return None;
            }
            no_sni_targets
        }
    };

    // Match ALPN
    let alpn_hashes: HashSet<u64> = parsed
        .alpn_protocols
        .iter()
        .map(|s| hash_alpn(s.as_bytes()))
        .collect();

    for candidate in candidates {
        // Skip non-passthrough targets
        if !matches!(candidate.tls_mode, TlsMode::Passthrough) {
            continue;
        }

        // Check IP allowlist
        if candidate.ip_lookup_table.longest_match(ip).is_none() {
            continue;
        }

        // Check ALPN matching
        if alpn_hashes.is_empty() {
            if candidate.allow_no_alpn {
                return Some(candidate.clone());
            }
        } else if !alpn_hashes.is_disjoint(&candidate.alpn_protocol_hashes)
            || candidate.allow_any_alpn
        {
            return Some(candidate.clone());
        }
    }

    None
}

/// Handle passthrough stream - forward ClientHello + remaining data without decryption
async fn handle_passthrough_stream(
    stream: TcpStream,
    addr: &std::net::SocketAddr,
    client_hello_frame: Vec<u8>,
    target_data: Arc<TlsTargetData>,
) -> std::io::Result<()> {
    debug!("Passthrough TLS for {}", addr);

    // Get target location
    let target_location = match &target_data.target_data.action_data {
        TargetActionData::Raw {
            location_data,
            next_address_index,
        } => {
            if location_data.len() > 1 {
                let idx = next_address_index.fetch_add(1, Ordering::Relaxed);
                &location_data[idx % location_data.len()]
            } else {
                &location_data[0]
            }
        }
        TargetActionData::Http { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTP action not supported with TLS passthrough mode",
            ));
        }
    };

    // Passthrough mode cannot use client_tls (would cause TLS-in-TLS)
    // This should be caught during config validation
    debug_assert!(
        target_location.tls_connector.is_none(),
        "client_tls should not be configured in passthrough mode - this should have been caught during validation"
    );

    // Connect to target
    let mut target_stream = setup_target_stream(
        addr,
        target_location,
        target_data.target_data.tcp_nodelay,
        target_data.target_data.tcp_keepalive,
    )
    .await?;

    // Forward the buffered ClientHello first
    crate::util::write_all(&mut target_stream, &client_hello_frame).await?;

    debug!(
        "Forwarded ClientHello ({} bytes) from {} to {}",
        client_hello_frame.len(),
        addr,
        &target_location.location,
    );

    // Bidirectional copy for the rest of the connection
    // Set b_need_initial_flush=true to flush the ClientHello before copying
    let copy_result = copy_bidirectional(
        &mut (Box::new(stream) as Box<dyn crate::async_stream::AsyncStream>),
        &mut target_stream,
        false,
        true, // Flush target_stream before starting bidirectional copy
    )
    .await;

    debug!(
        "Passthrough finished: {} to {}",
        addr, &target_location.location
    );

    copy_result?;
    Ok(())
}

async fn process_tls_stream(
    mut stream: TcpStream,
    addr: &std::net::SocketAddr,
    ip: Ipv6Addr,
    non_tls_data: Option<Arc<TargetData>>,
    sni_trie: Arc<DomainTrie<Vec<Arc<TlsTargetData>>>>,
    no_sni_targets: Arc<Vec<Arc<TlsTargetData>>>,
) -> std::io::Result<()> {
    // UNIFIED APPROACH: Always parse ClientHello first
    // This allows us to route to either passthrough or terminate targets

    // Create TlsReader for parsing
    let mut reader = crate::tls_reader::TlsReader::new();

    // Try to parse ClientHello with timeout
    let parse_timeout = timeout(
        Duration::from_secs(5),
        crate::tls_parser::parse_client_hello(&mut reader, &mut stream),
    );

    let parsed = match parse_timeout.await {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(e)) if non_tls_data.is_some() => {
            // Not TLS (or malformed TLS) - try non-TLS target
            // Pass buffered data to be written first (passthrough approach)
            debug!(
                "Failed to parse TLS ClientHello from {}: {}, trying non-TLS target",
                addr, e
            );
            let (mut buf, _pos, end) = reader.into_inner();
            buf.truncate(end);

            let initial_data = if buf.is_empty() { None } else { Some(buf) };
            return run_stream_action(Box::new(stream), addr, non_tls_data.unwrap(), initial_data)
                .await;
        }
        Ok(Err(e)) => {
            // No non-TLS target and can't parse TLS
            return Err(e);
        }
        Err(_) if non_tls_data.is_some() => {
            // Timeout while parsing - assume non-TLS
            // Pass buffered data to be written first (passthrough approach)
            warn!(
                "TLS ClientHello parse timed out for {}, assuming non-TLS connection",
                addr
            );
            let (mut buf, _pos, end) = reader.into_inner();
            buf.truncate(end);

            let initial_data = if buf.is_empty() { None } else { Some(buf) };
            return run_stream_action(Box::new(stream), addr, non_tls_data.unwrap(), initial_data)
                .await;
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("TLS ClientHello parse timed out: {}", elapsed),
            ));
        }
    };

    debug!(
        "Parsed ClientHello from {} - SNI: {:?}, ALPN: {:?}",
        addr, parsed.server_name, parsed.alpn_protocols
    );

    // Get the buffered ClientHello data for replay and truncate to actual data
    let (mut buf, _pos, end) = reader.into_inner();
    buf.truncate(end);

    // Try to match passthrough targets first (higher priority)
    if let Some(target) = find_matching_passthrough_target(&parsed, ip, &sni_trie, &no_sni_targets) {
        return handle_passthrough_stream(stream, addr, buf, target).await;
    }

    // Try to match terminate targets
    if let Some((target, tls_config)) = find_matching_terminate_target(&parsed, ip, &sni_trie, &no_sni_targets)
    {
        let (tls_stream, target_data) =
            handle_terminate_with_parsed(stream, addr, buf, target, tls_config).await?;
        return run_stream_action(tls_stream, addr, target_data, None).await;
    }

    // No matching target found
    Err(std::io::Error::other(format!(
        "No matching TLS target for {} with SNI: {:?}, ALPN: {:?}",
        addr, parsed.server_name, parsed.alpn_protocols
    )))
}

async fn run_stream_action(
    mut source_stream: Box<dyn AsyncStream>,
    addr: &std::net::SocketAddr,
    target_data: Arc<TargetData>,
    initial_data: Option<Vec<u8>>,
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
            let mut target_stream = match setup_target_stream(
                addr,
                target_location,
                target_data.tcp_nodelay,
                target_data.tcp_keepalive,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    source_stream.try_shutdown().await?;
                    return Err(e);
                }
            };

            // Write initial data if present (passthrough-style approach)
            if let Some(ref data) = initial_data {
                crate::util::write_all(&mut target_stream, data).await?;
                debug!(
                    "Forwarded initial data ({} bytes) from {} to {}",
                    data.len(),
                    addr,
                    &target_location.location,
                );
            }

            debug!("Copying: {} to {}", addr, &target_location.location,);

            let copy_result = copy_bidirectional(
                &mut source_stream,
                &mut target_stream,
                false,
                initial_data.is_some(),
            )
            .await;

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
                target_data.tcp_keepalive,
                path_configs,
                default_http_action,
                source_stream,
                addr,
                initial_data,
            )
            .await
        }
    }
}

pub async fn setup_target_stream(
    addr: &std::net::SocketAddr,
    target_location: &TargetLocationData,
    tcp_nodelay: bool,
    tcp_keepalive: Option<TcpKeepaliveConfig>,
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
            // Apply TCP keepalive on client-side (target-facing) connection
            if let Some(keepalive_config) = tcp_keepalive {
                if let Err(e) = crate::socket_util::set_tcp_keepalive(
                    &tcp_stream,
                    Duration::from_secs(keepalive_config.idle_secs),
                    Duration::from_secs(keepalive_config.interval_secs),
                ) {
                    error!("Failed to set tcp_keepalive on target stream: {}", e);
                }
            }
            debug!(
                "Connected to remote: {} using local addr {}",
                addr,
                tcp_stream.local_addr().unwrap()
            );

            if let Some(ref connector) = target_location.tls_connector {
                // Use SNI from config if specified, otherwise try to parse from address
                // Note: If enable_sni=false in the config, the SNI won't be sent regardless
                let server_name = match &target_location.sni_hostname {
                    NoneOrOne::One(sni) => {
                        // Use explicitly configured SNI
                        rustls::pki_types::ServerName::try_from(sni.as_str())
                            .map(|s| s.to_owned())
                            .unwrap_or_else(|_| {
                                warn!("Invalid SNI hostname in config: {}, using address", sni);
                                rustls::pki_types::ServerName::try_from(address.as_str())
                                    .map(|s| s.to_owned())
                                    .unwrap_or_else(|_| get_dummy_server_name())
                            })
                    }
                    NoneOrOne::None | NoneOrOne::Unspecified => {
                        // Either explicitly disabled (None) or not configured (Unspecified)
                        // For None: dummy name is fine since enable_sni=false
                        // For Unspecified: try to parse from address
                        rustls::pki_types::ServerName::try_from(address.as_str())
                            .map(|s| s.to_owned())
                            .unwrap_or_else(|_| get_dummy_server_name())
                    }
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
                // For unix sockets, SNI behavior is controlled by the config's enable_sni setting
                // Use configured SNI if specified, otherwise use dummy (won't be sent if enable_sni=false)
                let server_name = match &target_location.sni_hostname {
                    NoneOrOne::One(sni) => rustls::pki_types::ServerName::try_from(sni.as_str())
                        .map(|s| s.to_owned())
                        .unwrap_or_else(|_| {
                            warn!("Invalid SNI hostname in config: {}, using dummy", sni);
                            get_dummy_server_name()
                        }),
                    NoneOrOne::None | NoneOrOne::Unspecified => {
                        // Use dummy name (won't be sent if enable_sni=false)
                        get_dummy_server_name()
                    }
                };
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
