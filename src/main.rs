#![feature(available_concurrency)]

mod config;
mod copy_bidirectional;
mod native_tls_util;

use config::ServerConfig;

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use treebitmap::IpLookupTable;

const BUFFER_SIZE: usize = 8192;

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl AsyncStream for TcpStream {}

impl AsyncStream for tokio_native_tls::TlsStream<TcpStream> {}

async fn process_stream(
    stream: TcpStream,
    addr: std::net::SocketAddr,
    target_data: Arc<TargetData>,
) -> std::io::Result<()> {
    // TODO: do both accept() and connect() at the same time to speed things up?
    let mut stream: Box<dyn AsyncStream> = if let Some(ref acceptor) = target_data.tls_acceptor {
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    let target_address = if target_data.address_data.len() > 1 {
        // fetch_add wraps around on overflow.
        let index = target_data
            .next_address_index
            .fetch_add(1, Ordering::Relaxed);
        &target_data.address_data[index % target_data.address_data.len()]
    } else {
        &target_data.address_data[0]
    };

    debug!(
        "Forwarding: {} to {}:{}",
        addr.ip(),
        &target_address.address,
        &target_address.port
    );

    let target_stream =
        TcpStream::connect((target_address.address.as_str(), target_address.port)).await?;
    let mut target_stream: Box<dyn AsyncStream> =
        if let Some(ref connector) = target_address.tls_connector {
            let tls_stream = connector
                .connect(&target_address.address, target_stream)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Box::new(tls_stream)
        } else {
            Box::new(target_stream)
        };

    copy_bidirectional::copy_bidirectional(&mut stream, &mut target_stream, BUFFER_SIZE).await
}

struct TargetData {
    pub tls_acceptor: Option<tokio_native_tls::TlsAcceptor>,
    pub address_data: Vec<TargetAddressData>,
    pub next_address_index: AtomicUsize,
}

struct TargetAddressData {
    pub address: String,
    pub port: u16,
    pub tls_connector: Option<tokio_native_tls::TlsConnector>,
}

async fn run(server_config: ServerConfig) -> std::io::Result<()> {
    let ServerConfig {
        server_address,
        target_configs,
    } = server_config;

    let mut lookup_table = IpLookupTable::new();

    for target_config in target_configs {
        let tls_acceptor = if let Some(cfg) = target_config.server_tls_config {
            let identity = native_tls_util::create_identity(&cfg.cert_path, &cfg.key_path).unwrap();
            Some(native_tls::TlsAcceptor::new(identity).unwrap().into())
        } else {
            None
        };

        let address_data = target_config
            .target_addresses
            .into_iter()
            .map(|target_address| {
                TargetAddressData {
                    address: target_address.address,
                    port: target_address.port,
                    tls_connector: if target_address.tls {
                        // TODO: support different configs/certs.
                        let c = native_tls::TlsConnector::builder()
                            .danger_accept_invalid_certs(true)
                            .danger_accept_invalid_hostnames(true)
                            .build()
                            .unwrap();
                        Some(c.into())
                    } else {
                        None
                    },
                }
            })
            .collect();

        let target_data = Arc::new(TargetData {
            tls_acceptor,
            address_data,
            next_address_index: AtomicUsize::new(0),
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

    for entry in lookup_table.iter() {
        debug!("Lookup table entry: {:?} (masklen {})", &entry.0, &entry.1);
    }

    let listener = TcpListener::bind(server_address).await.unwrap();
    info!("Listening: {}", listener.local_addr().unwrap());

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

        let target_data = match lookup_table.longest_match(ip) {
            Some((_, _, d)) => d.clone(),
            None => {
                // Not allowed.
                warn!("Unknown address, not allowing: {}", addr.ip());
                continue;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = process_stream(stream, addr, target_data).await {
                error!("Finished with error: {:?}", e);
            }
        });
    }
}

fn main() {
    env_logger::init();

    let config_paths: Vec<String> = std::env::args().skip(1).collect();
    let mut server_configs: Vec<ServerConfig> = config::load_configs(config_paths);

    if server_configs.is_empty() {
        error!("No server configs found.");
        return;
    }

    debug!("Loaded server configs: {:#?}", &server_configs);

    let last_config = server_configs.pop().unwrap();

    let num_threads = std::cmp::max(
        2,
        std::thread::available_concurrency()
            .map(|n| n.get())
            .unwrap_or(1),
    );

    debug!("Runtime threads: {}", num_threads);

    let runtime = Builder::new_multi_thread()
        .worker_threads(num_threads)
        .enable_io()
        .build()
        .expect("Could not build tokio runtime");

    for server_config in server_configs {
        runtime.spawn(async move { run(server_config).await });
    }

    runtime
        .block_on(async move { run(last_config).await })
        .unwrap();
}
