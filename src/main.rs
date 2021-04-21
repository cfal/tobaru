#![feature(available_concurrency)]

#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!("only one of tls-native or tls-rustls can be enabled.");

mod async_tls;
mod config;
mod copy_bidirectional;
#[cfg(feature = "tls-native")]
mod native_tls;
#[cfg(feature = "tls-rustls")]
mod rustls;

use async_tls::{AsyncStream, AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};
use config::ServerConfig;

use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use treebitmap::IpLookupTable;

const BUFFER_SIZE: usize = 8192;
const ACCEPT_AND_CONNECT_TOGETHER: bool = true;

#[cfg(feature = "tls-native")]
fn create_tls_factory() -> native_tls::NativeTlsFactory {
    native_tls::NativeTlsFactory::new()
}

#[cfg(feature = "tls-rustls")]
fn create_tls_factory() -> rustls::RustlsFactory {
    rustls::RustlsFactory::new()
}

async fn setup_source_stream(
    stream: TcpStream,
    tls_acceptor: &Option<Box<dyn AsyncTlsAcceptor>>,
) -> std::io::Result<Box<dyn AsyncStream>> {
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await?;
        Ok(tls_stream)
    } else {
        Ok(Box::new(stream))
    }
}

async fn setup_target_stream(
    target_address: &TargetAddressData,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let target_stream =
        TcpStream::connect((target_address.address.as_str(), target_address.port)).await?;

    if let Some(ref connector) = target_address.tls_connector {
        let tls_stream = connector
            .connect(&target_address.address, target_stream)
            .await?;
        Ok(tls_stream)
    } else {
        Ok(Box::new(target_stream))
    }
}

async fn process_stream(
    stream: TcpStream,
    addr: std::net::SocketAddr,
    target_data: Arc<TargetData>,
) -> std::io::Result<()> {
    let target_address = if target_data.address_data.len() > 1 {
        // fetch_add wraps around on overflow.
        let index = target_data
            .next_address_index
            .fetch_add(1, Ordering::Relaxed);
        &target_data.address_data[index % target_data.address_data.len()]
    } else {
        &target_data.address_data[0]
    };

    let (mut source_stream, mut target_stream) = if ACCEPT_AND_CONNECT_TOGETHER {
        futures_util::try_join!(
            setup_source_stream(stream, &target_data.tls_acceptor),
            setup_target_stream(&target_address)
        )?
    } else {
        (
            setup_source_stream(stream, &target_data.tls_acceptor).await?,
            setup_target_stream(&target_address).await?,
        )
    };

    debug!(
        "Forwarding: {} to {}:{}",
        addr.ip(),
        &target_address.address,
        &target_address.port
    );

    copy_bidirectional::copy_bidirectional(&mut source_stream, &mut target_stream, BUFFER_SIZE)
        .await
}

struct TargetData {
    pub tls_acceptor: Option<Box<dyn AsyncTlsAcceptor>>,
    pub address_data: Vec<TargetAddressData>,
    pub next_address_index: AtomicUsize,
}

struct TargetAddressData {
    pub address: String,
    pub port: u16,
    pub tls_connector: Option<Box<dyn AsyncTlsConnector>>,
}

async fn run(
    server_config: ServerConfig,
    tls_factory: Arc<dyn AsyncTlsFactory>,
) -> std::io::Result<()> {
    let ServerConfig {
        server_address,
        target_configs,
    } = server_config;

    let mut lookup_table = IpLookupTable::new();

    for target_config in target_configs {
        let tls_acceptor = if let Some(cfg) = target_config.server_tls_config {
            let mut cert_file = File::open(&cfg.cert_path)?;
            let mut cert_bytes = vec![];
            cert_file.read_to_end(&mut cert_bytes)?;

            let mut key_file = File::open(&cfg.key_path)?;
            let mut key_bytes = vec![];
            key_file.read_to_end(&mut key_bytes)?;

            Some(tls_factory.create_acceptor(&cert_bytes, &key_bytes))
        } else {
            None
        };

        let address_data = target_config
            .target_addresses
            .into_iter()
            .map(|target_address| TargetAddressData {
                address: target_address.address,
                port: target_address.port,
                tls_connector: if target_address.tls {
                    Some(tls_factory.create_connector())
                } else {
                    None
                },
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

    let tls_factory: Arc<dyn AsyncTlsFactory> = Arc::new(create_tls_factory());

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
        let cloned_factory = tls_factory.clone();
        runtime.spawn(async move { run(server_config, cloned_factory).await });
    }

    let cloned_factory = tls_factory.clone();
    runtime
        .block_on(async move { run(last_config, cloned_factory).await })
        .unwrap();
}
