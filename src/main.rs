#![feature(available_concurrency)]

#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!("only one of tls-native or tls-rustls can be enabled.");

mod async_stream;
mod async_tls;
mod config;
mod copy_bidirectional;
mod iptables_util;
#[cfg(feature = "tls-native")]
mod native_tls;
#[cfg(feature = "tls-rustls")]
mod rustls;

use async_stream::AsyncStream;
use async_tls::{AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};
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

#[cfg(feature = "tls-native")]
fn create_tls_factory() -> native_tls::NativeTlsFactory {
    native_tls::NativeTlsFactory::new()
}

#[cfg(feature = "tls-rustls")]
fn create_tls_factory() -> rustls::RustlsFactory {
    rustls::RustlsFactory::new()
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

async fn setup_source_stream(
    stream: TcpStream,
    server_tls_data: &Option<TargetTlsData>,
) -> std::io::Result<Box<dyn AsyncStream>> {
    if let Some(data) = server_tls_data {
        if data.optional {
            let is_tls_client_hello = peek_tls_client_hello(&stream).await?;
            debug!("Finished tls client hello check: {}", is_tls_client_hello);
            if !is_tls_client_hello {
                return Ok(Box::new(stream));
            }
        }
        let tls_stream = data.acceptor.accept(stream).await?;
        Ok(tls_stream)
    } else {
        Ok(Box::new(stream))
    }
}

async fn setup_target_stream(
    addr: &std::net::SocketAddr,
    target_address: &TargetAddressData,
    tcp_nodelay: bool,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let target_stream =
        TcpStream::connect((target_address.address.as_str(), target_address.port)).await?;

    if tcp_nodelay {
        if let Err(e) = target_stream.set_nodelay(true) {
            error!("Failed to set tcp_nodelay: {}", e);
        }
    }

    debug!(
        "Connected to remote: {} using local addr {}",
        addr,
        target_stream.local_addr().unwrap()
    );

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
    addr: &std::net::SocketAddr,
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

    debug!(
        "Starting: {}:{} to {}:{}",
        addr.ip(),
        addr.port(),
        &target_address.address,
        &target_address.port
    );

    let (mut source_stream, mut target_stream) = if target_data.early_connect {
        let (source_result, target_result) = futures_util::join!(
            setup_source_stream(stream, &target_data.server_tls_data),
            setup_target_stream(addr, &target_address, target_data.tcp_nodelay)
        );

        if source_result.is_err() || target_result.is_err() {
            if let Ok(mut source_stream) = source_result {
                let _ = source_stream.try_shutdown().await;
                return target_result.map(|_| ());
            }
            if let Ok(mut target_stream) = target_result {
                let _ = target_stream.try_shutdown().await;
                return source_result.map(|_| ());
            }
            // Both were errors, just return one.
            return source_result.map(|_| ());
        }

        (source_result.unwrap(), target_result.unwrap())
    } else {
        let mut source_stream = setup_source_stream(stream, &target_data.server_tls_data).await?;
        let target_stream =
            match setup_target_stream(addr, &target_address, target_data.tcp_nodelay).await {
                Ok(s) => s,
                Err(e) => {
                    source_stream.try_shutdown().await?;
                    return Err(e);
                }
            };
        (source_stream, target_stream)
    };

    debug!(
        "Copying: {}:{} to {}:{}",
        addr.ip(),
        addr.port(),
        &target_address.address,
        &target_address.port
    );

    let copy_result =
        copy_bidirectional::copy_bidirectional(&mut source_stream, &mut target_stream, BUFFER_SIZE)
            .await;

    debug!(
        "Shutdown: {}:{} to {}:{}",
        addr.ip(),
        addr.port(),
        &target_address.address,
        &target_address.port
    );

    let (_, _) = futures_util::join!(source_stream.try_shutdown(), target_stream.try_shutdown());

    debug!(
        "Done: {}:{} to {}:{}",
        addr.ip(),
        addr.port(),
        &target_address.address,
        &target_address.port
    );

    copy_result?;

    Ok(())
}

struct TargetData {
    pub server_tls_data: Option<TargetTlsData>,
    pub address_data: Vec<TargetAddressData>,
    pub next_address_index: AtomicUsize,
    pub early_connect: bool,
    pub tcp_nodelay: bool,
}

struct TargetTlsData {
    pub acceptor: Box<dyn AsyncTlsAcceptor>,
    pub optional: bool,
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
        use_iptables,
    } = server_config;

    let mut lookup_table = IpLookupTable::new();

    for target_config in target_configs {
        let server_tls_data = if let Some(cfg) = target_config.server_tls_config {
            let mut cert_file = File::open(&cfg.cert_path)?;
            let mut cert_bytes = vec![];
            cert_file.read_to_end(&mut cert_bytes)?;

            let mut key_file = File::open(&cfg.key_path)?;
            let mut key_bytes = vec![];
            key_file.read_to_end(&mut key_bytes)?;

            Some(TargetTlsData {
                acceptor: tls_factory.create_acceptor(&cert_bytes, &key_bytes),
                optional: cfg.optional,
            })
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
            server_tls_data,
            address_data,
            next_address_index: AtomicUsize::new(0),
            early_connect: target_config.early_connect,
            tcp_nodelay: target_config.tcp_nodelay,
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
        iptables_util::configure_iptables(server_address, &ip_masks);
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
            if let Err(e) = process_stream(stream, &addr, target_data).await {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

fn main() {
    env_logger::init();

    let tls_factory: Arc<dyn AsyncTlsFactory> = Arc::new(create_tls_factory());

    let mut config_paths = vec![];
    let mut clear_iptables_only = false;
    for arg in std::env::args().skip(1) {
        if arg == "--clear-iptables" {
            clear_iptables_only = true;
        } else {
            config_paths.push(arg);
        }
    }

    let mut server_configs: Vec<ServerConfig> = config::load_configs(config_paths);

    if server_configs.is_empty() {
        error!("No server configs found.");
        return;
    }

    debug!("Loaded server configs: {:#?}", &server_configs);

    for server_config in server_configs.iter() {
        if server_config.use_iptables {
            iptables_util::clear_iptables(server_config.server_address);
        }
    }

    if clear_iptables_only {
        info!("iptables cleared, exiting.");
        return;
    }

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
        .enable_time()
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
