use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::join;
use log::{debug, error, warn};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use treebitmap::IpLookupTable;

use crate::async_stream::AsyncStream;
use crate::async_tls::{AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};
use crate::config::TcpTargetConfig;
use crate::copy_bidirectional::copy_bidirectional;
use crate::iptables_util::{configure_iptables, Protocol};
use crate::tokio_util::resolve_host;

struct TcpTargetData {
    pub server_tls_data: Option<ServerTlsData>,
    pub address_data: Vec<TargetAddressData>,
    pub next_address_index: AtomicUsize,
    pub early_connect: bool,
    pub tcp_nodelay: bool,
}

struct ServerTlsData {
    pub acceptor: Box<dyn AsyncTlsAcceptor>,
    pub optional: bool,
}

struct TargetAddressData {
    pub address: String,
    pub port: u16,
    pub tls_connector: Option<Box<dyn AsyncTlsConnector>>,
}

const BUFFER_SIZE: usize = 8192;

pub async fn run_tcp_server(
    tls_factory: Arc<dyn AsyncTlsFactory>,
    server_address: SocketAddr,
    use_iptables: bool,
    target_configs: Vec<TcpTargetConfig>,
) -> std::io::Result<()> {
    let mut lookup_table = IpLookupTable::new();

    for target_config in target_configs {
        let server_tls_data = if let Some(cfg) = target_config.server_tls_config {
            let mut cert_file = File::open(&cfg.cert_path).await?;
            let mut cert_bytes = vec![];
            cert_file.read_to_end(&mut cert_bytes).await?;

            let mut key_file = File::open(&cfg.key_path).await?;
            let mut key_bytes = vec![];
            key_file.read_to_end(&mut key_bytes).await?;

            Some(ServerTlsData {
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
                tls_connector: if let Some(cfg) = target_address.client_tls_config {
                    Some(tls_factory.create_connector(cfg.verify))
                } else {
                    None
                },
            })
            .collect();

        let target_data = Arc::new(TcpTargetData {
            server_tls_data,
            address_data,
            next_address_index: AtomicUsize::new(0),
            early_connect: target_config.early_connect,
            tcp_nodelay: target_config.tcp_nodelay,
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
        configure_iptables(Protocol::Tcp, server_address, &ip_masks);
    }

    for entry in lookup_table.iter() {
        debug!("Lookup table entry: {:?} (masklen {})", &entry.0, &entry.1);
    }

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

async fn process_stream(
    stream: TcpStream,
    addr: &std::net::SocketAddr,
    target_data: Arc<TcpTargetData>,
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
        let (source_result, target_result) = join!(
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

    let copy_result = copy_bidirectional(&mut source_stream, &mut target_stream, BUFFER_SIZE).await;

    debug!(
        "Shutdown: {}:{} to {}:{}",
        addr.ip(),
        addr.port(),
        &target_address.address,
        &target_address.port
    );

    let (_, _) = join!(source_stream.try_shutdown(), target_stream.try_shutdown());

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
    server_tls_data: &Option<ServerTlsData>,
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
    let target_addr = resolve_host((target_address.address.as_str(), target_address.port)).await?;
    let target_stream = TcpStream::connect(target_addr).await?;

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
