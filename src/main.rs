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
mod tcp;
mod udp;

use std::sync::Arc;

use log::{debug, error, info};
use tokio::runtime::Builder;

use crate::async_tls::AsyncTlsFactory;
use crate::config::{ServerConfig, TargetConfigs};
use crate::tcp::run_tcp_server;
use crate::udp::run_udp_server;

#[cfg(feature = "tls-native")]
fn create_tls_factory() -> native_tls::NativeTlsFactory {
    native_tls::NativeTlsFactory::new()
}

#[cfg(feature = "tls-rustls")]
fn create_tls_factory() -> rustls::RustlsFactory {
    rustls::RustlsFactory::new()
}

async fn run(
    server_config: ServerConfig,
    tls_factory: Arc<dyn AsyncTlsFactory>,
) -> std::io::Result<()> {
    let ServerConfig {
        server_address,
        use_iptables,
        target_configs,
    } = server_config;

    match target_configs {
        TargetConfigs::Tcp(target_configs) => {
            return run_tcp_server(tls_factory, server_address, use_iptables, target_configs).await;
        }
        TargetConfigs::Udp(target_configs) => {
            return run_udp_server(server_address, use_iptables, target_configs).await;
        }
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
