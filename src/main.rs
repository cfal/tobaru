mod async_stream;
mod config;
mod copy_bidirectional;
mod iptables_util;
mod rustls_util;
mod tcp;
mod tokio_util;
mod udp;

use std::path::Path;

use log::{debug, error};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::runtime::Builder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::config::{ServerConfig, TargetConfigs};
use crate::tcp::run_tcp_server;
use crate::udp::run_udp_server;

#[derive(Debug)]
struct ConfigChanged;

fn start_notify_thread(
    config_paths: Vec<String>,
) -> (RecommendedWatcher, UnboundedReceiver<ConfigChanged>) {
    let (tx, rx) = unbounded_channel();

    let mut watcher = notify::recommended_watcher(move |res| match res {
        Ok(_) => {
            tx.send(ConfigChanged {}).unwrap();
        }
        Err(e) => println!("watch error: {:?}", e),
    })
    .unwrap();

    for config_path in config_paths {
        watcher
            .watch(Path::new(&config_path), RecursiveMode::NonRecursive)
            .unwrap();
    }

    (watcher, rx)
}

async fn run(server_config: ServerConfig) {
    let ServerConfig {
        address,
        use_iptables,
        target_configs,
    } = server_config;

    match target_configs {
        TargetConfigs::Tcp {
            tcp_nodelay,
            targets,
        } => {
            // TODO: restart or panic?
            if let Err(e) =
                run_tcp_server(address, use_iptables, tcp_nodelay, targets.into_vec()).await
            {
                error!("TCP forwarder finished with error: {}", e);
            }
        }
        TargetConfigs::Udp { targets } => {
            // TODO: restart or panic?
            if let Err(e) = run_udp_server(address, use_iptables, targets.into_vec()).await {
                error!("UDP forwarder finished with error: {}", e);
            }
        }
    }
}

fn help_str(command: &str) -> String {
    const HELP_STR: &str = "USAGE:

    {} [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] [..]

OPTIONS:

    -t, --threads NUM
        Number of worker threads, defaults to an estimated amount of parallelism.

    --clear-iptables-all
        Clear all tobaru-created rules from iptables and exit immediately.

    --clear-iptables-matching
        Clear tobaru-created rules for the addresses specified in the specified
        config files and exit immediately.

    -h, --help
        Show this help screen.

IPTABLES PERMISSIONS:

    To run iptable commands, this binary needs to have CAP_NET_RAW and CAP_NET_ADMIN
    permissions, or else be invoked by root.

EXAMPLES:

    {} -t 1 config1.yaml config2.yaml

        Run listeners from configs in config1.yaml and config2.yaml on a single thread.

    {} tcp://127.0.0.1:1000?target=127.0.0.1:2000

        Run a tcp listener on 127.0.0.1 port 1000, forwarding to 127.0.0.1 port 2000.

    sudo {} --clear-iptables-matching config1.yaml

        Clear iptable configs only for the config addresses in config1.yaml.
";

    HELP_STR.replace("{}", command)
}

fn print_help(command: &str, error: Option<&str>) -> ! {
    if let Some(s) = error {
        eprintln!("ERROR: {}", s);
        eprintln!();
    }
    eprintln!("{}", help_str(&command));
    std::process::exit(if error.is_some() { 1 } else { 0 });
}

fn main() {
    env_logger::init();

    let mut config_paths = vec![];
    let mut config_urls = vec![];
    let mut clear_iptables_matching = false;
    let mut clear_iptables_all = false;
    let mut num_threads: Option<usize> = None;

    let mut args = std::env::args();
    let command = args.next().unwrap();

    while let Some(arg) = args.next() {
        if arg == "--clear-iptables-all" {
            clear_iptables_all = true;
        } else if arg == "--clear-iptables-matching" {
            clear_iptables_matching = true;
        } else if arg == "--threads" || arg == "-t" {
            if num_threads.is_some() {
                print_help(&command, Some("Thread count was already specified"))
            }

            let num_threads_str = match args.next() {
                Some(s) => s,
                None => {
                    print_help(&command, Some("Missing thread count"));
                }
            };

            let t = match num_threads_str.parse::<usize>() {
                Ok(t) => t,
                Err(_) => {
                    print_help(&command, Some("Invalid thread count"));
                }
            };

            if t == 0 {
                print_help(&command, Some("Cannot specify zero thread count"));
            }

            num_threads = Some(t);
        } else if arg.find("://").is_some() {
            config_urls.push(arg);
        } else if arg == "--help" || arg == "-h" {
            print_help(&command, None);
        } else if arg.starts_with('-') {
            print_help(&command, Some(&format!("Unknown argument: {}", arg)));
        } else {
            config_paths.push(arg);
        }
    }

    if config_urls.is_empty() && config_paths.is_empty() {
        print_help(&command, Some("No config URLs or config paths specified"));
    }

    let num_threads = num_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
    });

    debug!("Worker threads: {}", num_threads);

    let mut builder = if num_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        mt.worker_threads(num_threads);
        mt
    };

    let runtime = builder
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not build tokio runtime");

    runtime.block_on(async move {
        if clear_iptables_all {
            iptables_util::clear_all_iptables().await;
            println!("iptables cleared of all tobaru rules, exiting.");
            return;
        }

        let (_watcher, mut config_rx) = start_notify_thread(config_paths.clone());
        loop {
            let server_configs: Vec<ServerConfig> =
                config::load_server_configs(config_paths.clone(), config_urls.clone())
                    .await
                    .unwrap();

            if server_configs.is_empty() {
                error!("No server configs found.");
                return;
            }

            debug!("Loaded server configs: {:#?}", &server_configs);

            for server_config in server_configs.iter() {
                if server_config.use_iptables || clear_iptables_matching {
                    iptables_util::clear_matching_iptables(server_config.address).await;
                }
            }

            if clear_iptables_matching {
                println!("iptables cleared of matching server rules, exiting.");
                return;
            }

            let mut join_handles = Vec::with_capacity(server_configs.len());
            for server_config in server_configs {
                join_handles.push(tokio::spawn(async move {
                    run(server_config).await;
                }));
            }

            config_rx.recv().await.unwrap();

            println!("Configs changed, restarting servers in 3 seconds..");

            for join_handle in join_handles {
                join_handle.abort();
            }

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Remove any extra events
            while let Ok(_) = config_rx.try_recv() {}
        }
    });
}
