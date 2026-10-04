mod async_stream;
mod config;
mod copy_bidirectional;
mod domain_trie;
mod hostname_util;
mod http;
mod iptables_util;
mod lifecycle;
mod rustls_util;
mod socket_util;
mod tcp;
mod tls_parser;
mod tls_reader;
mod tokio_util;
mod udp;
mod util;

use std::io::Write;

use log::{debug, error};
use tokio::runtime::Builder;

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

    --dry-run
        Load and validate configuration, including TLS files, without binding listeners.

    -h, --help
        Show this help screen.

IPTABLES PERMISSIONS:

    To run iptable commands, this binary needs to have CAP_NET_RAW and CAP_NET_ADMIN
    permissions, or else be invoked by root.

EXAMPLES:

    {} -t 1 config1.yaml config2.yaml

        Run servers from configs in config1.yaml and config2.yaml on a single thread.

    {} tcp://127.0.0.1:1000?target=127.0.0.1:2000

        Run a tcp server on 127.0.0.1 port 1000, forwarding to 127.0.0.1 port 2000.

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
    eprintln!("{}", help_str(command));
    std::process::exit(if error.is_some() { 1 } else { 0 });
}

#[derive(Debug, PartialEq)]
enum QuickAction {
    ClearIptablesMatching,
    ClearIptablesAll,
    DryRun,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let timestamp = buf.timestamp();
            let level_style = buf.default_level_style(record.level());
            let sanitized_args = format!("{}", record.args())
                .chars()
                .map(|c| {
                    if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        '?'
                    }
                })
                .collect::<String>();

            writeln!(
                buf,
                "[{} {level_style}{}{level_style:#} {}] {}",
                timestamp,
                record.level(),
                record.target(),
                sanitized_args
            )
        })
        .init();

    let mut config_paths = vec![];
    let mut config_urls = vec![];
    let mut quick_action: Option<QuickAction> = None;
    let mut num_threads: Option<usize> = None;

    let mut args = std::env::args();
    let command = args.next().unwrap();

    while let Some(arg) = args.next() {
        if arg == "--clear-iptables-all" {
            quick_action = Some(QuickAction::ClearIptablesAll);
        } else if arg == "--clear-iptables-matching" {
            quick_action = Some(QuickAction::ClearIptablesMatching);
        } else if arg == "--dry-run" {
            quick_action = Some(QuickAction::DryRun);
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
        } else if arg.contains("://") {
            config_urls.push(arg);
        } else if arg == "--help" || arg == "-h" {
            print_help(&command, None);
        } else if arg.starts_with('-') {
            print_help(&command, Some(&format!("Unknown argument: {}", arg)));
        } else {
            config_paths.push(arg);
        }
    }

    if config_urls.is_empty()
        && config_paths.is_empty()
        && quick_action != Some(QuickAction::ClearIptablesAll)
    {
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

    if let Err(error) = runtime.block_on(lifecycle::run(config_paths, config_urls, quick_action)) {
        error!("{error}");
        std::process::exit(1);
    }
}
