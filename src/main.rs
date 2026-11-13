mod async_stream;
mod cli;
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
mod tunnel;
mod udp;
mod util;

use std::io::Write;

use log::{debug, error};
use tokio::runtime::Builder;

fn help_str(command: &str) -> String {
    const HELP_STR: &str = "USAGE:

    {} [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] [..]
    {} [OPTIONS] static [STATIC OPTIONS] [DIRECTORY]

    Run '{} static --help' for config-free static file serving.

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

fn static_help_str(command: &str) -> String {
    format!(
        "USAGE:

    {command} [OPTIONS] static [STATIC OPTIONS] [DIRECTORY]

    Serve DIRECTORY (default: current directory) without a configuration file.

STATIC OPTIONS:

    -a, --address IP       Bind IP address (default: 127.0.0.1; IPv4 or IPv6).
    -p, --port PORT        Listen port (default: 8080; 0 chooses an available port).
    -c, --cache SECONDS    Cache-Control max-age (default: 3600; 0 is immediately stale).
    -t, --threads NUM      Worker threads (default: auto-detected).
    --dry-run              Validate the directory and server without binding.
    -h, --help             Show this help screen.
    --                     Treat remaining arguments as the directory name.

    Files, including dotfiles, are served with no authentication or TLS.
    Directories use index.html; there are no directory listings.
    A config file named 'static' must be passed as './static'.

EXAMPLES:

    {command} static
    {command} static -a 0.0.0.0 -p 9000 -c 0 ./dist
"
    )
}

fn print_help(command: &str, static_mode: bool, error: Option<&str>) -> ! {
    if let Some(s) = error {
        eprintln!("ERROR: {}", s);
        eprintln!();
    }
    eprintln!(
        "{}",
        if static_mode {
            static_help_str(command)
        } else {
            help_str(command)
        }
    );
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

    let mut args = std::env::args();
    let command = args.next().unwrap();
    let options = cli::parse(args)
        .unwrap_or_else(|error| print_help(&command, error.static_mode, Some(&error.message)));
    if let cli::Mode::Help { static_mode } = options.mode {
        print_help(&command, static_mode, None);
    }

    let num_threads = options.threads.unwrap_or_else(|| {
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

    let result = runtime.block_on(async {
        match options.mode {
            cli::Mode::Config { paths, urls, quick } => lifecycle::run(paths, urls, quick).await,
            cli::Mode::Static {
                address,
                directory,
                cache_secs,
                dry_run,
            } => {
                let config = config::static_http_server(address, directory, cache_secs).await?;
                lifecycle::run_standalone(config, dry_run).await
            }
            cli::Mode::Help { .. } => unreachable!(),
        }
    });
    if let Err(error) = result {
        error!("{error}");
        std::process::exit(1);
    }
}
