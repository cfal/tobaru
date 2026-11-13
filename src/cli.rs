use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use crate::QuickAction;

#[derive(Debug, PartialEq)]
pub enum Mode {
    Config {
        paths: Vec<String>,
        urls: Vec<String>,
        quick: Option<QuickAction>,
    },
    Static {
        address: SocketAddr,
        directory: String,
        cache_secs: u64,
        dry_run: bool,
    },
    Help {
        static_mode: bool,
    },
}

#[derive(Debug, PartialEq)]
pub struct Options {
    pub threads: Option<usize>,
    pub mode: Mode,
}

#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub static_mode: bool,
}

fn set_option<T: FromStr>(
    args: &mut impl Iterator<Item = String>,
    slot: &mut Option<T>,
    name: &str,
) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{name} was already specified"));
    }
    let text = args.next().ok_or_else(|| format!("Missing {name}"))?;
    *slot = Some(
        text.parse()
            .map_err(|_| format!("Invalid {name}: {text}"))?,
    );
    Ok(())
}

pub fn parse(args: impl Iterator<Item = String>) -> Result<Options, ParseError> {
    let mut static_mode = false;
    parse_inner(args, &mut static_mode).map_err(|message| ParseError {
        message,
        static_mode,
    })
}

fn parse_inner(
    mut args: impl Iterator<Item = String>,
    static_mode: &mut bool,
) -> Result<Options, String> {
    let mut paths = Vec::new();
    let mut urls = Vec::new();
    let mut quick = None;
    let mut threads = None;
    let mut saw_iptables = false;
    let mut address: Option<IpAddr> = None;
    let mut port = None;
    let mut cache_secs = None;
    let mut directory = None;
    let mut positional_only = false;

    while let Some(arg) = args.next() {
        if *static_mode && (positional_only || !arg.starts_with('-')) {
            if directory.replace(arg).is_some() {
                return Err("Only one static directory may be specified".into());
            }
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => {
                return Ok(Options {
                    threads,
                    mode: Mode::Help {
                        static_mode: *static_mode,
                    },
                })
            }
            "-t" | "--threads" => {
                set_option(&mut args, &mut threads, "thread count")?;
                if threads == Some(0) {
                    return Err("Cannot specify zero thread count".into());
                }
            }
            "--dry-run" => quick = Some(QuickAction::DryRun),
            "--clear-iptables-all" | "--clear-iptables-matching" => {
                saw_iptables = true;
                quick = Some(if arg == "--clear-iptables-all" {
                    QuickAction::ClearIptablesAll
                } else {
                    QuickAction::ClearIptablesMatching
                });
            }
            "static" if !*static_mode && paths.is_empty() && urls.is_empty() => *static_mode = true,
            "-a" | "--address" if *static_mode => {
                set_option(&mut args, &mut address, "IP address")?
            }
            "-p" | "--port" if *static_mode => set_option(&mut args, &mut port, "port")?,
            "-c" | "--cache" if *static_mode => {
                set_option(&mut args, &mut cache_secs, "cache duration")?
            }
            "--" if *static_mode => positional_only = true,
            _ if arg.starts_with('-') => return Err(format!("Unknown argument: {arg}")),
            _ if arg.contains("://") => urls.push(arg),
            _ => paths.push(arg),
        }
    }

    let mode = if *static_mode {
        if saw_iptables {
            return Err("Static mode cannot be combined with --clear-iptables-*".into());
        }
        Mode::Static {
            address: SocketAddr::new(
                address.unwrap_or(Ipv4Addr::LOCALHOST.into()),
                port.unwrap_or(8080),
            ),
            directory: directory.unwrap_or_else(|| ".".into()),
            cache_secs: cache_secs.unwrap_or(3600),
            dry_run: quick == Some(QuickAction::DryRun),
        }
    } else {
        if paths.is_empty() && urls.is_empty() && quick != Some(QuickAction::ClearIptablesAll) {
            return Err("No config URLs or config paths specified".into());
        }
        Mode::Config { paths, urls, quick }
    };
    Ok(Options { threads, mode })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Options, ParseError> {
        parse(args.iter().map(|arg| (*arg).into()))
    }

    #[test]
    fn static_defaults_and_overrides() {
        assert_eq!(
            parse_args(&["static"]).unwrap(),
            Options {
                threads: None,
                mode: Mode::Static {
                    address: "127.0.0.1:8080".parse().unwrap(),
                    directory: ".".into(),
                    cache_secs: 3600,
                    dry_run: false,
                },
            }
        );
        for args in [
            vec![
                "-t",
                "1",
                "--dry-run",
                "static",
                "-a",
                "::1",
                "-p",
                "0",
                "-c",
                "0",
                "dist",
            ],
            vec![
                "static",
                "dist",
                "--address",
                "::1",
                "--port",
                "0",
                "--cache",
                "0",
                "--threads",
                "1",
                "--dry-run",
            ],
        ] {
            assert_eq!(
                parse_args(&args).unwrap(),
                Options {
                    threads: Some(1),
                    mode: Mode::Static {
                        address: "[::1]:0".parse().unwrap(),
                        directory: "dist".into(),
                        cache_secs: 0,
                        dry_run: true,
                    },
                }
            );
        }
        for operand in ["-dist", "--help", "--", "static"] {
            assert!(
                matches!(parse_args(&["static", "--", operand]).unwrap().mode,
                Mode::Static { directory, .. } if directory == operand)
            );
        }
        assert!(
            matches!(parse_args(&["static", "-p", "65535", "-c", "60"]).unwrap().mode,
            Mode::Static { address, cache_secs: 60, .. } if address.port() == 65535)
        );
    }

    #[test]
    fn static_rejects_invalid_options() {
        for args in [
            vec!["static", "-a"],
            vec!["static", "-a", "localhost"],
            vec!["static", "-a", "127.0.0.1", "--address", "::1"],
            vec!["static", "-p"],
            vec!["static", "-p", "65536"],
            vec!["static", "-p", "-1"],
            vec!["static", "-p", "abc"],
            vec!["static", "-p", "1", "--port", "2"],
            vec!["static", "-c"],
            vec!["static", "-c", "-1"],
            vec!["static", "-c", "1.5"],
            vec!["static", "-c", "18446744073709551616"],
            vec!["static", "-c", "0", "--cache", "60"],
            vec!["static", "-t"],
            vec!["static", "-t", "0"],
            vec!["static", "-t", "abc"],
            vec!["-t", "1", "static", "-t", "2"],
            vec!["static", "--unknown"],
            vec!["static", "a", "b"],
            vec!["static", "--", "a", "b"],
            vec!["static", "--clear-iptables-all"],
            vec!["--clear-iptables-matching", "static", "--dry-run"],
            vec!["static", "--clear-iptables-all", "--dry-run"],
        ] {
            assert!(parse_args(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn config_operands_and_global_options_remain_compatible() {
        let url = "tcp://127.0.0.1:8080?target=127.0.0.1:9000";
        for args in [
            vec!["-t", "2", "./static", url, "static", "--dry-run"],
            vec!["./static", url, "--threads", "2", "--dry-run", "static"],
        ] {
            assert_eq!(
                parse_args(&args).unwrap(),
                Options {
                    threads: Some(2),
                    mode: Mode::Config {
                        paths: vec!["./static".into(), "static".into()],
                        urls: vec![url.into()],
                        quick: Some(QuickAction::DryRun),
                    },
                }
            );
        }
        assert!(matches!(
            parse_args(&["--clear-iptables-all"]).unwrap().mode,
            Mode::Config {
                quick: Some(QuickAction::ClearIptablesAll),
                ..
            }
        ));
        for args in [
            vec![],
            vec!["-a", "0.0.0.0"],
            vec!["config.yml", "-p", "80"],
        ] {
            assert!(parse_args(&args).is_err());
        }
    }

    #[test]
    fn help_is_scoped_to_the_selected_mode() {
        for (args, static_mode) in [
            (vec!["--help"], false),
            (vec!["static", "-h"], true),
            (vec!["-t", "1", "static", "--help"], true),
            (vec!["static", "--clear-iptables-all", "--help"], true),
            (vec!["--clear-iptables-matching", "static", "-h"], true),
        ] {
            assert_eq!(parse_args(&args).unwrap().mode, Mode::Help { static_mode });
        }
    }

    #[test]
    fn errors_preserve_argument_order_and_help_scope() {
        for (args, message, static_mode) in [
            (
                vec!["static", "a", "b"],
                "Only one static directory may be specified",
                true,
            ),
            (
                vec!["static", "--", "a", "--help"],
                "Only one static directory may be specified",
                true,
            ),
            (
                vec!["static", "a", "--", "b"],
                "Only one static directory may be specified",
                true,
            ),
            (
                vec!["static", "-p", "1", "--port"],
                "port was already specified",
                true,
            ),
            (
                vec!["static", "-p", "invalid", "--help"],
                "Invalid port: invalid",
                true,
            ),
            (vec!["-t", "static"], "Invalid thread count: static", false),
            (
                vec!["config.yml", "--unknown", "--help"],
                "Unknown argument: --unknown",
                false,
            ),
            (
                vec!["--clear-iptables-matching", "static", "--dry-run"],
                "Static mode cannot be combined with --clear-iptables-*",
                true,
            ),
        ] {
            let error = parse_args(&args).unwrap_err();
            assert_eq!(error.message, message, "{args:?}");
            assert_eq!(error.static_mode, static_mode, "{args:?}");
        }
    }
}
