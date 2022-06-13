use log::{debug, error};
use std::net::{Ipv6Addr, SocketAddr};
use std::process::Output;

use tokio::process::Command;

use crate::config::IpMask;

const IPTABLES_PATH: &str = "/usr/sbin/iptables";
const IP6TABLES_PATH: &str = "/usr/sbin/ip6tables";

pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(&self) -> &'static str {
        match self {
            &Protocol::Tcp => "tcp",
            &Protocol::Udp => "udp",
        }
    }
}

async fn run(program: &str, args: &[&str]) -> Vec<String> {
    debug!("Running {} with arguments: {:?}", program, args);
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(program)
        .args(args)
        .output()
        .await
        .expect("Failed to run iptables.");

    if stderr.len() > 0 {
        let stderr_str = String::from_utf8(stderr).expect("Failed to parse stderr");
        error!("iptables error messages: {}", stderr_str);
    }

    if !status.success() {
        panic!("iptables exited with status {}", status.code().unwrap());
    }

    String::from_utf8(stdout)
        .expect("Failed to parse stdout")
        .split('\n')
        .map(|s| s.to_string())
        .collect()
}

fn create_comment(socket_addr: &SocketAddr) -> String {
    format!("tobaru-rs@{}", socket_addr)
}

fn format_ipv6(addr: &Ipv6Addr) -> String {
    // ToString seems to print things in ipv4 format when possible.
    addr.segments()
        .iter()
        .map(|segment| format!("{:x}", segment))
        .collect::<Vec<_>>()
        .join(":")
}

pub async fn configure_iptables(protocol: Protocol, socket_addr: SocketAddr, ip_masks: &[IpMask]) {
    let comment = create_comment(&socket_addr);
    let port_str = socket_addr.port().to_string();

    for IpMask(addr, masklen) in ip_masks {
        run(
            IP6TABLES_PATH,
            &[
                "--wait",
                "5",
                "-A",
                "INPUT",
                "--protocol",
                protocol.as_str(),
                "--dport",
                &port_str,
                "-s",
                &format!("{}/{}", format_ipv6(addr), masklen),
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                &comment,
            ],
        )
        .await;

        if let Some(addr_v4) = addr.to_ipv4() {
            run(
                IPTABLES_PATH,
                &[
                    "--wait",
                    "5",
                    "-A",
                    "INPUT",
                    "--protocol",
                    protocol.as_str(),
                    "--dport",
                    &port_str,
                    "-s",
                    &format!("{}/{}", addr_v4, masklen.saturating_sub(96)),
                    "-j",
                    "ACCEPT",
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                ],
            )
            .await;
        }
    }

    for program in &[IPTABLES_PATH, IP6TABLES_PATH] {
        run(
            program,
            &[
                "--wait",
                "5",
                "-A",
                "INPUT",
                "--protocol",
                protocol.as_str(),
                "--dport",
                &port_str,
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                &comment,
            ],
        )
        .await;
    }
}

pub async fn clear_matching_iptables(socket_addr: SocketAddr) {
    let comment = create_comment(&socket_addr);
    clear_iptables(&comment).await
}

pub async fn clear_all_iptables() {
    clear_iptables("tobaru-rs").await
}

async fn clear_iptables(comment: &str) {
    for program in &[IPTABLES_PATH, IP6TABLES_PATH] {
        // Iterate through line backwards so that rule numbers don't change as we remove them.
        for line in run(
            program,
            &["--wait", "5", "-n", "-L", "INPUT", "--line-numbers"],
        )
        .await
        .into_iter()
        .rev()
        {
            if line.find(&comment).is_some() {
                let rule_number = line.trim_start().split(' ').next().unwrap();
                run(program, &["--wait", "5", "-D", "INPUT", rule_number]).await;
            }
        }
    }
}
