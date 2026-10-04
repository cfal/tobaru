use log::{debug, error};
use std::net::{Ipv6Addr, SocketAddr};
use std::process::Output;

use tokio::process::Command;

use crate::config::IpMask;

const IPTABLES_PATH: &str = "iptables";
const IP6TABLES_PATH: &str = "ip6tables";

pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

async fn run(program: &str, args: &[&str]) -> std::io::Result<Vec<String>> {
    debug!("Running {} with arguments: {:?}", program, args);
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(program).args(args).output().await?;

    if !stderr.is_empty() {
        let stderr_str = String::from_utf8_lossy(&stderr);
        error!("iptables error messages: {}", stderr_str);
    }

    if !status.success() {
        return Err(std::io::Error::other(format!(
            "{program} exited with {status}"
        )));
    }

    Ok(String::from_utf8(stdout)
        .map_err(std::io::Error::other)?
        .split('\n')
        .map(|s| s.to_string())
        .collect())
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

pub async fn configure_iptables(
    protocol: Protocol,
    socket_addr: SocketAddr,
    ip_masks: &[IpMask],
) -> std::io::Result<()> {
    let comment = create_comment(&socket_addr);
    let port_str = socket_addr.port().to_string();

    let mut ipv6_masks = vec![];
    let mut ipv4_masks = vec![];
    for IpMask(addr, masklen) in ip_masks {
        ipv6_masks.push(format!("{}/{}", format_ipv6(addr), masklen));
        if let Some(addr_v4) = addr.to_ipv4() {
            ipv4_masks.push(format!("{}/{}", addr_v4, masklen.saturating_sub(96)));
        }
    }

    // we need to chunk to avoid ArgumentListTooLong errors.
    for chunk in ipv6_masks.chunks(50) {
        run(
            IP6TABLES_PATH,
            &[
                "--wait",
                "10",
                "-A",
                "INPUT",
                "--protocol",
                protocol.as_str(),
                "--dport",
                &port_str,
                "-s",
                &chunk.join(","),
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                &comment,
            ],
        )
        .await?;
    }

    for chunk in ipv4_masks.chunks(50) {
        run(
            IPTABLES_PATH,
            &[
                "--wait",
                "10",
                "-A",
                "INPUT",
                "--protocol",
                protocol.as_str(),
                "--dport",
                &port_str,
                "-s",
                &chunk.join(","),
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                &comment,
            ],
        )
        .await?;
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
        .await?;
    }
    Ok(())
}

pub async fn clear_matching_iptables(socket_addr: SocketAddr) -> std::io::Result<()> {
    let comment = create_comment(&socket_addr);
    clear_iptables(&comment).await
}

pub async fn clear_all_iptables() -> std::io::Result<()> {
    clear_iptables("tobaru-rs").await
}

async fn clear_iptables(comment: &str) -> std::io::Result<()> {
    for program in &[IPTABLES_PATH, IP6TABLES_PATH] {
        // Iterate through line backwards so that rule numbers don't change as we remove them.
        for line in run(
            program,
            &["--wait", "5", "-n", "-L", "INPUT", "--line-numbers"],
        )
        .await?
        .into_iter()
        .rev()
        {
            if matches_comment(&line, comment) {
                let rule_number = line.trim_start().split(' ').next().unwrap();
                run(program, &["--wait", "5", "-D", "INPUT", rule_number]).await?;
            }
        }
    }
    Ok(())
}

fn matches_comment(line: &str, expected: &str) -> bool {
    let Some((_, tail)) = line.split_once("/*") else {
        return false;
    };
    let Some((comment, _)) = tail.split_once("*/") else {
        return false;
    };
    let comment = comment.trim();
    comment == expected || (expected == "tobaru-rs" && comment.starts_with("tobaru-rs@"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_matches_complete_rule_ownership() {
        let line = "1 DROP tcp /* tobaru-rs@127.0.0.1:8080 */";
        assert!(matches_comment(line, "tobaru-rs@127.0.0.1:8080"));
        assert!(matches_comment(line, "tobaru-rs"));
        assert!(!matches_comment(line, "tobaru-rs@127.0.0.1:80"));
        assert!(!matches_comment(
            "1 DROP /* unrelated-tobaru-rs */",
            "tobaru-rs"
        ));
    }

    #[tokio::test]
    async fn command_failures_are_errors_not_panics() {
        assert!(run("/does/not/exist", &[]).await.is_err());
        assert!(run("/bin/sh", &["-c", "exit 1"]).await.is_err());
        assert_eq!(run("/bin/sh", &["-c", "printf ok"]).await.unwrap(), ["ok"]);
    }
}
