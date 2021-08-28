use std::net::SocketAddr;

use crate::config::UdpTargetConfig;

pub async fn run_udp_server(
    server_address: SocketAddr,
    use_iptables: bool,
    target_configs: Vec<UdpTargetConfig>,
) -> std::io::Result<()> {
    panic!("TODO");
}
