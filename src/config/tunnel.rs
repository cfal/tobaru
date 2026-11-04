use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;

use serde::Deserialize;

use super::{Location, NetLocation, TcpTargetLocation};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelReference {
    pub server: String,
    pub peer: String,
    pub service: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelServerConfig {
    pub tunnel_server: String,
    pub address: SocketAddr,
    pub server_tls: TunnelServerTls,
    pub peers: HashMap<String, TunnelPeerConfig>,
    #[serde(default = "default_endpoint_limit")]
    pub max_connections: usize,
    #[serde(default = "default_pending_limit")]
    pub max_handshakes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelServerTls {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelPeerConfig {
    pub client_fingerprints: Vec<String>,
    pub services: Vec<String>,
    #[serde(default = "default_active_limit")]
    pub max_active_connections: usize,
    #[serde(default = "default_pending_limit")]
    pub max_pending_opens: usize,
    #[serde(default = "default_timeout")]
    pub open_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelClientConfig {
    pub tunnel_client: String,
    pub server: NetLocation,
    pub client_tls: TunnelClientTls,
    pub services: HashMap<String, TunnelExport>,
    #[serde(default = "default_active_limit")]
    pub max_active_connections: usize,
    #[serde(default = "default_data_limit")]
    pub max_data_connections: usize,
    #[serde(default = "default_local_dials")]
    pub max_concurrent_local_dials: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelClientTls {
    pub cert: String,
    pub key: String,
    #[serde(default = "super::default_true")]
    pub verify: bool,
    #[serde(default)]
    pub server_fingerprints: Vec<String>,
    #[serde(default)]
    pub sni_hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelExport {
    pub location: TcpTargetLocation,
}

fn default_endpoint_limit() -> usize {
    1024
}
fn default_active_limit() -> usize {
    128
}
fn default_pending_limit() -> usize {
    32
}
fn default_data_limit() -> usize {
    256
}
fn default_local_dials() -> usize {
    16
}
fn default_timeout() -> u64 {
    10
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, message))
    }
}

fn limit(value: usize, maximum: usize, name: &str) -> io::Result<()> {
    require(
        (1..=maximum).contains(&value),
        &format!("Invalid tunnel {name}: expected 1..={maximum}"),
    )
}

impl TunnelServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        require(
            valid_name(&self.tunnel_server),
            "Invalid tunnel server name",
        )?;
        limit(self.peers.len(), 128, "peer count")?;
        limit(self.max_connections, 65536, "max_connections")?;
        limit(self.max_handshakes, self.max_connections, "max_handshakes")?;
        let mut fingerprints = HashSet::new();
        for (name, peer) in &self.peers {
            require(valid_name(name), "Invalid tunnel peer name")?;
            limit(peer.services.len(), 32, "service count")?;
            let mut services = HashSet::new();
            for name in &peer.services {
                require(
                    valid_name(name) && services.insert(name),
                    "Invalid or duplicate tunnel service",
                )?;
            }
            require(
                !peer.client_fingerprints.is_empty(),
                "Tunnel peer requires client_fingerprints",
            )?;
            for pin in crate::rustls_util::process_fingerprints(&peer.client_fingerprints)? {
                require(
                    fingerprints.insert(pin),
                    "Tunnel fingerprint belongs to multiple peers",
                )?;
            }
            limit(peer.max_active_connections, 65536, "max_active_connections")?;
            limit(
                peer.max_pending_opens,
                peer.max_active_connections.min(4096),
                "max_pending_opens",
            )?;
            require(
                (1..=86400).contains(&peer.open_timeout_secs),
                "Invalid tunnel open_timeout_secs",
            )?;
        }
        Ok(())
    }
}

impl TunnelClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        require(
            valid_name(&self.tunnel_client),
            "Invalid tunnel client name",
        )?;
        require(self.server.port != 0, "Tunnel server port must be nonzero")?;
        limit(self.services.len(), 32, "service count")?;
        limit(self.max_active_connections, 65536, "max_active_connections")?;
        limit(self.max_data_connections, 65536, "max_data_connections")?;
        limit(
            self.max_concurrent_local_dials,
            self.max_active_connections.min(4096),
            "max_concurrent_local_dials",
        )?;
        require(
            self.client_tls.verify || !self.client_tls.server_fingerprints.is_empty(),
            "Tunnel server verification or fingerprint pinning is required",
        )?;
        crate::rustls_util::process_fingerprints(&self.client_tls.server_fingerprints)?;
        rustls::pki_types::ServerName::try_from(self.server_name()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid tunnel server identity",
            )
        })?;
        for (name, export) in &self.services {
            require(valid_name(name), "Invalid tunnel service name")?;
            let (location, tls) = export.location.clone().into_components();
            require(!tls.is_enabled(), "Tunnel exports cannot enable client_tls")?;
            require(
                matches!(location, Location::Address(_) | Location::Path(_)),
                "Tunnel exports must be physical TCP or Unix destinations",
            )?;
        }
        Ok(())
    }

    pub fn server_name(&self) -> &str {
        self.client_tls
            .sni_hostname
            .as_deref()
            .unwrap_or(&self.server.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn client_defaults_and_strict_identity_policy() {
        let value = json!({"tunnel_client":"home", "server":"public.example:7443",
            "client_tls":{"cert":"client.pem", "key":"client.key"},
            "services":{"web":{"location":"127.0.0.1:8080"}}});
        let config: TunnelClientConfig = serde_json::from_value(value.clone()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.max_active_connections, 128);
        assert_eq!(config.max_data_connections, 256);
        for patch in [json!({"verify":false}), json!({"sni_hostname":"bad name"})] {
            let mut bad = value.clone();
            bad["client_tls"]
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(serde_json::from_value::<TunnelClientConfig>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut bad = value;
        bad["client_tls"]["alpn_protocols"] = json!(["h2"]);
        assert!(serde_json::from_value::<TunnelClientConfig>(bad).is_err());
    }

    #[test]
    fn server_requires_unique_authorized_identities_and_finite_limits() {
        let value = json!({"tunnel_server":"edge", "address":"0.0.0.0:7443",
            "server_tls":{"cert":"server.pem","key":"server.key"},
            "peers":{"home":{"client_fingerprints":["ab".repeat(32)],"services":["web"]}}});
        serde_json::from_value::<TunnelServerConfig>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        for idle in [json!(0), json!(4), json!(null)] {
            let mut bad = value.clone();
            bad["peers"]["home"]["idle_connections"] = idle;
            assert!(serde_json::from_value::<TunnelServerConfig>(bad).is_err());
        }
        for (key, bad_value) in [
            ("max_connections", json!(0)),
            ("max_handshakes", json!(1025)),
        ] {
            let mut bad = value.clone();
            bad[key] = bad_value;
            assert!(serde_json::from_value::<TunnelServerConfig>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut duplicate = value.clone();
        duplicate["peers"]["other"] = value["peers"]["home"].clone();
        assert!(serde_json::from_value::<TunnelServerConfig>(duplicate)
            .unwrap()
            .validate()
            .is_err());
    }
}
