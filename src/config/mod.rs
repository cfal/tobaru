mod ip_mask;
mod location;
mod option_util;
mod tls_option;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;

use percent_encoding::percent_decode_str;
use serde::Deserialize;
use url::Url;

pub use ip_mask::IpMask;
pub use location::{Location, NetLocation};
pub use option_util::{NoneOrSome, OneOrSome};
pub use tls_option::TlsOption;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Config {
    ServerConfig(ServerConfig),
    IpMaskGroup {
        group: String,
        ip_masks: OneOrSome<IpMaskSelection>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum IpMaskSelection {
    Literal(IpMask),
    Group(String),
}

impl IpMaskSelection {
    pub fn unwrap_literal(self) -> IpMask {
        match self {
            IpMaskSelection::Literal(ip_mask) => ip_mask,
            IpMaskSelection::Group(_) => {
                panic!("Tried to unwrap an IP group as a literal");
            }
        }
    }

    pub fn replace_groups(
        selections: &mut OneOrSome<IpMaskSelection>,
        groups: &HashMap<String, Vec<IpMask>>,
    ) -> std::io::Result<()> {
        let mut ret = vec![];
        for selection in selections.iter() {
            match selection {
                IpMaskSelection::Literal(ip_mask) => {
                    ret.push(IpMaskSelection::Literal(ip_mask.clone()));
                }
                IpMaskSelection::Group(client_group) => match groups.get(client_group.as_str()) {
                    Some(ip_masks) => {
                        ret.extend(ip_masks.iter().cloned().map(IpMaskSelection::Literal));
                    }
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("No such ip group: {}", client_group),
                        ));
                    }
                },
            }
        }
        let _ = std::mem::replace(selections, OneOrSome::Some(ret));
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub address: SocketAddr,
    #[serde(default, alias = "iptables")]
    pub use_iptables: bool,
    #[serde(flatten)]
    pub target_configs: TargetConfigs,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum TargetConfigs {
    Tcp {
        #[serde(alias = "target")]
        targets: OneOrSome<TcpTargetConfig>,
    },
    Udp {
        #[serde(alias = "target")]
        targets: OneOrSome<UdpTargetConfig>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpTargetConfig {
    pub allowlist: OneOrSome<IpMaskSelection>,
    #[serde(alias = "location")]
    pub locations: OneOrSome<TcpTargetLocation>,
    #[serde(default)]
    pub server_tls: Option<ServerTlsConfig>,
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TcpTargetLocation {
    OnlyAddress(NetLocation),
    OnlyPath(PathBuf),
    Config {
        #[serde(flatten)]
        location: Location,

        #[serde(default)]
        client_tls: ClientTlsConfig,
    },
}

impl TcpTargetLocation {
    pub fn into_components(self) -> (Location, ClientTlsConfig) {
        match self {
            TcpTargetLocation::OnlyAddress(net_location) => {
                (Location::Address(net_location), ClientTlsConfig::default())
            }
            TcpTargetLocation::OnlyPath(path_buf) => {
                (Location::Path(path_buf), ClientTlsConfig::default())
            }
            TcpTargetLocation::Config {
                location,
                client_tls,
            } => (location, client_tls),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerTlsConfig {
    #[serde(default, alias = "sni_hostname")]
    pub sni_hostnames: NoneOrSome<TlsOption>,

    // the alpn protocols to show in the serverhello response
    #[serde(default, alias = "alpn_protocol")]
    pub alpn_protocols: NoneOrSome<TlsOption>,

    pub cert: String,
    pub key: String,

    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ClientTlsConfig {
    Enable(bool),
    WithSettings {
        #[serde(default = "default_true")]
        enable: bool,
        verify: bool,
    },
}

impl Default for ClientTlsConfig {
    fn default() -> Self {
        ClientTlsConfig::Enable(false)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpTargetConfig {
    #[serde(alias = "address", alias = "locations", alias = "location")]
    pub addresses: OneOrSome<NetLocation>,
    pub allowlist: OneOrSome<IpMaskSelection>,
    pub association_timeout_secs: Option<u32>,
}

pub async fn load_server_configs(
    config_paths: Vec<String>,
    config_urls: Vec<String>,
) -> std::io::Result<Vec<ServerConfig>> {
    let mut groups: HashMap<String, Vec<IpMask>> = HashMap::new();
    let mut server_configs = vec![];

    for config_path in config_paths {
        let config_str = tokio::fs::read_to_string(&config_path).await?;
        let configs = serde_yaml::from_str::<Vec<Config>>(&config_str).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse config YAML: {}", e),
            )
        })?;
        for config in configs {
            match config {
                Config::ServerConfig(server_config) => {
                    server_configs.push(server_config);
                }
                Config::IpMaskGroup {
                    group,
                    mut ip_masks,
                } => {
                    if IpMask::try_from(group.as_str()).is_ok() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid IP group name, looks like an IP mask: {}", group),
                        ));
                    }
                    IpMaskSelection::replace_groups(&mut ip_masks, &groups)?;
                    let ip_masks = ip_masks
                        .into_iter()
                        .map(IpMaskSelection::unwrap_literal)
                        .collect::<Vec<_>>();
                    if groups.insert(group.clone(), ip_masks).is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("duplicate IP group name: {}", group),
                        ));
                    }
                }
            }
        }
    }

    for server_config in server_configs.iter_mut() {
        match server_config.target_configs {
            TargetConfigs::Tcp { ref mut targets } => {
                for target in targets.iter_mut() {
                    IpMaskSelection::replace_groups(&mut target.allowlist, &groups)?;
                }
            }
            TargetConfigs::Udp { ref mut targets } => {
                for target in targets.iter_mut() {
                    IpMaskSelection::replace_groups(&mut target.allowlist, &groups)?;
                }
            }
        }
    }

    for config_url in config_urls {
        server_configs.push(load_url(&config_url).await?);
    }

    Ok(server_configs)
}

pub async fn load_url(config_url: &str) -> std::io::Result<ServerConfig> {
    let url = Url::parse(config_url).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Failed to parse url: {}", e),
        )
    })?;

    if url.scheme() != "tcp" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "URL format only supports TCP",
        ));
    }

    let host_str = url.host_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No host specified in URL format",
        )
    })?;

    let port = url.port().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No port specified in URL format",
        )
    })?;

    let address = tokio::net::lookup_host((host_str, port))
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unable to resolve bind address",
            )
        })?;

    let mut locations = vec![];

    for (query_key, query_value) in url.query_pairs().into_owned() {
        let query_value = percent_decode_str(&query_value)
            .decode_utf8()
            .unwrap()
            .into_owned();

        match query_key.as_str() {
            "target" | "target-address" => {
                locations.push(TcpTargetLocation::Config {
                    location: Location::Address(query_value.as_str().try_into()?),
                    client_tls: ClientTlsConfig::default(),
                });
            }
            "target-path" => {
                locations.push(TcpTargetLocation::Config {
                    location: Location::Path(PathBuf::from(query_value)),
                    client_tls: ClientTlsConfig::default(),
                });
            }
            unknown_key => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown URL query key: {}", unknown_key),
                ));
            }
        }
    }

    if locations.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No target locations specified in URL query",
        ));
    }

    let tcp_target_config = TcpTargetConfig {
        allowlist: OneOrSome::One(IpMaskSelection::Literal(IpMask::all())),
        locations: OneOrSome::Some(locations),
        server_tls: None,
        tcp_nodelay: true,
    };

    Ok(ServerConfig {
        address,
        use_iptables: false,
        target_configs: TargetConfigs::Tcp {
            targets: OneOrSome::One(tcp_target_config),
        },
    })
}
