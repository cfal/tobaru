mod ip_mask;
mod location;
mod option_util;
mod tls_option;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use log::warn;
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
        #[serde(alias = "ip_mask")]
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
    #[serde(deserialize_with = "deserialize_socket_addr", alias = "bindAddress")]
    pub address: SocketAddr,
    #[serde(default, alias = "iptables")]
    pub use_iptables: bool,
    #[serde(flatten)]
    pub target_configs: TargetConfigs,
}

// serde can't seem to deserialize IPv6 addresses directly.
// see https://github.com/serde-rs/serde/issues/2227
fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use std::net::ToSocketAddrs;
    let value = String::deserialize(deserializer)?;
    let mut iter = value.to_socket_addrs().map_err(|e| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("invalid socket address"),
            &"invalid socket address",
        )
    })?;

    let socket_addr = iter.next().ok_or_else(|| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("unable to resolve socket address"),
            &"unable to resolve socket address",
        )
    })?;

    Ok(socket_addr)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum TargetConfigs {
    Tcp {
        #[serde(default = "default_true")]
        tcp_nodelay: bool,
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
    // deprecated - use Tcp::Action Forward configuration
    #[serde(alias = "location", alias = "addresses", alias = "address")]
    pub locations: NoneOrSome<TcpTargetLocation>,
    #[serde(default, alias = "serverTls")]
    pub server_tls: Option<ServerTlsConfig>,
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
    #[serde(default)]
    pub action: Option<TcpAction>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TcpAction {
    #[serde(alias = "forward")]
    Forward {
        locations: OneOrSome<TcpTargetLocation>,
    },
    #[serde(alias = "http")]
    Http {
        paths: HashMap<String, Vec<HttpPathConfig>>,
        default_http_action: HttpPathAction,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpPathConfig {
    pub required_request_headers: Option<HashMap<String, HttpValueMatch>>,
    pub http_action: HttpPathAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HttpValueMatch {
    Any,
    Single(String),
    Multiple(Vec<String>),
}

impl Default for HttpValueMatch {
    fn default() -> Self {
        HttpValueMatch::Any
    }
}

impl HttpValueMatch {
    pub fn matches(&self, value: Option<&str>) -> bool {
        match self {
            HttpValueMatch::Single(ref allowed_value) => {
                if value.is_none() {
                    return false;
                }
                allowed_value == value.unwrap()
            }
            HttpValueMatch::Multiple(ref allowed_values) => {
                if value.is_none() {
                    return false;
                }
                let value = value.unwrap();
                for v in allowed_values.iter() {
                    if v == value {
                        return true;
                    }
                }
                false
            }
            HttpValueMatch::Any => !value.is_none(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum HttpPathAction {
    CloseConnection,
    ServeMessage {
        status_code: u16,
        status_message: Option<String>,
        content: String,
        response_headers: HashMap<String, String>,
        response_id_header_name: Option<String>,
    },
    ServeDirectory {
        path: String,
        response_headers: HashMap<String, String>,
        response_id_header_name: Option<String>,
    },
    Forward {
        target_locations: OneOrSome<TcpTargetLocation>,
        // replacement paths are best effort - it's entirely possible that absolute paths are specified
        // in the returned content and it would break.
        replacement_path: Option<String>,
        request_header_patch: Option<HttpHeaderPatch>,
        response_header_patch: Option<HttpHeaderPatch>,
        request_id_header_name: Option<String>,
        response_id_header_name: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpHeaderPatch {
    pub default_headers: HashMap<String, String>,
    pub overwrite_headers: HashMap<String, String>,
    pub remove_headers: Vec<String>,
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

#[derive(Debug, Clone)]
pub enum ClientTlsConfig {
    Enabled,
    EnabledWithoutVerify,
    Disabled,
}

impl<'de> Deserialize<'de> for ClientTlsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct ClientTlsConfigVisitor;
        impl<'de> serde::de::Visitor<'de> for ClientTlsConfigVisitor {
            type Value = ClientTlsConfig;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a boolean or the string 'no-verify'")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value != "no-verify" {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Other("invalid client tls string value"),
                        &"invalid client tls string value, only supported string value is no-verify",
                    ));
                }
                Ok(ClientTlsConfig::EnabledWithoutVerify)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match v {
                    true => Ok(ClientTlsConfig::Enabled),
                    false => Ok(ClientTlsConfig::Disabled),
                }
            }
        }

        deserializer.deserialize_any(ClientTlsConfigVisitor)
    }
}

impl Default for ClientTlsConfig {
    fn default() -> Self {
        ClientTlsConfig::Disabled
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpTargetConfig {
    #[serde(alias = "address", alias = "locations", alias = "location")]
    pub addresses: OneOrSome<NetLocation>,
    pub allowlist: OneOrSome<IpMaskSelection>,
    pub association_timeout_secs: Option<u32>,
}

fn deserialize_configs(mut config_str: String) -> std::io::Result<Vec<Config>> {
    let trimmed_str = config_str.trim();
    let is_json = if trimmed_str.starts_with("//") {
        // if we detect a single-line comment as previously allowed in the
        // JSON config.
        true
    } else if trimmed_str.starts_with("{") && trimmed_str.ends_with("}") {
        // previously, a single config object was supported, convert into an array.
        config_str = format!("[\n{}\n]\n", config_str);
        true
    } else if trimmed_str.starts_with("-") {
        // yaml item in array
        false
    } else {
        warn!("Could not detect config format, assuming YAML.");
        false
    };

    if is_json {
        config_str = config_str
            .split('\n')
            .filter(|s| !s.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
    }

    if config_str.find("serverTls").is_some() {
        eprintln!("WARNING: serverTls is deprecated and has been renamed to server_tls. This will be removed in future versions.");
    }

    if config_str.find("bindAddress").is_some() {
        eprintln!("WARNING: bindAddress is deprecated and has been renamed to address. This will be removed in future versions.");
    }

    // Unfortunately, we can't grep for `address` in target configs since it's valid for server
    // configs.
    if config_str.find("addresses").is_some() {
        eprintln!("WARNING: addresses is deprecated and has been renamed to locations. This will be removed in future versions.");
    }

    if is_json {
        serde_json::from_str(&config_str).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse config JSON: {}", e),
            )
        })
    } else {
        serde_yaml::from_str(&config_str).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse config YAML: {}", e),
            )
        })
    }
}

pub async fn load_server_configs(
    config_paths: Vec<String>,
    config_urls: Vec<String>,
) -> std::io::Result<Vec<ServerConfig>> {
    let mut groups: HashMap<String, Vec<IpMask>> = HashMap::new();

    // add the default 'all' ip group.
    groups.insert(String::from("all"), vec![IpMask::all()]);

    let mut server_configs = vec![];

    for config_path in config_paths {
        let config_str = tokio::fs::read_to_string(&config_path).await?;
        let configs = deserialize_configs(config_str)?;
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
            TargetConfigs::Tcp {
                ref mut targets, ..
            } => {
                for target in targets.iter_mut() {
                    if !target.locations.is_empty() {
                        if target.action.is_some() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "Target config cannot have both locations and action",
                            ));
                        }
                        let locations = std::mem::replace(&mut target.locations, NoneOrSome::None);
                        eprintln!("WARNING: locations is deprecated, use action forward instead");
                        target.action = Some(TcpAction::Forward {
                            locations: OneOrSome::Some(locations.into_vec()),
                        });
                    }
                    if target.action.is_none() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Target config must have action",
                        ));
                    }
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
        locations: NoneOrSome::Some(locations),
        server_tls: None,
        tcp_nodelay: true,
        action: None,
    };

    Ok(ServerConfig {
        address,
        use_iptables: false,
        target_configs: TargetConfigs::Tcp {
            tcp_nodelay: true,
            targets: OneOrSome::One(tcp_target_config),
        },
    })
}
