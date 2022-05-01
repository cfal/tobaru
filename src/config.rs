use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use json::JsonValue;
use log::{debug, warn};
use percent_encoding::percent_decode_str;
use url::Url;

use crate::location::Location;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_address: SocketAddr,
    pub use_iptables: bool,
    pub target_configs: TargetConfigs,
}

#[derive(Debug, Clone)]
pub enum TargetConfigs {
    Tcp(Vec<TcpTargetConfig>),
    Udp(Vec<UdpTargetConfig>),
}

#[derive(Debug, Clone)]
pub struct TcpTargetLocation {
    pub location: Location,
    pub client_tls_config: Option<ClientTlsConfig>,
}

pub type IpMask = (Ipv6Addr, u32);

#[derive(Debug, Clone)]
pub struct ServerTlsConfig {
    pub sni_hostnames: HashSet<TlsOption>,
    // the alpn protocols to show in the serverhello response
    pub alpn_protocols: HashSet<TlsOption>,

    pub cert_path: String,
    pub key_path: String,
    pub optional: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum TlsOption {
    None,
    Any,
    Specified(String),
}

impl From<&str> for TlsOption {
    fn from(s: &str) -> Self {
        match s {
            "any" => TlsOption::Any,
            "none" => TlsOption::None,
            hostname => TlsOption::Specified(hostname.to_string()),
        }
    }
}

impl TlsOption {
    pub fn is_specified(&self) -> bool {
        match self {
            TlsOption::Specified(_) => true,
            _ => false,
        }
    }
    pub fn unwrap_specified(&self) -> &str {
        match self {
            TlsOption::Specified(s) => s.as_str(),
            _ => panic!("Not a hostname"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientTlsConfig {
    pub verify: bool,
}

#[derive(Debug, Clone)]
pub struct TcpTargetConfig {
    pub allowed_ips: Vec<IpMask>,
    pub target_locations: Vec<TcpTargetLocation>,
    pub server_tls_config: Option<ServerTlsConfig>,
    pub tcp_nodelay: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct UdpTargetAddress {
    // We don't convert to SocketAddr here so that if it's a hostname,
    // it could be updated without restarting the process depending on
    // the system's DNS settings.
    pub address: String,
    pub port: u16,
}

impl std::fmt::Display for UdpTargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "{}:{}", self.address, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct UdpTargetConfig {
    pub target_addresses: Vec<UdpTargetAddress>,
    pub allowed_ips: Vec<IpMask>,
    pub association_timeout_secs: Option<u32>,
}

pub async fn load_configs(
    config_paths: Vec<String>,
    config_urls: Vec<String>,
    is_initial: bool,
) -> Vec<ServerConfig> {
    let mut config_objects = vec![];
    for config_path in config_paths {
        let config_str = match tokio::fs::read_to_string(&config_path).await {
            Ok(s) => s,
            Err(e) => {
                println!("Failed to read {}, skipping: {}", config_path, e);
                if is_initial {
                    panic!("Initial load failed.");
                }
                continue;
            }
        };
        let config_str = config_str
            .split('\n')
            .filter(|line| return !line.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");
        let config_object = match json::parse(&config_str) {
            Ok(o) => o,
            Err(e) => {
                println!("Failed to read {}, invalid JSON: {}", config_path, e);
                if is_initial {
                    panic!("Initial load failed.");
                }
                continue;
            }
        };
        config_objects.push(config_object);
    }

    for config_url in config_urls {
        let config_object = convert_url_to_obj(&config_url).unwrap();
        config_objects.push(config_object);
    }

    let mut ip_groups = HashMap::new();
    for config_object in config_objects.iter_mut() {
        load_ip_groups(config_object, &mut ip_groups);
    }

    debug!("IP groups: {:#?}", ip_groups);

    let mut all_configs = vec![];
    for config_object in config_objects.into_iter() {
        let configs = load_config(config_object, &ip_groups);
        all_configs.extend(configs.into_iter())
    }

    all_configs
}

fn load_ip_groups(obj: &mut JsonValue, ip_groups: &mut HashMap<String, Vec<IpMask>>) {
    if !obj.has_key("ipGroups") {
        return;
    }

    let mut groups = match obj["ipGroups"].take() {
        JsonValue::Object(o) => o,
        _ => panic!("Invalid ipGroups object"),
    };

    for (group_name, group_val) in groups.iter_mut() {
        let ips = match group_val.take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid ipGroups range array"),
        };
        let ip_strs = ips
            .into_iter()
            .map(|obj| {
                let ip_str = obj
                    .as_str()
                    .expect("Invalid ip group entry, expected string");
                lookup_ip_mask(ip_str, ip_groups)
            })
            .collect::<Vec<Vec<IpMask>>>()
            .concat();
        ip_groups.insert(group_name.to_string(), ip_strs);
    }
}

fn convert_ip_mask(mask_str: &str) -> IpMask {
    if mask_str == "all" {
        // Special string meaning all IPs should be accepted.
        return (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0);
    }

    let tokens: Vec<&str> = mask_str.split('/').collect();
    let (ip_str, mask_str) = if tokens.len() == 1 {
        (mask_str, "")
    } else if tokens.len() == 2 {
        (tokens[0], tokens[1])
    } else {
        panic!("Invalid ip mask: {}", mask_str);
    };

    match ip_str.parse::<Ipv6Addr>() {
        Ok(i) => {
            let masklen = if mask_str.len() == 0 {
                128
            } else {
                mask_str.parse().expect("Could not parse ipv6 mask")
            };
            (i, masklen)
        }
        Err(_) => match ip_str.parse::<Ipv4Addr>() {
            Ok(i) => {
                let masklen = if mask_str.len() == 0 {
                    128
                } else {
                    mask_str.parse::<u32>().expect("Could not parse ipv4 mask") + 96
                };
                (i.to_ipv6_mapped(), masklen)
            }
            Err(_) => {
                panic!("Invalid ip address: {}", ip_str);
            }
        },
    }
}

fn load_config(mut obj: JsonValue, ip_groups: &HashMap<String, Vec<IpMask>>) -> Vec<ServerConfig> {
    let server_objs = match obj {
        JsonValue::Array(v) => v,
        JsonValue::Object(_) => {
            if obj.has_key("servers") {
                match obj["servers"].take() {
                    JsonValue::Array(v) => v,
                    _ => {
                        panic!("Expected array value for servers.")
                    }
                }
            } else {
                vec![obj]
            }
        }
        _ => vec![obj],
    };

    server_objs
        .into_iter()
        .map(|server_obj| parse_server_object(server_obj, ip_groups))
        .collect()
}

fn parse_server_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> ServerConfig {
    let server_address = obj["bindAddress"]
        .take_string()
        .expect("No bind address")
        .to_socket_addrs()
        .expect("Invalid bind address")
        .next()
        .expect("Unable to resolve bind address");

    let use_iptables = is_true_value(&obj["iptables"], false);

    let target_value = take_existing(&mut obj, &["target", "targets", "to"]);

    let target_objs = match target_value {
        JsonValue::String(s) => {
            let mut json_obj = JsonValue::new_object();
            json_obj["address"] = s.into();
            vec![json_obj]
        }
        JsonValue::Object(_) => vec![target_value],
        JsonValue::Array(v) => v,
        _ => panic!("Invalid targets"),
    };

    let target_configs = match obj["protocol"].as_str().unwrap_or("tcp") {
        "tcp" => {
            let target_configs = target_objs
                .into_iter()
                .map(|target_obj| parse_tcp_target_object(target_obj, ip_groups))
                .collect();

            TargetConfigs::Tcp(target_configs)
        }
        "udp" => {
            let target_configs = target_objs
                .into_iter()
                .map(|target_obj| parse_udp_target_object(target_obj, ip_groups))
                .collect();
            TargetConfigs::Udp(target_configs)
        }
        unknown_protocol => {
            panic!("Unknown protocol value: {}", unknown_protocol);
        }
    };

    ServerConfig {
        server_address,
        use_iptables,
        target_configs,
    }
}

fn take_target_location_objects(obj: &mut JsonValue) -> Vec<JsonValue> {
    if obj.has_key("location") {
        vec![obj["location"].take()]
    } else if obj.has_key("locations") {
        match obj["locations"].take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid target addresses"),
        }
    } else if obj.has_key("address") {
        warn!("Target key 'address' is deprecated");
        vec![obj["address"].take()]
    } else if obj.has_key("addresses") {
        warn!("Target key 'addresses' is deprecated");
        match obj["addresses"].take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid target addresses"),
        }
    } else {
        panic!("Target object has no location field");
    }
}

fn parse_tcp_target_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> TcpTargetConfig {
    let server_tls_config = parse_server_tls_object(obj["serverTls"].take());

    let location_objs = take_target_location_objects(&mut obj);

    let target_locations: Vec<TcpTargetLocation> = location_objs
        .into_iter()
        .map(parse_tcp_target_location)
        .collect();

    if target_locations.is_empty() {
        panic!("No target addresses specified.");
    }

    // support allowlist key for backwards compatibility
    let allowed_ips = parse_allowed_ips(&mut obj, ip_groups);

    let tcp_nodelay = match obj["tcp_nodelay"].take() {
        JsonValue::Boolean(b) => b,
        JsonValue::Null => false,
        invalid => panic!("Invalid tcp_nodelay value: {}", invalid),
    };

    TcpTargetConfig {
        allowed_ips,
        server_tls_config,
        target_locations,
        tcp_nodelay,
    }
}

fn parse_allowed_ips(obj: &mut JsonValue, ip_groups: &HashMap<String, Vec<IpMask>>) -> Vec<IpMask> {
    let allowed_ips_obj = take_existing(obj, &["allowed_ips", "allowlist"]);

    let allowed_ip_strs = match allowed_ips_obj {
        JsonValue::String(s) => vec![s],
        JsonValue::Short(s) => vec![s.as_str().to_string()],
        JsonValue::Array(v) => v
            .into_iter()
            .map(|v| v.as_str().expect("Invalid allowed_ips entry").to_string())
            .collect::<Vec<_>>(),
        JsonValue::Null => vec!["all".to_string()],
        invalid => panic!("Invalid allowed_ips value: {}", invalid),
    };

    allowed_ip_strs
        .into_iter()
        .map(|s| lookup_ip_mask(&s, ip_groups))
        .collect::<Vec<Vec<IpMask>>>()
        .concat()
}

fn lookup_ip_mask(s: &str, ip_groups: &HashMap<String, Vec<IpMask>>) -> Vec<IpMask> {
    if s.starts_with("@") {
        match ip_groups.get(&s[1..]) {
            Some(ips) => ips.iter().map(|ip| ip.clone()).collect(),
            None => {
                panic!("No such IP group: {}", s)
            }
        }
    } else {
        vec![convert_ip_mask(s)]
    }
}

fn parse_server_tls_object(obj: JsonValue) -> Option<ServerTlsConfig> {
    match obj {
        JsonValue::Null => None,
        JsonValue::Object(mut o) => {
            let sni_hostnames = match o["sni_hostnames"].take() {
                JsonValue::String(s) => HashSet::from([s.as_str().into()]),
                JsonValue::Short(s) => HashSet::from([s.as_str().into()]),
                JsonValue::Array(v) => {
                    let mut hostnames = v
                        .into_iter()
                        .map(|v| v.as_str().expect("Invalid sni_hostnames entry").into())
                        .collect::<HashSet<_>>();
                    if hostnames.is_empty() {
                        hostnames.extend([TlsOption::None, TlsOption::Any]);
                    }
                    hostnames
                }
                JsonValue::Null => HashSet::from([TlsOption::None, TlsOption::Any]),
                invalid => panic!("Invalid sni_hostnames value: {}", invalid),
            };

            let cert_path = o["cert"].take_string().expect("No cert path");
            let key_path = o["key"].take_string().expect("No key path");
            let optional = is_true_value(&o["optional"], false);

            let alpn_protocols = match o["alpn_protocols"].take() {
                JsonValue::String(s) => HashSet::from([s.as_str().into()]),
                JsonValue::Short(s) => HashSet::from([s.as_str().into()]),
                JsonValue::Array(v) => {
                    let mut hostnames = v
                        .into_iter()
                        .map(|v| v.as_str().expect("Invalid alpn_protocols entry").into())
                        .collect::<HashSet<_>>();
                    if hostnames.is_empty() {
                        hostnames.extend([TlsOption::None, TlsOption::Any]);
                    }
                    hostnames
                }
                JsonValue::Null => HashSet::from([TlsOption::None, TlsOption::Any]),
                invalid => panic!("Invalid alpn_protocols value: {}", invalid),
            };

            Some(ServerTlsConfig {
                sni_hostnames,
                alpn_protocols,
                cert_path,
                key_path,
                optional,
            })
        }
        _ => {
            panic!("Unknown server TLS config");
        }
    }
}

fn parse_client_tls_object(obj: JsonValue) -> Option<ClientTlsConfig> {
    match obj {
        JsonValue::Null => None,
        JsonValue::Object(mut o) => {
            let verify = o
                .remove("verify")
                .map(|v| is_true_value(&v, true))
                .unwrap_or(true);
            Some(ClientTlsConfig { verify })
        }
        _ => {
            if is_true_value(&obj, false) {
                Some(ClientTlsConfig { verify: true })
            } else {
                None
            }
        }
    }
}

fn parse_tcp_target_location(mut obj: JsonValue) -> TcpTargetLocation {
    if obj.is_object() {
        let location = if obj.has_key("path") {
            let path_str = obj["path"]
                .take_string()
                .expect("Target path is not a string");
            Location::from_path(path_str.as_str())
        } else {
            let address = obj["address"]
                .take_string()
                .expect("Target address is not a string");
            if obj.has_key("port") {
                let port = obj["port"]
                    .as_u16()
                    .expect("Target port is not a valid number");
                (address.as_str(), port).into()
            } else {
                Location::from_net_address(&address).expect("Target address is invalid")
            }
        };

        TcpTargetLocation {
            location,
            client_tls_config: parse_client_tls_object(obj["tls"].take()),
        }
    } else if obj.is_string() {
        let mut s = obj.take_string().unwrap();

        let (location_str, query_str) = match s.find("/?") {
            Some(i) => {
                let query_str = s.split_off(i + 2);
                // Remove the question mark and the slash.
                s.pop();
                s.pop();
                (s, query_str)
            }
            None => (s, String::new()),
        };

        let location = Location::from(location_str.as_str());
        TcpTargetLocation {
            location,
            client_tls_config: if query_str.find("tls=true").is_some() {
                Some(ClientTlsConfig {
                    verify: !query_str.find("verify=false").is_some(),
                })
            } else {
                None
            },
        }
    } else {
        panic!("Invalid target address: {}", obj);
    }
}

fn parse_udp_target_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> UdpTargetConfig {
    let location_objs = take_target_location_objects(&mut obj);

    let target_addresses: Vec<UdpTargetAddress> = location_objs
        .into_iter()
        .map(parse_udp_target_address)
        .collect();

    if target_addresses.is_empty() {
        panic!("No target addresses specified.");
    }

    let allowed_ips = parse_allowed_ips(&mut obj, ip_groups);

    let association_timeout_secs = obj["association_timeout_secs"].as_u32();

    UdpTargetConfig {
        target_addresses,
        allowed_ips,
        association_timeout_secs,
    }
}

fn parse_udp_target_address(mut obj: JsonValue) -> UdpTargetAddress {
    if obj.is_object() {
        UdpTargetAddress {
            address: obj["address"]
                .take_string()
                .expect("Target address is not a string"),
            port: obj["port"]
                .as_u16()
                .expect("Target port is not a valid number"),
        }
    } else if obj.is_string() {
        let mut s = obj.take_string().unwrap();
        let i = s.rfind(':').expect("No port separator in address string");
        let port_str = s.split_off(i + 1);
        // Remove the colon.
        s.pop();

        UdpTargetAddress {
            address: s,
            port: port_str.parse().expect("Invalid target port"),
        }
    } else {
        panic!("Invalid target address: {}", obj);
    }
}

fn is_true_value(value: &JsonValue, default_value: bool) -> bool {
    if value.is_string() {
        let value_str = value.as_str().unwrap();
        return value_str == "true" || value_str == "1" || value_str == "yes";
    } else if value.is_number() {
        let value = value.as_i32().unwrap();
        return value == 1;
    }
    value.as_bool().unwrap_or(default_value)
}

fn convert_url_to_obj(url_str: &str) -> std::result::Result<JsonValue, String> {
    let url = Url::parse(url_str).map_err(|e| format!("Failed to parse url: {}", e))?;

    let mut json_obj = JsonValue::new_object();

    let protocol = url.scheme();

    json_obj.insert("protocol", protocol.to_string()).unwrap();

    let host_str = match url.host_str() {
        Some(s) => s.to_string(),
        None => {
            return Err(format!("URL missing host: {}", url_str));
        }
    };

    let address = match url.port() {
        Some(port) => format!("{}:{}", host_str, port),
        None => host_str,
    };

    json_obj.insert("bindAddress", address).unwrap();

    for (query_key, query_value) in url.query_pairs().into_owned() {
        let new_value = JsonValue::String(
            percent_decode_str(&query_value)
                .decode_utf8()
                .unwrap()
                .into_owned(),
        );

        let mut key_parts = query_key.split('.').collect::<Vec<_>>();
        let final_part = key_parts.pop().unwrap();

        let mut current_obj = &mut json_obj;
        for key_part in key_parts.into_iter() {
            if !current_obj.has_key(&key_part) {
                current_obj[key_part] = JsonValue::new_object();
            }
            current_obj = &mut current_obj[key_part];
        }

        if current_obj.has_key(final_part) {
            let existing_value = &mut current_obj[final_part];
            if existing_value.is_array() {
                existing_value.push(new_value).unwrap();
            } else {
                let existing_value = current_obj.remove(final_part);
                current_obj
                    .insert(final_part, vec![existing_value, new_value])
                    .unwrap();
            }
        } else {
            current_obj.insert(final_part, new_value).unwrap();
        }
    }

    Ok(json_obj)
}

fn take_existing(obj: &mut JsonValue, keys: &[&str]) -> JsonValue {
    for key in keys {
        if obj.has_key(*key) {
            return obj[*key].take();
        }
    }
    JsonValue::Null
}
