use json::JsonValue;
use log::{debug, warn};

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

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
pub struct TcpTargetAddress {
    // We don't convert to SocketAddr here so that if it's a hostname,
    // it could be updated without restarting the process depending on
    // the system's DNS settings.
    pub address: String,
    pub port: u16,
    pub tls: bool,
}

pub type IpMask = (Ipv6Addr, u32);

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub struct TcpTargetConfig {
    pub target_addresses: Vec<TcpTargetAddress>,
    pub allowlist: Vec<IpMask>,
    pub server_tls_config: Option<TlsConfig>,
    pub early_connect: bool,
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
    pub allowlist: Vec<IpMask>,
    pub association_timeout_secs: Option<u32>,
}

pub fn load_configs(config_paths: Vec<String>, config_urls: Vec<String>) -> Vec<ServerConfig> {
    let mut config_objects: Vec<JsonValue> = config_paths
        .iter()
        .map(|config_path| {
            let config_str =
                std::fs::read_to_string(config_path).expect("Failed to read from config file");
            let config_str = config_str
                .split('\n')
                .filter(|line| return !line.trim_start().starts_with("//"))
                .collect::<Vec<&str>>()
                .join("\n");
            json::parse(&config_str).expect("Invalid JSON in config")
        })
        .collect();

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

    for config_url in config_urls {
        all_configs.push(load_config_from_url(config_url, &ip_groups));
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

fn load_config_from_url(url: String, ip_groups: &HashMap<String, Vec<IpMask>>) -> ServerConfig {
    fn split(mut input: String, separator: &str) -> (String, String) {
        match input.find(separator) {
            Some(index) => {
                let suffix = input.split_off(index + separator.len());
                input.truncate(input.len() - separator.len());
                (input, suffix)
            }
            None => (input, String::new()),
        }
    }

    fn trim(input: &mut String, c: u8) {
        let b = input.as_bytes();
        let mut i = b.len() - 1;
        while b[i] == c {
            i -= 1;
        }
        input.truncate(i + 1);
    }

    fn b(input: String) -> bool {
        input != "false" && input != "0"
    }

    let mut obj = JsonValue::new_object();

    let (protocol, remaining) = split(url, "://");

    obj.insert("protocol", protocol).unwrap();

    let (mut address, query) = split(remaining, "?");
    trim(&mut address, b'/');

    obj.insert("bindAddress", address.clone()).unwrap();

    // only a single target is supported with urls.
    let mut target = JsonValue::new_object();

    for param in query.split("&") {
        let (key, value) = split(param.to_string(), "=");
        if key == "iptables" {
            obj.insert("iptables", b(value)).unwrap();
        } else if key == "targetAddress" || key == "target" || key == "to" {
            target.insert("address", value).unwrap();
        } else if key == "tcp_nodelay" || key == "nodelay" || key == "tcpNodelay" {
            target.insert("tcp_nodelay", b(value)).unwrap();
        } else if key == "early_connect" || key == "earlyConnect" {
            target.insert("early_connect", b(value)).unwrap()
        } else if key == "allowlist" || key == "allow" || key == "allowed" {
            target
                .insert(
                    "allowlist",
                    value
                        .split(",")
                        .map(|item| item.to_string())
                        .collect::<Vec<String>>(),
                )
                .unwrap();
        } else {
            panic!("Unknown query parameter: {}", key);
        }
    }

    if !target.has_key("address") {
        panic!("Config URL for {} is missing target address.", address);
    }

    if !target.has_key("allowlist") {
        warn!(
            "Config URL for {} missing allowlist, allowing all connections.",
            address
        );
        target.insert("allowlist", vec!["0.0.0.0/0"]).unwrap();
    }

    obj.insert("target", target).unwrap();

    parse_server_object(obj, ip_groups)
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

    let use_iptables = obj["iptables"].as_bool().unwrap_or(false);

    let target_configs = match obj["protocol"].as_str().unwrap_or("tcp") {
        "tcp" => {
            let target_configs = if obj.has_key("target") {
                vec![parse_tcp_target_object(obj["target"].take(), ip_groups)]
            } else {
                let target_objs = match obj["targets"].take() {
                    JsonValue::Array(v) => v,
                    _ => panic!("Invalid targets"),
                };
                target_objs
                    .into_iter()
                    .map(|target_obj| parse_tcp_target_object(target_obj, ip_groups))
                    .collect()
            };
            TargetConfigs::Tcp(target_configs)
        }
        "udp" => {
            let target_configs = if obj.has_key("target") {
                vec![parse_udp_target_object(obj["target"].take(), ip_groups)]
            } else {
                let target_objs = match obj["targets"].take() {
                    JsonValue::Array(v) => v,
                    _ => panic!("Invalid targets"),
                };
                target_objs
                    .into_iter()
                    .map(|target_obj| parse_udp_target_object(target_obj, ip_groups))
                    .collect()
            };
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

fn parse_tcp_target_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> TcpTargetConfig {
    let server_tls_config = if obj.has_key("serverTls") {
        Some(parse_tls_object(obj["serverTls"].take()))
    } else {
        None
    };

    let target_addresses = if obj.has_key("address") {
        vec![parse_tcp_target_address(obj["address"].take())]
    } else {
        let addresses_objs = match obj["addresses"].take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid target addresses"),
        };
        addresses_objs
            .into_iter()
            .map(parse_tcp_target_address)
            .collect()
    };

    if target_addresses.is_empty() {
        panic!("No target addresses specified.");
    }

    let allowlist = match obj["allowlist"].take() {
        JsonValue::String(s) => lookup_ip_mask(&s, ip_groups),
        JsonValue::Short(s) => lookup_ip_mask(s.as_str(), ip_groups),
        JsonValue::Array(v) => v
            .into_iter()
            .map(|v| lookup_ip_mask(v.as_str().expect("Invalid allowlist entry"), ip_groups))
            .collect::<Vec<Vec<IpMask>>>()
            .concat(),
        invalid => panic!("Invalid allowlist value: {}", invalid),
    };

    let early_connect = match obj["early_connect"].take() {
        JsonValue::Boolean(b) => b,
        JsonValue::Null => false,
        invalid => panic!("Invalid early_connect value: {}", invalid),
    };

    if early_connect {
        warn!("Enabling early connect, this can cause excessive target connections on unauthorized connections.");
    }

    let tcp_nodelay = match obj["tcp_nodelay"].take() {
        JsonValue::Boolean(b) => b,
        JsonValue::Null => false,
        invalid => panic!("Invalid tcp_nodelay value: {}", invalid),
    };

    TcpTargetConfig {
        server_tls_config,
        target_addresses,
        allowlist,
        early_connect,
        tcp_nodelay,
    }
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

fn parse_tls_object(mut obj: JsonValue) -> TlsConfig {
    TlsConfig {
        cert_path: obj["cert"].take_string().expect("No cert path"),
        key_path: obj["key"].take_string().expect("No key path"),
        optional: obj["optional"].as_bool().unwrap_or(false),
    }
}

fn parse_tcp_target_address(mut obj: JsonValue) -> TcpTargetAddress {
    if obj.is_object() {
        TcpTargetAddress {
            address: obj["address"]
                .take_string()
                .expect("Target address is not a string"),
            port: obj["port"]
                .as_u16()
                .expect("Target port is not a valid number"),
            tls: obj["tls"].as_bool().unwrap_or(false),
        }
    } else if obj.is_string() {
        let mut s = obj.take_string().unwrap();
        let i = s.rfind(':').expect("No port separator in address string");
        let mut port_str = s.split_off(i + 1);
        // Remove the colon.
        s.pop();

        let (port_str, tls) = if port_str.starts_with("+") {
            (port_str.split_off(1), true)
        } else {
            (port_str, false)
        };

        TcpTargetAddress {
            address: s,
            port: port_str.parse().expect("Invalid target port"),
            tls,
        }
    } else {
        panic!("Invalid target address: {}", obj);
    }
}

fn parse_udp_target_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> UdpTargetConfig {
    let target_addresses = if obj.has_key("address") {
        vec![parse_udp_target_address(obj["address"].take())]
    } else {
        let addresses_objs = match obj["addresses"].take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid target addresses"),
        };
        addresses_objs
            .into_iter()
            .map(parse_udp_target_address)
            .collect()
    };

    if target_addresses.is_empty() {
        panic!("No target addresses specified.");
    }

    let allowlist = match obj["allowlist"].take() {
        JsonValue::String(s) => lookup_ip_mask(&s, ip_groups),
        JsonValue::Short(s) => lookup_ip_mask(s.as_str(), ip_groups),
        JsonValue::Array(v) => v
            .into_iter()
            .map(|v| lookup_ip_mask(v.as_str().expect("Invalid allowlist entry"), ip_groups))
            .collect::<Vec<Vec<IpMask>>>()
            .concat(),
        invalid => panic!("Invalid allowlist value: {}", invalid),
    };

    let association_timeout_secs = obj["association_timeout_secs"].as_u32();

    UdpTargetConfig {
        target_addresses,
        allowlist,
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
