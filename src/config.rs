use json::JsonValue;
use log::debug;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_address: String,
    pub target_configs: Vec<TargetConfig>,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct TargetAddress {
    // We don't convert to SocketAddr here so that if it's a hostname,
    // it could be updated without restarting the process depending on
    // the system's DNS settings.
    pub address: String,
    pub port: u16,
    pub tls: bool,
}

pub type IpMask = (Ipv6Addr, u32);

#[derive(Debug, Clone)]
pub struct TargetConfig {
    pub server_tls_config: Option<TlsConfig>,
    pub target_addresses: Vec<TargetAddress>,
    pub allowlist: Vec<IpMask>,
}

pub fn load_configs(config_paths: Vec<String>) -> Vec<ServerConfig> {
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
                    .expect("Invalid ip range value, expected string");
                convert_ip_mask(ip_str)
            })
            .collect();
        ip_groups.insert(group_name.to_string(), ip_strs);
    }
}

fn convert_ip_mask(mask_str: &str) -> IpMask {
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
                32
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
    let server_address = obj["bindAddress"].take_string().expect("No bind address");

    let target_configs = if obj.has_key("target") {
        vec![parse_target_object(obj["target"].take(), ip_groups)]
    } else {
        let target_objs = match obj["targets"].take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid targets"),
        };
        target_objs
            .into_iter()
            .map(|target_obj| parse_target_object(target_obj, ip_groups))
            .collect()
    };

    ServerConfig {
        server_address,
        target_configs,
    }
}

fn parse_target_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> TargetConfig {
    let server_tls_config = if obj.has_key("serverTls") {
        Some(parse_tls_object(obj["serverTls"].take()))
    } else {
        None
    };

    let target_addresses = if obj.has_key("address") {
        vec![parse_target_address(obj["address"].take())]
    } else {
        let addresses_objs = match obj["addresses"].take() {
            JsonValue::Array(v) => v,
            _ => panic!("Invalid target addresses"),
        };
        addresses_objs
            .into_iter()
            .map(parse_target_address)
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

    TargetConfig {
        server_tls_config,
        target_addresses,
        allowlist,
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
    }
}

fn parse_target_address(mut obj: JsonValue) -> TargetAddress {
    if obj.is_object() {
        TargetAddress {
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

        TargetAddress {
            address: s,
            port: port_str.parse().expect("Invalid target port"),
            tls,
        }
    } else {
        panic!("Invalid target address: {}", obj);
    }
}
