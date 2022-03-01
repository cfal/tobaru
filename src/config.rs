use json::JsonValue;
use log::{debug, warn};
use percent_encoding::percent_decode_str;
use url::Url;

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
    pub client_tls_config: Option<ClientTlsConfig>,
}

pub type IpMask = (Ipv6Addr, u32);

#[derive(Debug, Clone)]
pub struct ServerTlsConfig {
    pub allowed_sni_hostnames: Option<Vec<String>>,
    pub cert_path: String,
    pub key_path: String,
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub struct ClientTlsConfig {
    pub verify: bool,
}

#[derive(Debug, Clone)]
pub struct TcpTargetConfig {
    pub allowed_ips: Vec<IpMask>,
    pub target_addresses: Vec<TcpTargetAddress>,
    pub server_tls_config: Option<ServerTlsConfig>,
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
    pub allowed_ips: Vec<IpMask>,
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
        let config_object = convert_url_to_obj(&config_url).unwrap();
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

    let target_value = if obj.has_key("target") {
        obj["target"].take()
    } else {
        obj["targets"].take()
    };

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

fn parse_tcp_target_object(
    mut obj: JsonValue,
    ip_groups: &HashMap<String, Vec<IpMask>>,
) -> TcpTargetConfig {
    let server_tls_config = parse_server_tls_object(obj["serverTls"].take());

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

    // support allowlist key for backwards compatibility
    let allowed_ips = parse_allowed_ips(&mut obj, ip_groups);

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
        allowed_ips,
        server_tls_config,
        target_addresses,
        early_connect,
        tcp_nodelay,
    }
}

fn parse_allowed_ips(obj: &mut JsonValue, ip_groups: &HashMap<String, Vec<IpMask>>) -> Vec<IpMask> {
    let allowed_ips_obj = if obj.has_key("allowed_ips") {
        obj["allowed_ips"].take()
    } else {
        obj["allowlist"].take()
    };

    let allowed_ip_strs = match allowed_ips_obj {
        JsonValue::String(s) => vec![s],
        JsonValue::Short(s) => vec![s.as_str().to_string()],
        JsonValue::Array(v) => v
            .into_iter()
            .map(|v| v.as_str().expect("Invalid allowed_ips entry").to_string())
            .collect::<Vec<_>>(),
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
            let allowed_sni_hostnames = match o["allowed_sni_hostnames"].take() {
                JsonValue::String(s) => Some(vec![s]),
                JsonValue::Short(s) => Some(vec![s.to_string()]),
                JsonValue::Array(v) => {
                    let hostnames = v
                        .into_iter()
                        .map(|v| {
                            v.as_str()
                                .expect("Invalid allowed_sni_hostnames entry")
                                .to_string()
                        })
                        .collect::<Vec<_>>();
                    if hostnames.is_empty() {
                        panic!("allowed_sni_hostnames is empty");
                    }
                    Some(hostnames)
                }
                JsonValue::Null => None,
                invalid => panic!("Invalid allowed_sni_hostnames value: {}", invalid),
            };

            let cert_path = o["cert"].take_string().expect("No cert path");
            let key_path = o["key"].take_string().expect("No key path");
            let optional = is_true_value(&o["optional"], false);

            Some(ServerTlsConfig {
                allowed_sni_hostnames,
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

fn parse_tcp_target_address(mut obj: JsonValue) -> TcpTargetAddress {
    if obj.is_object() {
        TcpTargetAddress {
            address: obj["address"]
                .take_string()
                .expect("Target address is not a string"),
            port: obj["port"]
                .as_u16()
                .expect("Target port is not a valid number"),
            client_tls_config: parse_client_tls_object(obj["tls"].take()),
        }
    } else if obj.is_string() {
        let mut s = obj.take_string().unwrap();
        let i = s.rfind(':').expect("No port separator in address string");
        let mut suffix_str = s.split_off(i + 1);
        // Remove the colon.
        s.pop();

        let (mut port_str, query_str) = match suffix_str.find("/?") {
            Some(i) => {
                let query_str = suffix_str.split_off(i + 2);
                // Remove the question mark and the slash.
                suffix_str.pop();
                suffix_str.pop();
                (suffix_str, query_str)
            }
            None => (suffix_str, String::new()),
        };

        let (port_str, tls) = if port_str.starts_with("+") {
            (port_str.split_off(1), true)
        } else {
            (port_str, false)
        };

        TcpTargetAddress {
            address: s,
            port: port_str.parse().expect("Invalid target port"),
            client_tls_config: if tls {
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
