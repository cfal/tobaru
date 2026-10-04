use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetLocation {
    pub address: String,
    pub port: u16,
}

impl TryFrom<&str> for NetLocation {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::io::Result<Self> {
        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid net address: {value}; expected host:port or [IPv6]:port"),
            )
        };
        let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
        let address = if host.starts_with('[') && host.ends_with(']') {
            host[1..host.len() - 1]
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| invalid())?
                .to_string()
        } else {
            if host.is_empty()
                || host.contains([':', '[', ']'])
                || host.chars().any(char::is_whitespace)
            {
                return Err(invalid());
            }
            host.to_owned()
        };
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let port = port.parse::<u16>().map_err(|_| invalid())?;
        Ok(Self { address, port })
    }
}

impl<'de> Deserialize<'de> for NetLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        value.as_str().try_into().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for NetLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.address.contains(':') {
            write!(f, "[{}]:{}", self.address, self.port)
        } else {
            write!(f, "{}:{}", self.address, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_support_hostnames_and_both_ip_families() {
        for (wire, host, port) in [
            ("backend.test:443", "backend.test", 443),
            ("127.0.0.1:0", "127.0.0.1", 0),
            ("[::1]:8080", "::1", 8080),
            ("[2001:db8::1]:65535", "2001:db8::1", 65535),
        ] {
            let location: NetLocation = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(location.address, host);
            assert_eq!(location.port, port);
            assert_eq!(
                NetLocation::try_from(location.to_string().as_str()).unwrap(),
                location
            );
        }
    }

    #[test]
    fn malformed_locations_return_config_errors() {
        for wire in [
            "backend",
            "backend:abc",
            "backend:99999",
            "backend:",
            ":80",
            "backend:+80",
            "::1:80",
            "[bad]:80",
            "[::1:80",
            "backend:80:90",
        ] {
            assert_eq!(
                NetLocation::try_from(wire).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput,
                "{wire}"
            );
            let error = serde_json::from_value::<NetLocation>(serde_json::json!(wire)).unwrap_err();
            assert!(error.to_string().contains("Invalid net address"), "{error}");
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Location {
    // We don't convert to SocketAddr here so that if it's a hostname,
    // it could be updated without restarting the process depending on
    // the system's DNS settings.
    Address(NetLocation),
    Path(PathBuf),
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Location::Address(net_location) => write!(f, "{}", net_location),
            Location::Path(p) => write!(f, "{}", p.display()),
        }
    }
}
