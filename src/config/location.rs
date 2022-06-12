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
        let tokens = value.splitn(2, ':').collect::<Vec<_>>();
        if tokens.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid net address",
            ));
        }
        let address = tokens[0].to_string();
        let port = tokens[1].parse::<u16>().unwrap();
        Ok(Self { address, port })
    }
}

impl<'de> Deserialize<'de> for NetLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        let net_location = value.as_str().try_into().map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("invalid net address"),
                &"invalid net address",
            )
        })?;

        Ok(net_location)
    }
}

impl std::fmt::Display for NetLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "{}:{}", self.address, self.port)
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
