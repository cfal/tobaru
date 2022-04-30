use std::net::ToSocketAddrs;
use std::path::PathBuf;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Location {
    // We don't convert to SocketAddr here so that if it's a hostname,
    // it could be updated without restarting the process depending on
    // the system's DNS settings.
    Net((String, u16)),
    Unix(PathBuf),
}

impl Location {
    pub fn from_net_address(value: &str) -> std::io::Result<Self> {
        let tokens = value.splitn(2, ':').collect::<Vec<_>>();
        if tokens.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid net address",
            ));
        }
        let address = tokens[0].to_string();
        let port = tokens[1].parse::<u16>().unwrap();
        Ok(Location::Net((address, port)))
    }

    pub fn from_path(value: &str) -> Self {
        Location::Unix(PathBuf::from(value))
    }
}

impl From<&str> for Location {
    fn from(value: &str) -> Self {
        if let Ok(mut iter) = value.to_socket_addrs() {
            if iter.next().is_some() {
                return Self::from_net_address(value).unwrap();
            }
        }
        Self::from_path(value)
    }
}

impl From<(&str, u16)> for Location {
    fn from(value: (&str, u16)) -> Self {
        Location::Net((value.0.to_string(), value.1))
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Location::Net((addr, port)) => write!(f, "{}:{}", addr, port),
            Location::Unix(p) => write!(f, "{}", p.display()),
        }
    }
}
