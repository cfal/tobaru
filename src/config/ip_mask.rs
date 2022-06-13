use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct IpMask(pub Ipv6Addr, pub u32);

impl IpMask {
    pub fn all() -> Self {
        Self(Ipv6Addr::UNSPECIFIED, 0)
    }
}

impl TryFrom<&str> for IpMask {
    type Error = std::io::Error;

    fn try_from(mask_str: &str) -> std::io::Result<Self> {
        if mask_str == "all" {
            return Ok(IpMask::all());
        }

        let tokens: Vec<&str> = mask_str.split('/').collect();
        let (ip_str, masklen_str) = if tokens.len() == 1 {
            (mask_str, "")
        } else if tokens.len() == 2 {
            (tokens[0], tokens[1])
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid ip mask: {}", mask_str),
            ));
        };

        let (addr, masklen) = match ip_str.parse::<Ipv6Addr>() {
            Ok(i) => {
                let masklen = if masklen_str.len() == 0 {
                    128
                } else {
                    masklen_str.parse().map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("could not parse ipv6 mask length: {}", e),
                        )
                    })?
                };
                (i, masklen)
            }
            Err(_) => match ip_str.parse::<Ipv4Addr>() {
                Ok(i) => {
                    let masklen = if masklen_str.len() == 0 {
                        128
                    } else {
                        96 + masklen_str.parse::<u32>().map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("could not parse ipv4 mask length: {}", e),
                            )
                        })?
                    };
                    (i.to_ipv6_mapped(), masklen)
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("could not parse ip address: {}", e),
                    ));
                }
            },
        };

        if masklen > 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid ipv6 mask length (max 128): {}", masklen),
            ));
        }

        Ok(Self(addr, masklen))
    }
}

impl std::fmt::Display for IpMask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "{}/{}", self.0, self.1)
    }
}

impl<'de> Deserialize<'de> for IpMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let mask_str = String::deserialize(deserializer)?;

        let mask = mask_str.as_str().try_into().map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("invalid ip mask"),
                &"invalid ip mask",
            )
        })?;

        Ok(mask)
    }
}
