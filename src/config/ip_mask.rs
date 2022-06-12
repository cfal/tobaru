use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct IpMask(pub Ipv6Addr, pub u32);

impl IpMask {
    pub fn all() -> Self {
        Self(Ipv6Addr::UNSPECIFIED, 0)
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
        if mask_str == "all" {
            return Ok(IpMask::all());
        }

        let tokens: Vec<&str> = mask_str.split('/').collect();
        let (ip_str, masklen_str) = if tokens.len() == 1 {
            (mask_str.as_str(), "")
        } else if tokens.len() == 2 {
            (tokens[0], tokens[1])
        } else {
            return Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("invalid ip mask"),
                &"invalid ip mask",
            ));
        };

        match ip_str.parse::<Ipv6Addr>() {
            Ok(i) => {
                let masklen = if masklen_str.len() == 0 {
                    128
                } else {
                    masklen_str.parse().map_err(|_| {
                        serde::de::Error::invalid_value(
                            serde::de::Unexpected::Other("invalid ipv6 mask"),
                            &"invalid ipv6 mask",
                        )
                    })?
                };
                Ok(Self(i, masklen))
            }
            Err(_) => match ip_str.parse::<Ipv4Addr>() {
                Ok(i) => {
                    let masklen = if masklen_str.len() == 0 {
                        128
                    } else {
                        96 + masklen_str.parse::<u32>().map_err(|_| {
                            serde::de::Error::invalid_value(
                                serde::de::Unexpected::Other("invalid ipv4 mask"),
                                &"invalid ipv4 mask",
                            )
                        })?
                    };
                    Ok(Self(i.to_ipv6_mapped(), masklen))
                }
                Err(_) => Err(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Other("invalid ip address"),
                    &"invalid ip address",
                )),
            },
        }
    }
}
