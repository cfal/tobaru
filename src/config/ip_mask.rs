use std::net::{Ipv4Addr, Ipv6Addr};

use ip_network_table_deps_treebitmap::address::Address;
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
                let masklen = if masklen_str.is_empty() {
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
                    let masklen = if masklen_str.is_empty() {
                        128
                    } else {
                        let prefix = masklen_str.parse::<u32>().map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("could not parse ipv4 mask length: {}", e),
                            )
                        })?;
                        if prefix > 32 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("invalid ipv4 mask length (max 32): {prefix}"),
                            ));
                        }
                        96 + prefix
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

        Ok(Self(addr.mask(masklen), masklen))
    }
}

impl std::fmt::Display for IpMask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ip_network_table_deps_treebitmap::IpLookupTable;

    #[test]
    fn cidrs_normalize_host_bits_in_literals_json_and_yaml() {
        for (input, expected_address, expected_prefix) in [
            ("192.0.2.123/26", "::ffff:192.0.2.64", 122),
            ("192.0.2.200/24", "::ffff:192.0.2.0", 120),
            ("192.0.2.123/0", "::ffff:0.0.0.0", 96),
            ("192.0.2.123", "::ffff:192.0.2.123", 128),
            ("::ffff:192.0.2.123/122", "::ffff:192.0.2.64", 122),
            ("::ffff:192.0.2.123/80", "::", 80),
            (
                "2001:db8:1234:5678:ffff::1/65",
                "2001:db8:1234:5678:8000::",
                65,
            ),
            ("2001:db8::abcd/64", "2001:db8::", 64),
            ("2001:db8::abcd/0", "::", 0),
            ("2001:db8::abcd", "2001:db8::abcd", 128),
            ("all", "::", 0),
        ] {
            for IpMask(address, prefix) in [
                IpMask::try_from(input).unwrap(),
                serde_json::from_value(serde_json::json!(input)).unwrap(),
                serde_yaml::from_str(input).unwrap(),
            ] {
                assert_eq!(
                    address,
                    expected_address.parse::<Ipv6Addr>().unwrap(),
                    "{input}"
                );
                assert_eq!(prefix, expected_prefix, "{input}");
                let round_trip = IpMask::try_from(format!("{address}/{prefix}").as_str()).unwrap();
                assert_eq!((round_trip.0, round_trip.1), (address, prefix));
            }
        }
    }

    #[test]
    fn every_prefix_clears_only_host_bits_and_can_be_inserted() {
        for prefix in 0..=128 {
            let input = format!("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/{prefix}");
            let IpMask(address, stored_prefix) = IpMask::try_from(input.as_str()).unwrap();
            let expected = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            assert_eq!(address, Ipv6Addr::from(expected), "{input}");
            assert_eq!(stored_prefix, prefix);
            let mut table = IpLookupTable::new();
            table.insert(address, stored_prefix, ());
            assert!(table.longest_match(Ipv6Addr::from(u128::MAX)).is_some());
        }
        for prefix in 0..=32 {
            let input = format!("255.255.255.255/{prefix}");
            let IpMask(address, stored_prefix) = IpMask::try_from(input.as_str()).unwrap();
            let expected = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            assert_eq!(
                address,
                Ipv4Addr::from(expected).to_ipv6_mapped(),
                "{input}"
            );
            assert_eq!(stored_prefix, 96 + prefix);
            let mut table = IpLookupTable::new();
            table.insert(address, stored_prefix, ());
            assert!(table
                .longest_match(Ipv4Addr::BROADCAST.to_ipv6_mapped())
                .is_some());
            assert!(table.longest_match(Ipv6Addr::LOCALHOST).is_none());
        }
    }

    #[test]
    fn ipv4_prefixes_are_validated_before_mapping() {
        for prefix in ["33", "128", "4294967200", "4294967295", "4294967296"] {
            let input = format!("127.0.0.1/{prefix}");
            assert!(IpMask::try_from(input.as_str()).is_err(), "{input}");
            assert!(serde_json::from_value::<IpMask>(serde_json::json!(input)).is_err());
        }
        for (input, expected) in [
            ("127.0.0.1", 128),
            ("127.0.0.1/", 128),
            ("127.0.0.1/32", 128),
            ("127.0.0.1/0", 96),
            ("127.0.0.1/24", 120),
            ("::1", 128),
            ("::1/0", 0),
            ("::1/128", 128),
        ] {
            assert_eq!(IpMask::try_from(input).unwrap().1, expected, "{input}");
        }
        assert!(IpMask::try_from("::1/129").is_err());
    }

    #[test]
    fn mapped_ipv4_prefixes_do_not_admit_unrelated_addresses() {
        for (input, peer, expected) in [
            ("127.0.0.1/32", "127.0.0.1", true),
            ("127.0.0.1/32", "203.0.113.42", false),
            ("127.0.0.1/0", "203.0.113.42", true),
            ("127.0.0.1/0", "::1", false),
        ] {
            let IpMask(address, prefix) = IpMask::try_from(input).unwrap();
            let mut table = IpLookupTable::new();
            table.insert(address, prefix, ());
            let peer = peer
                .parse::<Ipv6Addr>()
                .unwrap_or_else(|_| peer.parse::<Ipv4Addr>().unwrap().to_ipv6_mapped());
            assert_eq!(table.longest_match(peer).is_some(), expected);
        }
    }

    #[test]
    fn invalid_prefixes_cannot_be_resolved_as_literal_allowlists_or_groups() {
        use crate::config::{IpMaskGroupConfig, IpMaskSelection, OneOrSome, TcpTargetConfig};
        let invalid = "127.0.0.1/4294967200";
        let mut target: TcpTargetConfig = serde_json::from_value(serde_json::json!({
            "allowlist": invalid, "location": "127.0.0.1:80"
        }))
        .unwrap();
        let groups = std::collections::HashMap::new();
        assert!(IpMaskSelection::replace_groups(&mut target.allowlist, &groups).is_err());
        let mut group: IpMaskGroupConfig = serde_json::from_value(serde_json::json!({
            "group": "clients", "ip_mask": invalid
        }))
        .unwrap();
        assert!(IpMaskSelection::replace_groups(&mut group.ip_masks, &groups).is_err());
        assert!(matches!(
            target.allowlist,
            OneOrSome::One(IpMaskSelection::Group(_))
        ));
    }
}
