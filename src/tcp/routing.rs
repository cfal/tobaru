use std::cmp::Reverse;
use std::net::Ipv6Addr;
use std::sync::Arc;

use ip_network_table_deps_treebitmap::IpLookupTable;

use super::{TargetActionData, TargetData, TlsTargetData};
use crate::config::{IpMask, NoneOrSome, SniValue};
use crate::domain_trie::DomainTrie;
use crate::tls_parser::ParsedClientHello;

#[derive(Default)]
pub(super) struct RoutingTable {
    non_tls: IpLookupTable<Ipv6Addr, Arc<TargetData>>,
    raw: IpLookupTable<Ipv6Addr, Arc<TargetData>>,
    tls: IpLookupTable<Ipv6Addr, bool>,
    sni: DomainTrie<Vec<Arc<TlsTargetData>>>,
    no_sni: Vec<Arc<TlsTargetData>>,
}

struct IpMatch {
    prefix_len: u32,
    target: Arc<TargetData>,
}

pub(super) struct IpTargets {
    non_tls: Option<IpMatch>,
    raw: Option<IpMatch>,
    tls_prefix_len: Option<u32>,
}

impl IpTargets {
    pub fn is_empty(&self) -> bool {
        self.non_tls.is_none() && self.tls_prefix_len.is_none()
    }

    pub fn direct_target(&self) -> Option<Arc<TargetData>> {
        let candidate = self.non_tls.as_ref()?;
        if matches!(candidate.target.action_data, TargetActionData::Raw { .. }) {
            if self
                .tls_prefix_len
                .is_none_or(|prefix_len| candidate.prefix_len > prefix_len)
            {
                return Some(candidate.target.clone());
            }
        } else if self.tls_prefix_len.is_none() && self.raw.is_none() {
            return Some(candidate.target.clone());
        }
        None
    }

    pub fn fallback(&self, starts_with_tls: bool) -> Option<Arc<TargetData>> {
        // HTTP targets can accept plaintext detection failures, never opaque TLS.
        let candidate = if starts_with_tls {
            &self.raw
        } else {
            &self.non_tls
        };
        candidate.as_ref().map(|m| m.target.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum AlpnMatch {
    Any,
    Absent,
    Exact,
}

pub(super) fn alpn_match(candidate: &TlsTargetData, protocols: &[Vec<u8>]) -> Option<AlpnMatch> {
    if protocols.is_empty() {
        candidate.allow_no_alpn.then_some(AlpnMatch::Absent)
    } else if protocols
        .iter()
        .any(|p| candidate.alpn_protocols.contains(p))
    {
        Some(AlpnMatch::Exact)
    } else {
        candidate.allow_any_alpn.then_some(AlpnMatch::Any)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct TlsRank {
    ip_prefix_len: u32,
    sni_specificity: usize,
    alpn: AlpnMatch,
    config_order: Reverse<usize>,
}

pub(super) enum SelectedTarget {
    Raw(Arc<TargetData>),
    Tls(Arc<TlsTargetData>, AlpnMatch),
}

impl RoutingTable {
    pub fn insert_non_tls(
        &mut self,
        allowlist: &[IpMask],
        target: Arc<TargetData>,
    ) -> std::io::Result<()> {
        let mut seen = IpLookupTable::new();
        for &IpMask(address, prefix_len) in allowlist {
            if seen.insert(address, prefix_len, ()).is_some() {
                return Err(std::io::Error::other(format!(
                    "Address {address}/{prefix_len} is duplicated in the target allowlist."
                )));
            }
            // Targets are registered in configuration order; equal prefixes keep
            // the first eligible target in each protocol class.
            if self.non_tls.exact_match(address, prefix_len).is_none() {
                self.non_tls.insert(address, prefix_len, target.clone());
            }
            if matches!(target.action_data, TargetActionData::Raw { .. })
                && self.raw.exact_match(address, prefix_len).is_none()
            {
                self.raw.insert(address, prefix_len, target.clone());
            }
        }
        Ok(())
    }

    pub fn insert_tls(&mut self, hostnames: &NoneOrSome<SniValue>, target: Arc<TlsTargetData>) {
        for (address, prefix_len, _) in target.ip_lookup_table.iter() {
            self.tls.insert(address, prefix_len, true);
        }
        if hostnames.is_empty() {
            self.sni.entry_or_default("*").push(target.clone());
            self.no_sni.push(target);
            return;
        }
        for hostname in hostnames.iter() {
            match hostname {
                SniValue::None => self.no_sni.push(target.clone()),
                SniValue::Any => self.sni.entry_or_default("*").push(target.clone()),
                SniValue::Specified(pattern) => {
                    if let Some(suffix) = pattern.strip_prefix('.') {
                        self.sni.entry_or_default(suffix).push(target.clone());
                        self.sni
                            .entry_or_default(&format!("*.{suffix}"))
                            .push(target.clone());
                    } else {
                        self.sni.entry_or_default(pattern).push(target.clone());
                    }
                }
            }
        }
    }

    pub fn ip_targets(&self, ip: Ipv6Addr) -> IpTargets {
        let lookup = |table: &IpLookupTable<Ipv6Addr, Arc<TargetData>>| {
            table
                .longest_match(ip)
                .map(|(_, prefix_len, target)| IpMatch {
                    prefix_len,
                    target: target.clone(),
                })
        };
        IpTargets {
            non_tls: lookup(&self.non_tls),
            raw: lookup(&self.raw),
            tls_prefix_len: self
                .tls
                .longest_match(ip)
                .map(|(_, prefix_len, _)| prefix_len),
        }
    }

    pub fn select(
        &self,
        ip: Ipv6Addr,
        parsed: &ParsedClientHello,
        ip_targets: &IpTargets,
    ) -> Option<SelectedTarget> {
        let mut best: Option<(TlsRank, Arc<TlsTargetData>)> = None;
        let mut consider = |sni_specificity, candidates: &Vec<Arc<TlsTargetData>>| {
            for candidate in candidates {
                let Some((_, ip_prefix_len, _)) = candidate.ip_lookup_table.longest_match(ip)
                else {
                    continue;
                };
                let Some(alpn) = alpn_match(candidate, &parsed.alpn_protocols) else {
                    continue;
                };
                let rank = TlsRank {
                    ip_prefix_len,
                    sni_specificity,
                    alpn,
                    config_order: Reverse(candidate.config_order),
                };
                if best.as_ref().is_none_or(|(previous, _)| rank > *previous) {
                    best = Some((rank, candidate.clone()));
                }
            }
        };
        match &parsed.server_name {
            Some(hostname) => self.sni.for_each_match(hostname, &mut consider),
            None => consider(0, &self.no_sni),
        }

        if let Some((rank, target)) = best {
            // TLS wins an equal-prefix tie, but cannot override a narrower raw route.
            if ip_targets
                .raw
                .as_ref()
                .is_none_or(|raw| rank.ip_prefix_len >= raw.prefix_len)
            {
                return Some(SelectedTarget::Tls(target, rank.alpn));
            }
        }
        ip_targets
            .raw
            .as_ref()
            .map(|raw| SelectedTarget::Raw(raw.target.clone()))
    }
}
