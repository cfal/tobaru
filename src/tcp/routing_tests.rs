use super::*;
use crate::config::{NoneOrSome, SniValue};
use crate::tls_parser::ParsedClientHello;

fn raw_target() -> Arc<TargetData> {
    Arc::new(TargetData {
        tcp_nodelay: true,
        tcp_keepalive: None,
        action_data: TargetActionData::Raw {
            location_data: vec![],
            next_address_index: AtomicUsize::new(0),
        },
    })
}

fn masks(values: &[&str]) -> Vec<IpMask> {
    values
        .iter()
        .map(|value| IpMask::try_from(*value).unwrap())
        .collect()
}

fn tls_target(order: usize, allowlist: &[&str], protocols: &[&str]) -> TlsTargetData {
    let config = serde_json::from_value(serde_json::json!(protocols)).unwrap();
    let (allow_no_alpn, allow_any_alpn, alpn_protocols) = parse_alpn_config(&config);
    let mut ip_lookup_table = IpLookupTable::new();
    for IpMask(address, prefix_len) in masks(allowlist) {
        ip_lookup_table.insert(address, prefix_len, true);
    }
    TlsTargetData {
        config_order: order,
        handshake_timeout_secs: None,
        allow_no_alpn,
        allow_any_alpn,
        alpn_protocols,
        ip_lookup_table,
        tls_mode: TlsMode::Passthrough,
        target_data: raw_target(),
    }
}

fn add_tls(routes: &mut RoutingTable, target: TlsTargetData, names: &[&str]) -> Arc<TargetData> {
    let names: NoneOrSome<SniValue> = serde_json::from_value(serde_json::json!(names)).unwrap();
    let data = target.target_data.clone();
    routes.insert_tls(&names, Arc::new(target));
    data
}

fn peer(address: &str) -> Ipv6Addr {
    match address.parse::<IpAddr>().unwrap() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

fn select(
    routes: &RoutingTable,
    address: &str,
    name: Option<&str>,
    protocols: &[&str],
) -> Option<Arc<TargetData>> {
    let ip = peer(address);
    let parsed = ParsedClientHello {
        server_name: name.map(str::to_owned),
        alpn_protocols: protocols.iter().map(|p| p.as_bytes().to_vec()).collect(),
    };
    routes
        .select(ip, &parsed, &routes.ip_targets(ip))
        .map(|selected| match selected {
            SelectedTarget::Raw(target) => target,
            SelectedTarget::Tls(target, _) => target.target_data.clone(),
        })
}

#[test]
fn unknown_cloudflare_sni_uses_raw_catch_all_without_a_second_clause() {
    for tls_mask in ["0.0.0.0/0", "173.245.48.0/20"] {
        let mut routes = RoutingTable::default();
        let raw = raw_target();
        routes
            .insert_non_tls(&masks(&["0.0.0.0/0"]), raw.clone())
            .unwrap();
        let tls = add_tls(
            &mut routes,
            tls_target(1, &[tls_mask], &[]),
            &["tutte.snailcdn.com"],
        );
        for (name, expected) in [("qa.snailcdn.com", &raw), ("tutte.snailcdn.com", &tls)] {
            let selected = select(&routes, "173.245.48.1", Some(name), &["http/1.1"]).unwrap();
            assert!(Arc::ptr_eq(&selected, expected));
        }
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", Some("qa.snailcdn.com"), &[]).unwrap(),
            &raw,
        ));
    }
}

#[test]
fn ip_specificity_precedes_protocol_and_sni_for_both_address_families() {
    for (address, all, network, host) in [
        ("192.0.2.1", "0.0.0.0/0", "192.0.2.0/24", "192.0.2.1/32"),
        ("2001:db8::1", "::/0", "2001:db8::/32", "2001:db8::1/128"),
    ] {
        let mut routes = RoutingTable::default();
        add_tls(
            &mut routes,
            tls_target(0, &[all], &[]),
            &["api.example.com"],
        );
        let wildcard = add_tls(&mut routes, tls_target(1, &[all, network], &[]), &["any"]);
        assert!(Arc::ptr_eq(
            &select(&routes, address, Some("api.example.com"), &[]).unwrap(),
            &wildcard,
        ));
        let raw = raw_target();
        routes.insert_non_tls(&masks(&[host]), raw.clone()).unwrap();
        assert!(Arc::ptr_eq(
            &select(&routes, address, Some("api.example.com"), &[]).unwrap(),
            &raw,
        ));
        assert!(Arc::ptr_eq(
            &routes.ip_targets(peer(address)).direct_target().unwrap(),
            &raw
        ));
    }
}

#[test]
fn ipv4_catch_all_spellings_have_equal_specificity() {
    for broad in ["all", "::/0", "::/80", "::ffff:0:0/96"] {
        for (raw_mask, tls_mask) in [("0.0.0.0/0", broad), (broad, "0.0.0.0/0")] {
            let mut routes = RoutingTable::default();
            let raw = raw_target();
            routes
                .insert_non_tls(&masks(&[raw_mask]), raw.clone())
                .unwrap();
            let tls = add_tls(
                &mut routes,
                tls_target(0, &[tls_mask], &[]),
                &["api.example.com"],
            );
            assert!(routes
                .ip_targets(peer("192.0.2.1"))
                .direct_target()
                .is_none());
            assert!(Arc::ptr_eq(
                &select(&routes, "192.0.2.1", Some("api.example.com"), &[]).unwrap(),
                &tls,
            ));
            assert!(Arc::ptr_eq(
                &select(&routes, "192.0.2.1", Some("other.example.com"), &[]).unwrap(),
                &raw,
            ));

            let mut routes = RoutingTable::default();
            add_tls(&mut routes, tls_target(0, &[raw_mask], &[]), &["any"]);
            let exact = add_tls(
                &mut routes,
                tls_target(1, &[tls_mask], &[]),
                &["api.example.com"],
            );
            assert!(Arc::ptr_eq(
                &select(&routes, "192.0.2.1", Some("api.example.com"), &[]).unwrap(),
                &exact,
            ));
        }
    }
}

#[test]
fn equivalent_ipv4_non_tls_prefixes_keep_configuration_order() {
    for broad in ["all", "::/0", "::/80", "::ffff:0:0/96"] {
        for (first_mask, second_mask) in [(broad, "0.0.0.0/0"), ("0.0.0.0/0", broad)] {
            for http_first in [false, true] {
                let mut routes = RoutingTable::default();
                let first = if http_first {
                    protocol_tests::target(HttpProtocols::default())
                } else {
                    raw_target()
                };
                let second = raw_target();
                routes
                    .insert_non_tls(&masks(&[first_mask]), first.clone())
                    .unwrap();
                routes
                    .insert_non_tls(&masks(&[second_mask]), second.clone())
                    .unwrap();
                let candidates = routes.ip_targets(peer("192.0.2.1"));
                assert!(Arc::ptr_eq(&candidates.fallback(false).unwrap(), &first));
                assert!(Arc::ptr_eq(
                    &candidates.fallback(true).unwrap(),
                    if http_first { &second } else { &first },
                ));
            }
        }
    }
}

#[test]
fn ipv4_catch_all_normalization_preserves_narrower_and_native_ipv6_routes() {
    let mut routes = RoutingTable::default();
    let broad = raw_target();
    let narrow = raw_target();
    routes
        .insert_non_tls(&masks(&["all"]), broad.clone())
        .unwrap();
    routes
        .insert_non_tls(&masks(&["::/80", "192.0.2.0/24"]), narrow.clone())
        .unwrap();
    for (address, expected) in [
        ("192.0.2.1", &narrow),
        ("198.51.100.1", &broad),
        ("::1", &narrow),
        ("2001:db8::1", &broad),
    ] {
        assert!(Arc::ptr_eq(
            &routes.ip_targets(peer(address)).direct_target().unwrap(),
            expected
        ));
    }
    let mut routes = RoutingTable::default();
    routes
        .insert_non_tls(&masks(&["::/96", "2001:db8::/32"]), raw_target())
        .unwrap();
    assert!(routes.ip_targets(peer("192.0.2.1")).is_empty());
}

#[test]
fn sni_specificity_precedes_alpn_and_configuration_order() {
    let mut routes = RoutingTable::default();
    let any = add_tls(&mut routes, tls_target(0, &["all"], &["h2"]), &["any"]);
    let shallow = add_tls(
        &mut routes,
        tls_target(1, &["all"], &["h2"]),
        &["*.example.com"],
    );
    let deep = add_tls(
        &mut routes,
        tls_target(2, &["all"], &["any"]),
        &["*.api.example.com"],
    );
    let exact = add_tls(
        &mut routes,
        tls_target(3, &["all"], &["any"]),
        &["v1.api.example.com"],
    );
    for (name, expected) in [
        ("other.com", any),
        ("api.example.com", shallow),
        ("v2.api.example.com", deep),
        ("V1.API.EXAMPLE.COM.", exact),
    ] {
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", Some(name), &["h2"]).unwrap(),
            &expected
        ));
    }
}

#[test]
fn rejected_specific_patterns_do_not_hide_eligible_ancestors() {
    let mut routes = RoutingTable::default();
    let raw = raw_target();
    routes
        .insert_non_tls(&masks(&["all"]), raw.clone())
        .unwrap();
    let any = add_tls(&mut routes, tls_target(0, &["all"], &["h2"]), &["any"]);
    let wildcard = add_tls(
        &mut routes,
        tls_target(1, &["all"], &["http/1.1"]),
        &["*.example.com"],
    );
    add_tls(
        &mut routes,
        tls_target(2, &["192.0.2.2"], &[]),
        &["api.example.com"],
    );
    add_tls(
        &mut routes,
        tls_target(3, &["all"], &["private"]),
        &["api.example.com"],
    );
    for (protocols, expected) in [
        (&["http/1.1"][..], wildcard),
        (&["h2"][..], any),
        (&[][..], raw),
    ] {
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", Some("api.example.com"), protocols).unwrap(),
            &expected,
        ));
    }
}

#[test]
fn exact_alpn_precedes_any_and_earlier_config_breaks_ties() {
    let mut routes = RoutingTable::default();
    add_tls(&mut routes, tls_target(0, &["all"], &["any"]), &["any"]);
    let first = add_tls(
        &mut routes,
        tls_target(1, &["all"], &["h2", "any"]),
        &["any"],
    );
    add_tls(&mut routes, tls_target(2, &["all"], &["h2"]), &["any"]);
    assert!(Arc::ptr_eq(
        &select(&routes, "192.0.2.1", Some("example.com"), &["other", "h2"]).unwrap(),
        &first
    ));
}

#[test]
fn absent_sni_and_alpn_are_not_matched_by_any() {
    let mut routes = RoutingTable::default();
    let raw = raw_target();
    routes
        .insert_non_tls(&masks(&["all"]), raw.clone())
        .unwrap();
    let any = add_tls(&mut routes, tls_target(0, &["all"], &["any"]), &["any"]);
    for (name, protocols, expected) in [
        (None, &[][..], &raw),
        (None, &["h2"][..], &raw),
        (Some("example.com"), &[][..], &raw),
        (Some("example.com"), &["h2"][..], &any),
    ] {
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", name, protocols).unwrap(),
            expected
        ));
    }
    let absent = add_tls(&mut routes, tls_target(1, &["all"], &["none"]), &["none"]);
    assert!(Arc::ptr_eq(
        &select(&routes, "192.0.2.1", None, &[]).unwrap(),
        &absent
    ));
    let defaults = add_tls(&mut routes, tls_target(2, &["all"], &[]), &[]);
    assert!(Arc::ptr_eq(
        &select(&routes, "192.0.2.1", Some("example.com"), &[]).unwrap(),
        &defaults
    ));
    assert!(Arc::ptr_eq(
        &select(&routes, "192.0.2.1", None, &["h2"]).unwrap(),
        &defaults
    ));
}

#[test]
fn dot_shorthand_and_multiple_patterns_use_the_best_matching_pattern() {
    let mut routes = RoutingTable::default();
    let dotted = add_tls(&mut routes, tls_target(0, &["all"], &[]), &[".example.com"]);
    let multiple = add_tls(
        &mut routes,
        tls_target(1, &["all"], &[]),
        &["any", "*.api.example.com", "api.example.com"],
    );
    for (name, expected) in [
        ("example.com", &dotted),
        ("other.example.com", &dotted),
        ("api.example.com", &multiple),
        ("v1.api.example.com", &multiple),
    ] {
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", Some(name), &[]).unwrap(),
            expected
        ));
    }
}

#[test]
fn termination_and_passthrough_have_equal_priority() {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = Arc::new(
        create_server_config(
            load_certs(identity.cert.pem().as_bytes()).unwrap(),
            &load_private_key(identity.signing_key.serialize_pem().as_bytes()).unwrap(),
            vec![],
            &[],
            &[],
        )
        .unwrap(),
    );
    for terminate_first in [true, false] {
        let mut routes = RoutingTable::default();
        let mut first = None;
        for order in 0..2 {
            let mut target = tls_target(order, &["all"], &[]);
            if (order == 0) == terminate_first {
                target.tls_mode = TlsMode::Terminate {
                    alpn_tls_config: config.clone(),
                    no_alpn_tls_config: config.clone(),
                };
            }
            let data = add_tls(&mut routes, target, &["any"]);
            if order == 0 {
                first = Some(data);
            }
        }
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", Some("localhost"), &[]).unwrap(),
            first.as_ref().unwrap()
        ));
    }
}

#[test]
fn raw_prefix_ties_keep_the_first_target_but_duplicate_masks_in_one_target_fail() {
    let mut routes = RoutingTable::default();
    let first = raw_target();
    routes
        .insert_non_tls(&masks(&["192.0.2.7/24"]), first.clone())
        .unwrap();
    routes
        .insert_non_tls(&masks(&["192.0.2.0/24"]), raw_target())
        .unwrap();
    assert!(Arc::ptr_eq(
        &routes
            .ip_targets(peer("192.0.2.1"))
            .direct_target()
            .unwrap(),
        &first
    ));
    assert!(routes
        .insert_non_tls(&masks(&["10.0.0.0/8", "10.1.2.3/8"]), raw_target())
        .is_err());
}

#[test]
fn http_targets_cannot_hide_a_raw_fallback_for_tls() {
    for (http_mask, raw_mask) in [("192.0.2.1/32", "0.0.0.0/0"), ("0.0.0.0/0", "0.0.0.0/0")] {
        let mut routes = RoutingTable::default();
        let http = protocol_tests::target(HttpProtocols::default());
        let raw = raw_target();
        routes
            .insert_non_tls(&masks(&[http_mask]), http.clone())
            .unwrap();
        routes
            .insert_non_tls(&masks(&[raw_mask]), raw.clone())
            .unwrap();
        let candidates = routes.ip_targets(peer("192.0.2.1"));
        assert!(candidates.direct_target().is_none());
        assert!(Arc::ptr_eq(&candidates.fallback(false).unwrap(), &http));
        assert!(Arc::ptr_eq(&candidates.fallback(true).unwrap(), &raw));
        assert!(Arc::ptr_eq(
            &select(&routes, "192.0.2.1", Some("example.com"), &[]).unwrap(),
            &raw
        ));
    }
}

#[test]
fn missing_eligible_targets_reject_and_ipv4_catch_all_does_not_admit_ipv6() {
    let mut routes = RoutingTable::default();
    let http = protocol_tests::target(HttpProtocols::default());
    routes
        .insert_non_tls(&masks(&["0.0.0.0/0"]), http.clone())
        .unwrap();
    assert!(Arc::ptr_eq(
        &routes
            .ip_targets(peer("192.0.2.1"))
            .direct_target()
            .unwrap(),
        &http
    ));
    assert!(routes
        .ip_targets(peer("192.0.2.1"))
        .fallback(true)
        .is_none());
    assert!(select(&routes, "192.0.2.1", Some("example.com"), &[]).is_none());
    assert!(routes.ip_targets(peer("2001:db8::1")).is_empty());
}
