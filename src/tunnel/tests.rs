use super::*;

struct IdentityFiles(std::path::PathBuf);

impl IdentityFiles {
    fn new() -> Self {
        let parent = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join("tmp");
        std::fs::create_dir_all(&parent).unwrap();
        let directory = parent.join(format!("tobaru-tunnel-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&directory).unwrap();
        let files = Self(directory);
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(files.0.join("cert.pem"), identity.cert.pem()).unwrap();
        std::fs::write(
            files.0.join("key.pem"),
            identity.signing_key.serialize_pem(),
        )
        .unwrap();
        files
    }
}

impl Drop for IdentityFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn preparation_reuses_accounting_after_removal_and_lower_limits() {
    let files = IdentityFiles::new();
    let mut config = RuntimeConfig {
        tunnel_servers: vec![serde_json::from_value(serde_json::json!({
            "tunnel_server": "edge", "address": "0.0.0.0:7000",
            "server_tls": {"cert": files.0.join("cert.pem"), "key": files.0.join("key.pem")},
            "max_connections": 2, "max_handshakes": 1,
            "peers": {
                "home": {"client_fingerprints": ["aa".repeat(32)], "services": ["web"],
                    "max_active_connections": 2, "max_pending_opens": 2},
                "other": {"client_fingerprints": ["bb".repeat(32)], "services": ["web"],
                    "max_active_connections": 2, "max_pending_opens": 2}
            }
        }))
        .unwrap()],
        ..RuntimeConfig::default()
    };
    let key = ("edge".into(), "home".into());
    let other_key = ("edge".into(), "other".into());
    let mut store = Store::default();
    let old = store.prepare(&config).unwrap();
    let old_gate = old.gate.clone();
    let peer = &old.registry.0[&key];
    assert!(Arc::ptr_eq(
        &peer.endpoint,
        &old.registry.0[&other_key].endpoint
    ));
    let held: Vec<_> = [
        &peer.active,
        &peer.pending,
        &peer.physical,
        &peer.endpoint.accepted,
        &peer.endpoint.credits,
    ]
    .into_iter()
    .map(|counter| [counter.acquire(2).unwrap(), counter.acquire(2).unwrap()])
    .collect();
    drop(old);
    drop(store.prepare(&RuntimeConfig::default()).unwrap());
    config.tunnel_servers[0].max_connections = 1;
    for peer in config.tunnel_servers[0].peers.values_mut() {
        peer.max_active_connections = 1;
        peer.max_pending_opens = 1;
    }
    let new = store.prepare(&config).unwrap();
    assert!(!Arc::ptr_eq(&old_gate, &new.gate));
    let peer = &new.registry.0[&key];
    let other = &new.registry.0[&other_key];
    assert!(Arc::ptr_eq(&peer.endpoint, &other.endpoint));
    assert_eq!(other.active.count(), 0);
    assert_eq!(other.pending.count(), 0);
    assert_eq!(other.physical.count(), 0);
    assert!(peer.endpoint.accept().is_err());
    for ((counter, limit), [first, second]) in [
        (&peer.active, peer.config.max_active_connections),
        (&peer.pending, peer.config.max_pending_opens),
        (&peer.physical, peer.config.max_active_connections),
        (&peer.endpoint.accepted, peer.endpoint.limit),
        (&peer.endpoint.credits, peer.endpoint.limit),
    ]
    .into_iter()
    .zip(held)
    {
        assert_eq!(counter.count(), 2);
        assert!(
            matches!(counter.acquire(limit), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        drop(first);
        assert!(counter.acquire(limit).is_err());
        drop(second);
        drop(counter.acquire(limit).unwrap());
        assert_eq!(counter.count(), 0);
    }
    drop(peer.endpoint.accept().unwrap());
}

#[test]
fn binding_requires_the_configured_server_peer_and_service() {
    let (mut peer, _, _) = test_support::harness(1);
    Arc::get_mut(&mut peer).unwrap().config.open_timeout_secs = 7;
    let registry = Registry(HashMap::from([(
        ("edge".into(), "home".into()),
        peer.clone(),
    )]));
    let reference = TunnelReference {
        server: "edge".into(),
        peer: "home".into(),
        service: "web".into(),
    };
    let binding = registry.bind(&reference).unwrap();
    assert!(Arc::ptr_eq(&binding.peer, &peer));
    assert_eq!(binding.service, "web");
    assert_eq!(binding.setup_timeout(), Duration::from_secs(7));
    for invalid in [
        TunnelReference {
            server: "missing".into(),
            ..reference.clone()
        },
        TunnelReference {
            peer: "missing".into(),
            ..reference.clone()
        },
        TunnelReference {
            service: "missing".into(),
            ..reference
        },
    ] {
        assert!(
            matches!(registry.bind(&invalid), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }
}
