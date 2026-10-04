use std::collections::BTreeSet;

use serde_json::{Map, Value};

fn one_or_many(value: &Value) -> &[Value] {
    value
        .as_array()
        .map_or_else(|| std::slice::from_ref(value), Vec::as_slice)
}

pub(super) fn deprecated_keys(
    config: &Map<String, Value>,
) -> BTreeSet<(&'static str, &'static str)> {
    let mut keys = BTreeSet::new();
    if config.contains_key("bindAddress") {
        keys.insert(("bindAddress", "address"));
    }
    let Some(targets) = config.get("targets").or_else(|| config.get("target")) else {
        return keys;
    };
    for target in one_or_many(targets) {
        if target.get("serverTls").is_some() {
            keys.insert(("serverTls", "server_tls"));
        }
        if target.get("addresses").is_some()
            || target["default_http_action"].get("addresses").is_some()
        {
            keys.insert(("addresses", "locations"));
        }
        if let Some(paths) = target["http_paths"].as_object() {
            for entries in paths.values() {
                for entry in one_or_many(entries) {
                    if entry["http_action"].get("addresses").is_some() {
                        keys.insert(("addresses", "locations"));
                    }
                }
            }
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_only_config_fields_not_comments_values_or_header_names() {
        let config: Map<String, Value> = serde_yaml::from_str(
            r#"
# bindAddress, serverTls, addresses
address: 127.0.0.1:8080
target:
  allowlist: all
  default_http_action:
    type: serve-message
    status_code: 200
    content: serverTls bindAddress addresses
    response_headers:
      addresses: serverTls
  http_paths:
    /addresses:
      required_request_headers:
        serverTls: any
      http_action: close
"#,
        )
        .unwrap();
        assert!(deprecated_keys(&config).is_empty());
    }

    #[test]
    fn finds_aliases_in_single_and_multiple_targets_and_routes() {
        for config in [
            serde_json::json!({"bindAddress":"127.0.0.1:8080", "target":{"serverTls":{}, "addresses":"backend:80"}}),
            serde_json::json!({"bindAddress":"127.0.0.1:8080", "targets":[{"serverTls":{}, "default_http_action":{"addresses":"backend:80"}}]}),
            serde_json::json!({"bindAddress":"127.0.0.1:8080", "target":{"serverTls":{}, "http_paths":{"/":{"http_action":{"addresses":"backend:80"}}, "/a":[{"http_action":{"addresses":"backend:80"}}]}}}),
        ] {
            assert_eq!(
                deprecated_keys(config.as_object().unwrap()),
                BTreeSet::from([
                    ("bindAddress", "address"),
                    ("serverTls", "server_tls"),
                    ("addresses", "locations")
                ])
            );
        }
    }
}
