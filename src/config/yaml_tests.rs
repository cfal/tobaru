use super::*;
use serde_json::{json, Value};

#[test]
fn yaml_scalar_types_and_json_value_conversion_remain_compatible() {
    let actual: Value = serde_yaml::from_str(
        "truth: true\nfalsehood: false\nnull_value: null\nempty:\ninteger: 42\nfloat: 1.5\nleading_zero: 012\nyes_string: yes\ndate_string: 2026-10-10\nquoted: '42'\n",
    ).unwrap();
    assert_eq!(
        actual,
        json!({
            "truth": true, "falsehood": false, "null_value": null, "empty": null,
            "integer": 42, "float": 1.5, "leading_zero": "012", "yes_string": "yes",
            "date_string": "2026-10-10", "quoted": "42"
        })
    );
    assert_eq!(
        serde_yaml::from_str::<Value>(&serde_yaml::to_string(&actual).unwrap()).unwrap(),
        actual
    );
}

#[test]
fn yaml_aliases_custom_actions_and_nulls_match_json_configuration() {
    let yaml = r#"
- address: &bind 127.0.0.1:9000
  transport: tcp
  target: &target
    allowlist: [127.0.0.1/32, clients]
    tcp_keepalive: null
    http_timeouts:
      request_header_timeout_secs: null
      response_header_timeout_secs: 17
    http_paths:
      /api:
        required_request_headers:
          host: example.test
        http_action:
          type: forward
          location: 127.0.0.1:9001
    default_http_action:
      type: serve-message
      status_code: 200
      content: |
        first line
        second line
- bindAddress: *bind
  target: *target
"#;
    let expected_target = json!({
        "allowlist": ["127.0.0.1/32", "clients"], "tcp_keepalive": null,
        "http_timeouts": {"request_header_timeout_secs": null, "response_header_timeout_secs": 17},
        "http_paths": {"/api": {"required_request_headers": {"host": "example.test"}, "http_action": {"type":"forward", "location":"127.0.0.1:9001"}}},
        "default_http_action": {"type":"serve-message", "status_code":200, "content":"first line\nsecond line\n"}
    });
    let expected = json!([
        {"address":"127.0.0.1:9000", "transport":"tcp", "target":expected_target},
        {"bindAddress":"127.0.0.1:9000", "target":expected_target},
    ]);
    let yaml_configs = deserialize_configs(yaml.into(), "config.yaml").unwrap();
    let json_configs = deserialize_configs(expected.to_string(), "config.json").unwrap();
    assert_eq!(format!("{yaml_configs:?}"), format!("{json_configs:?}"));
}

#[test]
fn yaml_merge_keys_are_not_implicitly_expanded() {
    let value: Value =
        serde_yaml::from_str("defaults: &base {a: 1}\nchild: {<<: *base, b: 2}\n").unwrap();
    assert_eq!(
        value,
        json!({"defaults":{"a":1}, "child":{"<<":{"a":1}, "b":2}})
    );
    assert!(deserialize_configs(
        "- group: clients\n  ip_masks: &masks [127.0.0.1]\n- <<: {address: '127.0.0.1:9000'}\n  target: {allowlist: *masks, location: '127.0.0.1:9001'}\n".into(),
        "config.yaml",
    ).is_err());
}

#[test]
fn yaml_errors_retain_locations_and_duplicate_key_behavior() {
    let error = serde_yaml::from_str::<serde_yaml::Value>("key: 1\nkey: 2\n").unwrap_err();
    assert!(error.to_string().contains("duplicate"));
    assert!(error.location().is_some());
    // Config maps deserialize through serde_json::Map, whose visitor keeps the last value.
    let value: Value = serde_yaml::from_str("key: 1\nkey: 2\n").unwrap();
    assert_eq!(value, json!({"key":2}));
    for input in ["key: [\n", "key: *missing\n", "---\na: 1\n---\na: 2\n"] {
        assert!(serde_yaml::from_str::<Value>(input).is_err());
    }
}
