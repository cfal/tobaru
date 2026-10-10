use super::{
    AlpnValue, HttpHeaderPatch, HttpPathAction, HttpProtocols, NoneOrSome, ServerTlsConfig,
};

impl HttpProtocols {
    pub fn resolve(protocols: Self, tls: Option<&mut ServerTlsConfig>) -> std::io::Result<Self> {
        let Some(tls) = tls else {
            return Ok(protocols);
        };
        if matches!(tls.alpn_protocols, NoneOrSome::Unspecified) {
            let mut alpn = Vec::new();
            if protocols.http2 {
                alpn.push(AlpnValue::Specified("h2".into()));
            }
            if protocols.http1 {
                alpn.push(AlpnValue::Specified("http/1.1".into()));
                alpn.push(AlpnValue::None);
            }
            tls.alpn_protocols = NoneOrSome::Some(alpn);
        }
        if tls.alpn_protocols.is_empty() && !protocols.http1 {
            return Err(std::io::Error::other("HTTP/2-only TLS requires ALPN h2"));
        }
        for value in tls.alpn_protocols.iter() {
            let enabled = match value {
                AlpnValue::Specified(name) if name == "h2" => protocols.http2,
                // Custom ALPN and wildcard/no-ALPN fallbacks retain H1 semantics.
                _ => protocols.http1,
            };
            if !enabled {
                return Err(std::io::Error::other(
                    "server_tls.alpn_protocols permits a protocol disabled by http_protocols",
                ));
            }
        }
        Ok(protocols)
    }
}

fn header_name(name: &str) -> Result<(), String> {
    if !crate::http::syntax::is_token(name.as_bytes()) {
        return Err(format!("Invalid HTTP header name: {name:?}"));
    }
    Ok(())
}

fn header_value(value: &str) -> Result<(), String> {
    if !crate::http::syntax::is_field_value(value.as_bytes()) {
        return Err("HTTP metadata must not contain control characters".into());
    }
    Ok(())
}

fn headers(fields: &std::collections::HashMap<String, String>) -> Result<(), String> {
    for (name, value) in fields {
        header_name(name)?;
        header_value(value)?;
    }
    Ok(())
}

fn non_framing_header(name: &str) -> Result<(), String> {
    header_name(name)?;
    if [
        "content-length",
        "transfer-encoding",
        "connection",
        "trailer",
        "upgrade",
    ]
    .iter()
    .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        return Err(format!("HTTP header is managed by the server: {name}"));
    }
    Ok(())
}

fn local_response_headers(
    fields: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    headers(fields)?;
    for name in fields.keys() {
        non_framing_header(name)?;
    }
    Ok(())
}

impl HttpHeaderPatch {
    fn validate(&self) -> Result<(), String> {
        headers(&self.default_headers)?;
        headers(&self.overwrite_headers)?;
        for name in &self.remove_headers {
            header_name(name)?;
        }
        Ok(())
    }
}

impl HttpPathAction {
    pub(super) fn validate(&self) -> Result<(), String> {
        let id_names = match self {
            Self::CloseConnection => return Ok(()),
            Self::ServeMessage(config) => {
                if !(200..600).contains(&config.status_code) {
                    return Err(
                        "serve-message requires a final HTTP status code between 200 and 599"
                            .into(),
                    );
                }
                if let Some(message) = &config.status_message {
                    header_value(message)?;
                }
                local_response_headers(&config.response_headers)?;
                [None, config.response_id_header_name.as_deref()]
            }
            Self::ServeDirectory(config) => {
                local_response_headers(&config.response_headers)?;
                [None, config.response_id_header_name.as_deref()]
            }
            Self::Forward(config) => {
                if let Some(path) = &config.replacement_path {
                    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
                        return Err("HTTP replacement_path must not contain whitespace or control characters".into());
                    }
                }
                for patch in [&config.request_header_patch, &config.response_header_patch]
                    .into_iter()
                    .flatten()
                {
                    patch.validate()?;
                }
                [
                    config.request_id_header_name.as_deref(),
                    config.response_id_header_name.as_deref(),
                ]
            }
        };
        for name in id_names.into_iter().flatten() {
            non_framing_header(name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn http2_policy_is_explicit_and_bounded() {
        use super::super::{Http2Config, HttpProtocol, HttpTcpActionConfig};
        let config: HttpTcpActionConfig =
            serde_json::from_value(json!({"default_http_action":"close"})).unwrap();
        assert_eq!(
            config.http_protocols,
            HttpProtocols {
                http1: true,
                http2: true
            }
        );
        assert_eq!(config.http2.max_concurrent_streams.get(), 64);
        let HttpPathAction::Forward(config) =
            serde_json::from_value(json!({"type":"forward", "location":"localhost:80"})).unwrap()
        else {
            panic!()
        };
        assert_eq!(config.upstream_protocol, HttpProtocol::Http1);
        for value in [
            json!({"prior_knowledge":true}),
            json!({"max_concurrent_streams":0}),
            json!({"header_timeout_secs":0}),
            json!({"typo":1}),
        ] {
            assert!(serde_json::from_value::<Http2Config>(value).is_err());
        }
        for value in [
            json!({"max_concurrent_streams":4097}),
            json!({"max_header_list_size":1048577}),
            json!({"drain_timeout_secs":86401}),
        ] {
            assert!(serde_json::from_value::<Http2Config>(value)
                .unwrap()
                .validate()
                .is_err());
        }
        assert!(serde_json::from_value::<HttpPathAction>(
            json!({"type":"forward", "location":"localhost:80", "upstream_protocol":"http3"})
        )
        .is_err());
    }

    #[test]
    fn http_protocol_allowlist_is_nonempty_and_unambiguous() {
        for value in [
            json!([]),
            json!(["http1", "http1"]),
            json!(["http3"]),
            json!(null),
            json!("http2"),
        ] {
            assert!(serde_json::from_value::<HttpProtocols>(value).is_err());
        }
        for (value, http1, http2) in [
            (json!(["http1"]), true, false),
            (json!(["http2"]), false, true),
            (json!(["http1", "http2"]), true, true),
            (json!(["http2", "http1"]), true, true),
        ] {
            let protocols: HttpProtocols = serde_json::from_value(value).unwrap();
            assert_eq!(protocols, HttpProtocols { http1, http2 });
            assert_eq!(HttpProtocols::resolve(protocols, None).unwrap(), protocols);
        }
    }

    #[test]
    fn http_tls_derives_alpn_only_when_unspecified() {
        for (http1, http2, expected) in [
            (true, true, vec!["h2", "http/1.1", "none"]),
            (true, false, vec!["http/1.1", "none"]),
            (false, true, vec!["h2"]),
        ] {
            let protocols = HttpProtocols { http1, http2 };
            let mut tls: ServerTlsConfig = serde_json::from_value(json!({})).unwrap();
            assert_eq!(
                HttpProtocols::resolve(protocols, Some(&mut tls)).unwrap(),
                protocols
            );
            let names: Vec<_> = tls
                .alpn_protocols
                .iter()
                .map(|value| match value {
                    AlpnValue::Specified(name) => name.as_str(),
                    AlpnValue::None => "none",
                    AlpnValue::Any => "any",
                })
                .collect();
            assert_eq!(names, expected);
        }
        for alpn in [
            json!([]),
            json!(null),
            json!(["legacy-http", "none"]),
            json!(["any", "none"]),
            json!(["http/1.1"]),
        ] {
            let mut tls: ServerTlsConfig =
                serde_json::from_value(json!({"alpn_protocols":alpn})).unwrap();
            let before = tls.alpn_protocols.clone().into_vec();
            HttpProtocols::resolve(HttpProtocols::default(), Some(&mut tls)).unwrap();
            assert_eq!(tls.alpn_protocols.into_vec(), before);
        }
    }

    #[test]
    fn http_tls_rejects_alpn_for_disabled_protocols() {
        for (protocols, alpn) in [
            (json!(["http1"]), json!(["h2"])),
            (json!(["http2"]), json!(["h2", "http/1.1"])),
            (json!(["http2"]), json!(["h2", "none"])),
            (json!(["http2"]), json!(["h2", "any"])),
            (json!(["http2"]), json!(["legacy-http"])),
            (json!(["http2"]), json!([])),
            (json!(["http2"]), json!(null)),
        ] {
            let protocols = serde_json::from_value(protocols).unwrap();
            let mut tls = serde_json::from_value(json!({"alpn_protocols":alpn})).unwrap();
            assert!(HttpProtocols::resolve(protocols, Some(&mut tls)).is_err());
        }
    }

    #[test]
    fn local_responses_and_ids_cannot_override_wire_framing() {
        for name in [
            "Content-Length",
            "TRANSFER-Encoding",
            "Connection",
            "Trailer",
            "Upgrade",
        ] {
            for mut action in [
                json!({"type":"serve-message", "status_code":200}),
                json!({"type":"serve-directory", "path":"."}),
            ] {
                action["response_headers"] = json!({name:"value"});
                assert!(serde_json::from_value::<HttpPathAction>(action).is_err());
            }
            for mut action in [
                json!({"type":"serve-message", "status_code":200}),
                json!({"type":"serve-directory", "path":"."}),
                json!({"type":"forward", "location":"localhost:80"}),
            ] {
                action["response_id_header_name"] = json!(name);
                assert!(serde_json::from_value::<HttpPathAction>(action).is_err());
            }
            assert!(serde_json::from_value::<HttpPathAction>(json!({
                "type":"forward", "location":"localhost:80", "request_id_header_name":name
            }))
            .is_err());
        }
        for status in [100, 101, 103, 199] {
            assert!(serde_json::from_value::<HttpPathAction>(json!({
                "type":"serve-message", "status_code":status
            }))
            .is_err());
        }
    }

    #[test]
    fn passthrough_rejects_http_actions_before_accepting_connections() {
        let tls: super::super::ServerTlsConfig =
            serde_json::from_value(json!({"mode":"passthrough"})).unwrap();
        for value in [
            json!({"protocol":"http", "default_http_action":"close"}),
            json!({"protocol":"http", "default_http_action":{"type":"forward", "location":"localhost:80"}}),
        ] {
            let action = serde_json::from_value(value).unwrap();
            assert!(tls.validate_with_action(&action).is_err());
        }
        let action = serde_json::from_value(json!({"location":"localhost:443"})).unwrap();
        assert!(tls.validate_with_action(&action).is_ok());
    }

    #[test]
    fn http_route_keys_are_paths_not_request_targets() {
        for path in ["", "api", "/api?x=1", "/api#x", "/a b", "/a\r\n"] {
            let config = json!({"default_http_action":"close", "http_paths":{
                path:{"http_action":"close"}
            }});
            assert!(
                serde_json::from_value::<super::super::HttpTcpActionConfig>(config).is_err(),
                "{path:?}"
            );
        }
        for path in ["/", "/api", "/api/", "/a%20b"] {
            let config = json!({"default_http_action":"close", "http_paths":{
                path:{"http_action":"close"}
            }});
            assert!(
                serde_json::from_value::<super::super::HttpTcpActionConfig>(config).is_ok(),
                "{path:?}"
            );
        }
    }

    #[test]
    fn configured_http_metadata_cannot_inject_wire_lines() {
        for value in [
            json!({"type":"serve-message", "status_code":200, "status_message":"OK\r\nx-injected: yes"}),
            json!({"type":"serve-message", "status_code":999}),
            json!({"type":"serve-message", "status_code":200, "response_headers":{"bad name":"yes"}}),
            json!({"type":"serve-directory", "path":".", "response_headers":{"x-test":"yes\nno"}}),
            json!({"type":"serve-directory", "path":".", "response_id_header_name":"x-id\r\nx-other"}),
            json!({"type":"forward", "location":"localhost:80", "request_header_patch":{"overwrite_headers":{"host":"a\r\nX: b"}}}),
            json!({"type":"forward", "location":"localhost:80", "response_header_patch":{"remove_headers":["bad:name"]}}),
            json!({"type":"forward", "location":"localhost:80", "replacement_path":"/a HTTP/1.1\r\nX: b"}),
            json!({"type":"forward", "location":"localhost:80", "request_id_header_name":""}),
        ] {
            assert!(
                serde_json::from_value::<HttpPathAction>(value.clone()).is_err(),
                "{value}"
            );
        }
        assert!(serde_json::from_value::<HttpPathAction>(json!({
            "type":"serve-message", "status_code":200, "content":"body\r\nlines",
            "response_headers":{"X-Test":"one\ttwo"}
        }))
        .is_ok());
    }

    #[test]
    fn non_string_protocol_is_a_config_error() {
        assert!(serde_json::from_value::<super::super::TcpAction>(json!({"protocol":3})).is_err());
    }

    #[test]
    fn malformed_network_locations_do_not_fall_back_to_unix_paths() {
        for value in ["backend:abc", "backend:99999", "[::1]:invalid"] {
            assert!(
                serde_json::from_value::<super::super::TcpTargetLocation>(json!(value)).is_err()
            );
        }
        for value in [
            json!("/tmp/backend:socket"),
            json!("backend.sock"),
            json!({"path":"backend:socket"}),
        ] {
            assert!(serde_json::from_value::<super::super::TcpTargetLocation>(value).is_ok());
        }
    }

    #[test]
    fn http_timeouts_are_opt_in_and_positive() {
        let config = |timeouts| {
            serde_json::from_value::<super::super::HttpTcpActionConfig>(json!({
                "default_http_action":"close", "http_timeouts": timeouts,
            }))
        };
        for value in [
            json!({}),
            json!({"request_header_timeout_secs":null}),
            json!({"local_body_timeout_secs":null}),
            json!({"local_body_timeout_secs":60}),
            json!({"request_header_timeout_secs":15, "response_header_timeout_secs":30, "keepalive_idle_timeout_secs":60}),
        ] {
            assert!(config(value).is_ok());
        }
        for value in [
            json!({"request_header_timeout_secs":0}),
            json!({"local_body_timeout_secs":0}),
            json!({"response_header_timeout_secs":-1}),
            json!({"keepalive_idle_timeout_secs":1.5}),
            json!({"typo":1}),
        ] {
            assert!(config(value).is_err());
        }
        let config: super::super::HttpTcpActionConfig =
            serde_json::from_value(json!({"default_http_action":"close"})).unwrap();
        assert!(config.http_timeouts.request_header_timeout_secs.is_none());
        assert!(config.http_timeouts.local_body_timeout_secs.is_none());
    }

    #[test]
    fn handshake_timeout_is_positive_and_only_applies_to_termination() {
        use super::super::ServerTlsConfig;
        assert!(
            serde_json::from_value::<ServerTlsConfig>(json!({"handshake_timeout_secs":0})).is_err()
        );
        let config: ServerTlsConfig =
            serde_json::from_value(json!({"mode":"passthrough", "handshake_timeout_secs":1}))
                .unwrap();
        assert!(config.validate().is_err());
        let config: ServerTlsConfig = serde_json::from_value(
            json!({"cert":"cert.pem", "key":"key.pem", "handshake_timeout_secs":1}),
        )
        .unwrap();
        assert!(config.validate().is_ok());
        let config: ServerTlsConfig =
            serde_json::from_value(json!({"mode":"passthrough"})).unwrap();
        assert!(config.handshake_timeout_secs.is_none());
    }
    #[test]
    fn udp_association_cap_is_optional_and_positive() {
        use super::super::TargetConfigs;
        let base = json!({"transport":"udp", "target":{"allowlist":"127.0.0.1", "location":"127.0.0.1:53"}});
        let config: TargetConfigs = serde_json::from_value(base.clone()).unwrap();
        assert!(matches!(
            config,
            TargetConfigs::Udp {
                udp_max_associations: None,
                ..
            }
        ));
        for value in [json!(null), json!(1), json!(4096)] {
            let mut config = base.clone();
            config["udp_max_associations"] = value;
            assert!(serde_json::from_value::<TargetConfigs>(config).is_ok());
        }
        for value in [json!(0), json!(-1), json!(1.5)] {
            let mut config = base.clone();
            config["udp_max_associations"] = value;
            assert!(serde_json::from_value::<TargetConfigs>(config).is_err());
        }
    }
}
