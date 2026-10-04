use super::{HttpHeaderPatch, HttpPathAction};

fn header_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err(format!("Invalid HTTP header name: {name:?}"));
    }
    Ok(())
}

fn header_value(value: &str) -> Result<(), String> {
    if value
        .bytes()
        .any(|byte| byte < 0x20 && byte != b'\t' || byte == 0x7f)
    {
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
                if !(100..600).contains(&config.status_code) {
                    return Err("HTTP status code must be between 100 and 599".into());
                }
                if let Some(message) = &config.status_message {
                    header_value(message)?;
                }
                headers(&config.response_headers)?;
                [None, config.response_id_header_name.as_deref()]
            }
            Self::ServeDirectory(config) => {
                headers(&config.response_headers)?;
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
            header_name(name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
