use std::collections::HashMap;

use super::string_util::update_base_path;
use crate::config::HttpHeaderPatch;

#[derive(Default)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn append(&mut self, name: String, value: String) {
        self.0.push((name.to_ascii_lowercase(), value));
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        // Routing previously used the last occurrence of a repeated field.
        self.0
            .iter()
            .rev()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    pub fn insert(&mut self, name: String, value: String) {
        self.remove_header(&name);
        self.append(name, value);
    }
}

pub trait HeaderMap {
    fn fields(&self) -> impl Iterator<Item = (&str, &str)>;
    fn remove_header(&mut self, name: &str);
    fn set_header(&mut self, name: String, value: String);

    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.fields()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    fn contains_token(&self, name: &str, token: &str) -> bool {
        self.header_values(name).any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    }

    fn chunked(&self) -> bool {
        self.contains_token("transfer-encoding", "chunked")
    }

    fn content_length(&self) -> std::io::Result<Option<usize>> {
        let mut length = None;
        for value in self
            .header_values("content-length")
            .flat_map(|value| value.split(','))
        {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(std::io::Error::other("Invalid content length"));
            }
            let parsed = value.parse::<usize>().map_err(std::io::Error::other)?;
            if length.is_some_and(|previous| previous != parsed) {
                return Err(std::io::Error::other("Conflicting content lengths"));
            }
            length = Some(parsed);
        }
        Ok(length)
    }

    fn connection_close(&self) -> bool {
        self.contains_token("connection", "close")
    }

    fn expect_100(&self) -> std::io::Result<bool> {
        let mut expect = false;
        for value in self.header_values("expect") {
            if !value.eq_ignore_ascii_case("100-continue") {
                return Err(std::io::Error::other(format!(
                    "Invalid expect value: {value}"
                )));
            }
            expect = true;
        }
        Ok(expect)
    }

    fn websocket_upgrade(&self) -> bool {
        self.contains_token("connection", "upgrade")
    }

    fn append_headers_to_string(&self, s: &mut String) {
        for (key, value) in self.fields() {
            s.push_str(key);
            s.push_str(": ");
            s.push_str(value);
            s.push_str("\r\n");
        }
    }

    fn update_path_headers(&mut self, base_path: &str, target_base_path: &Option<String>) {
        if let Some(prefix) = target_base_path {
            let location = self.header_values("location").last().map(str::to_owned);
            if let Some(location) = location.filter(|location| location.starts_with(prefix)) {
                self.set_header(
                    "location".into(),
                    update_base_path(&location, prefix, base_path),
                );
            }
        }
    }

    fn patch_headers(&mut self, header_patch: Option<&HttpHeaderPatch>) {
        if let Some(patch) = header_patch {
            for key in &patch.remove_headers {
                self.remove_header(key);
            }
            for (key, value) in &patch.overwrite_headers {
                self.set_header(key.to_ascii_lowercase(), value.clone());
            }
            for (key, value) in &patch.default_headers {
                if self.header_values(key).next().is_none() {
                    self.set_header(key.to_ascii_lowercase(), value.clone());
                }
            }
        }
    }
}

impl HeaderMap for Headers {
    fn fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    fn remove_header(&mut self, name: &str) {
        self.0.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    }

    fn set_header(&mut self, name: String, value: String) {
        self.insert(name, value);
    }
}

impl HeaderMap for HashMap<String, String> {
    fn fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    fn remove_header(&mut self, name: &str) {
        self.retain(|key, _| !key.eq_ignore_ascii_case(name));
    }

    fn set_header(&mut self, name: String, value: String) {
        self.remove_header(&name);
        self.insert(name.to_ascii_lowercase(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpPathAction;
    use crate::tcp::TargetHttpActionData;

    #[test]
    fn repeated_fields_keep_order_and_patches_replace_case_insensitively() {
        let mut headers = Headers::default();
        headers.append("Set-Cookie".into(), "a=1".into());
        headers.append("set-cookie".into(), "a=2".into());
        assert_eq!(
            headers.header_values("SET-COOKIE").collect::<Vec<_>>(),
            ["a=1", "a=2"]
        );
        headers.set_header("SET-COOKIE".into(), "b=3".into());
        assert_eq!(
            headers.header_values("set-cookie").collect::<Vec<_>>(),
            ["b=3"]
        );
        headers.remove_header("Set-Cookie");
        assert!(headers.header_values("set-cookie").next().is_none());
    }

    #[test]
    fn lengths_and_connection_tokens_are_unambiguous() {
        let mut headers = Headers::default();
        headers.append("content-length".into(), "12, 12".into());
        headers.append("Content-Length".into(), "12".into());
        assert_eq!(headers.content_length().unwrap(), Some(12));
        headers.append("content-length".into(), "13".into());
        assert!(headers.content_length().is_err());
        headers.set_header("content-length".into(), "+12".into());
        assert!(headers.content_length().is_err());
        headers.append("connection".into(), "keep-alive, Upgrade, CLOSE".into());
        assert!(headers.connection_close());
        assert!(headers.websocket_upgrade());
        headers.append("transfer-encoding".into(), "Chunked".into());
        assert!(headers.chunked());
    }

    #[test]
    fn forward_header_patches_survive_config_conversion() {
        let config: HttpPathAction = serde_yaml::from_str(
            "type: forward
location: 127.0.0.1:9001
request_header_patch:
  remove_headers: [x-remove]
  overwrite_headers: {x-existing: overwritten}
  default_headers: {x-existing: ignored, x-default: added}
response_header_patch:
  overwrite_headers: {x-response: replaced}
",
        )
        .unwrap();
        let TargetHttpActionData::Forward {
            request_header_patch,
            response_header_patch,
            ..
        } = config.into()
        else {
            panic!("expected forwarding action");
        };
        let mut request = HashMap::from([
            ("x-remove".to_owned(), "removed".to_owned()),
            ("x-existing".to_owned(), "original".to_owned()),
        ]);
        request.patch_headers(request_header_patch.as_deref());
        assert_eq!(
            request,
            HashMap::from([
                ("x-existing".to_owned(), "overwritten".to_owned()),
                ("x-default".to_owned(), "added".to_owned()),
            ])
        );
        let mut response = HashMap::new();
        response.patch_headers(response_header_patch.as_deref());
        assert_eq!(response["x-response"], "replaced");
    }

    #[test]
    fn absent_forward_header_patches_leave_headers_unchanged() {
        for extra in [
            "",
            "request_header_patch: null\nresponse_header_patch: null\n",
        ] {
            let config: HttpPathAction =
                serde_yaml::from_str(&format!("type: forward\nlocation: 127.0.0.1:9001\n{extra}"))
                    .unwrap();
            let TargetHttpActionData::Forward {
                request_header_patch,
                response_header_patch,
                ..
            } = config.into()
            else {
                panic!("expected forwarding action");
            };
            assert!(request_header_patch.is_none());
            assert!(response_header_patch.is_none());
            let original = HashMap::from([("x-existing".to_owned(), "original".to_owned())]);
            let mut headers = original.clone();
            headers.patch_headers(request_header_patch.as_deref());
            headers.patch_headers(response_header_patch.as_deref());
            assert_eq!(headers, original);
        }
    }
}
