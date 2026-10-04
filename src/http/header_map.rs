use std::collections::HashMap;

use super::string_util::update_base_path;
use crate::config::HttpHeaderPatch;

pub trait HeaderMap {
    fn chunked(&self) -> bool;
    fn content_length(&self) -> std::io::Result<Option<usize>>;
    fn connection_close(&self) -> bool;
    fn expect_100(&self) -> std::io::Result<bool>;
    fn websocket_upgrade(&self) -> bool;
    fn append_headers_to_string(&self, s: &mut String);
    fn patch_headers(&mut self, header_patch: Option<&HttpHeaderPatch>);
    fn update_path_headers(&mut self, base_path: &str, replacement_base_path: &Option<String>);
}

impl HeaderMap for HashMap<String, String> {
    fn chunked(&self) -> bool {
        self.get("transfer-encoding")
            .map(|value| value.split(",").map(str::trim).any(|s| s == "chunked"))
            .unwrap_or(false)
    }

    fn content_length(&self) -> std::io::Result<Option<usize>> {
        match self.get("content-length") {
            Some(value) => match value.parse::<usize>() {
                Ok(len) => Ok(Some(len)),
                Err(e) => Err(std::io::Error::other(format!(
                    "Could not parse content length: {}",
                    e
                ))),
            },
            None => Ok(None),
        }
    }

    fn connection_close(&self) -> bool {
        self.get("connection")
            .map(|value| value.to_lowercase() == "close")
            .unwrap_or(false)
    }

    fn expect_100(&self) -> std::io::Result<bool> {
        match self.get("expect") {
            Some(s) => {
                // 100-continue is the only supported value.
                // ref: https://datatracker.ietf.org/doc/html/rfc7231#section-5.1.1
                if s != "100-continue" {
                    return Err(std::io::Error::other(format!(
                        "Invalid expect value: {}",
                        s
                    )));
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn websocket_upgrade(&self) -> bool {
        self.get("connection")
            .map(|s| s.to_lowercase() == "upgrade")
            .unwrap_or(false)
    }

    fn append_headers_to_string(&self, s: &mut String) {
        for (key, value) in self.iter() {
            s.push_str(key);
            s.push_str(": ");
            s.push_str(value);
            s.push_str("\r\n");
        }
    }

    fn update_path_headers(&mut self, base_path: &str, target_base_path: &Option<String>) {
        // TODO: check Referer header
        if let Some(p) = target_base_path {
            if let Some(location) = self.get("location") {
                // TODO: handle full path
                if location.starts_with(p) {
                    let new_location = update_base_path(location, p, base_path);
                    self.insert("location".to_string(), new_location).unwrap();
                }
            }
        }
    }

    fn patch_headers(&mut self, header_patch: Option<&HttpHeaderPatch>) {
        if let Some(patch) = header_patch {
            for key in patch.remove_headers.iter() {
                let _ = self.remove(key);
            }
            for (key, value) in patch.overwrite_headers.iter() {
                let _ = self.insert(key.to_string(), value.to_string());
            }
            for (key, value) in patch.default_headers.iter() {
                if self.contains_key(key) {
                    continue;
                }
                let _ = self.insert(key.to_string(), value.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpPathAction;
    use crate::tcp::TargetHttpActionData;

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
