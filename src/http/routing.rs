use super::header_map::Headers;
use super::http_parser;
use crate::config::HttpValueMatch;
use crate::hostname_util::{matches_host_header, strip_host_port, validate_host_header};
use crate::tcp::{TargetHttpActionData, TargetHttpPathData};
use radix_trie::{Trie, TrieCommon};
use std::collections::HashMap;

pub(super) fn find_matching_action<'a>(
    path_configs: &'a Trie<String, Vec<TargetHttpPathData>>,
    default_action: &'a TargetHttpActionData,
    request_path: &str,
    request_data: &http_parser::ParsedHttpData,
) -> std::io::Result<(&'a str, &'a TargetHttpActionData)> {
    let mut lookup_path;
    let lookup = if request_path.ends_with('/') {
        request_path
    } else {
        lookup_path = String::with_capacity(request_path.len() + 1);
        lookup_path.push_str(request_path);
        lookup_path.push('/');
        &lookup_path
    };
    let matching_configs = path_configs.get_ancestor(lookup);

    if let Some(t) = matching_configs {
        for path_config in t.value().unwrap().iter() {
            if !has_required_headers(
                request_data.headers(),
                &path_config.required_request_headers,
            )? {
                continue;
            }
            return Ok((t.key().unwrap(), &path_config.http_action));
        }
    }

    Ok(("/", default_action))
}

fn has_required_headers(
    headers: &Headers,
    required: &HashMap<String, HttpValueMatch>,
) -> std::io::Result<bool> {
    for (key, rule) in required.iter() {
        let header_value = headers.get(key).map(String::as_str);
        if !matches_http_value(rule, header_value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Checks whether a header value matches an `HttpValueMatch` rule.
/// For `Hostnames`, validates and strips the port before matching.
pub fn matches_http_value(rule: &HttpValueMatch, value: Option<&str>) -> std::io::Result<bool> {
    match rule {
        HttpValueMatch::Any => Ok(value.is_some()),
        HttpValueMatch::Single(allowed) => Ok(value.is_some_and(|v| v == allowed)),
        HttpValueMatch::Multiple(allowed) => {
            Ok(value.is_some_and(|v| allowed.iter().any(|a| a == v)))
        }
        HttpValueMatch::Hostnames(patterns) => match value {
            Some(v) => {
                let hostname = strip_host_port(v);
                validate_host_header(hostname)?;
                Ok(patterns.iter().any(|p| matches_host_header(hostname, p)))
            }
            None => Ok(false),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::matches_http_value;
    use crate::config::HttpValueMatch;

    #[test]
    fn any_variant() {
        let m = HttpValueMatch::Any;
        assert!(matches_http_value(&m, Some("anything")).unwrap());
        assert!(!matches_http_value(&m, None).unwrap());
    }

    #[test]
    fn single_variant() {
        let m = HttpValueMatch::Single("exact-value".into());
        assert!(matches_http_value(&m, Some("exact-value")).unwrap());
        assert!(!matches_http_value(&m, Some("other")).unwrap());
        assert!(!matches_http_value(&m, None).unwrap());
    }

    #[test]
    fn multiple_variant() {
        let m = HttpValueMatch::Multiple(vec!["a".into(), "b".into()]);
        assert!(matches_http_value(&m, Some("a")).unwrap());
        assert!(matches_http_value(&m, Some("b")).unwrap());
        assert!(!matches_http_value(&m, Some("c")).unwrap());
        assert!(!matches_http_value(&m, None).unwrap());
    }

    #[test]
    fn single_exact_pattern() {
        let m = HttpValueMatch::Hostnames(vec!["example.com".into()]);
        assert!(matches_http_value(&m, Some("example.com")).unwrap());
        assert!(matches_http_value(&m, Some("example.com:8080")).unwrap());
        assert!(!matches_http_value(&m, Some("other.com")).unwrap());
    }

    #[test]
    fn wildcard_pattern() {
        let m = HttpValueMatch::Hostnames(vec!["*.example.com".into()]);
        assert!(matches_http_value(&m, Some("foo.example.com")).unwrap());
        assert!(matches_http_value(&m, Some("foo.example.com:443")).unwrap());
        assert!(!matches_http_value(&m, Some("example.com")).unwrap());
    }

    #[test]
    fn multiple_patterns() {
        let m = HttpValueMatch::Hostnames(vec![
            "api.example.com".into(),
            "*.internal.example.com".into(),
        ]);
        assert!(matches_http_value(&m, Some("api.example.com")).unwrap());
        assert!(matches_http_value(&m, Some("foo.internal.example.com")).unwrap());
        assert!(!matches_http_value(&m, Some("other.example.com")).unwrap());
    }

    #[test]
    fn none_value() {
        let m = HttpValueMatch::Hostnames(vec!["example.com".into()]);
        assert!(!matches_http_value(&m, None).unwrap());
    }

    #[test]
    fn case_insensitive_with_port_stripping() {
        let m = HttpValueMatch::Hostnames(vec!["example.com".into()]);
        assert!(matches_http_value(&m, Some("EXAMPLE.COM")).unwrap());
        assert!(matches_http_value(&m, Some("EXAMPLE.COM:8080")).unwrap());
        assert!(matches_http_value(&m, Some("Example.Com:443")).unwrap());
    }

    #[test]
    fn trailing_dot_rejected() {
        let m = HttpValueMatch::Hostnames(vec!["example.com".into()]);
        assert!(matches_http_value(&m, Some("example.com.")).is_err());
        assert!(matches_http_value(&m, Some("example.com.:8080")).is_err());
    }

    #[test]
    fn wildcard_case_and_trailing_dot_rejected() {
        let m = HttpValueMatch::Hostnames(vec!["*.example.com".into()]);
        assert!(matches_http_value(&m, Some("FOO.EXAMPLE.COM")).unwrap());
        assert!(matches_http_value(&m, Some("foo.example.com.")).is_err());
        assert!(matches_http_value(&m, Some("FOO.EXAMPLE.COM.:443")).is_err());
    }

    #[test]
    fn empty_host_header() {
        let m = HttpValueMatch::Hostnames(vec!["example.com".into()]);
        assert!(matches_http_value(&m, Some("")).is_err());
    }

    #[test]
    fn wildcard_through_deserialization() {
        let m = deser_host("\"*.example.com\"");
        assert!(matches_http_value(&m, Some("foo.example.com")).unwrap());
        assert!(matches_http_value(&m, Some("foo.example.com:8080")).unwrap());
        assert!(!matches_http_value(&m, Some("example.com")).unwrap());
        assert!(!matches_http_value(&m, Some("other.com")).unwrap());
    }

    #[test]
    fn dot_shorthand_through_deserialization() {
        let m = deser_host("\".example.com\"");
        assert!(matches!(m, HttpValueMatch::Hostnames(ref v) if v == &[".example.com"]));
        assert!(matches_http_value(&m, Some("example.com")).unwrap());
        assert!(matches_http_value(&m, Some("foo.example.com")).unwrap());
        assert!(!matches_http_value(&m, Some("other.com")).unwrap());
    }

    #[test]
    fn catch_all_through_deserialization() {
        let m = deser_host("\"*\"");
        assert!(matches!(m, HttpValueMatch::Hostnames(ref v) if v == &["*"]));
        assert!(matches_http_value(&m, Some("anything.example.com")).unwrap());
        assert!(matches_http_value(&m, Some("localhost")).unwrap());
    }

    #[test]
    fn empty_patterns_list() {
        let m = HttpValueMatch::Hostnames(vec![]);
        assert!(!matches_http_value(&m, Some("example.com")).unwrap());
        assert!(!matches_http_value(&m, None).unwrap());
    }

    #[test]
    fn bracketed_ipv6_with_hostname_pattern() {
        let m = HttpValueMatch::Hostnames(vec!["example.com".into()]);
        assert!(!matches_http_value(&m, Some("[::1]")).unwrap());
        assert!(!matches_http_value(&m, Some("[::1]:8080")).unwrap());
    }

    #[test]
    fn ipv4_pattern_with_port_stripping() {
        let m = HttpValueMatch::Hostnames(vec!["192.168.1.1".into()]);
        assert!(matches_http_value(&m, Some("192.168.1.1")).unwrap());
        assert!(matches_http_value(&m, Some("192.168.1.1:8080")).unwrap());
        assert!(!matches_http_value(&m, Some("10.0.0.1")).unwrap());
    }

    /// Deserializes a host header value through the config pipeline.
    fn deser_host(host_yaml: &str) -> HttpValueMatch {
        let yaml = format!(
            "required_request_headers:\n  host: {}\nhttp_action:\n  type: close\n",
            host_yaml
        );
        let c: crate::config::HttpPathConfig = serde_yaml::from_str(&yaml).unwrap();
        c.required_request_headers.get("host").unwrap().clone()
    }
}
