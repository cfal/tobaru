/// Validates and normalizes a hostname pattern string.
/// Strips a trailing dot (FQDN form) and rejects empty patterns,
/// control characters, and empty labels (consecutive dots).
pub fn normalize_hostname_pattern(pattern: &str) -> Result<String, String> {
    // Reject prefix-only patterns before trailing-dot strip masks the problem
    // (e.g. "*." -> "*").
    if pattern == "*." || pattern == "." {
        return Err("hostname pattern has empty domain suffix".into());
    }

    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);

    if pattern.is_empty() {
        return Err("hostname pattern is empty".into());
    }
    if pattern == "*" {
        return Ok(pattern.to_string());
    }

    let suffix = pattern
        .strip_prefix("*.")
        .or_else(|| pattern.strip_prefix('.'))
        .unwrap_or(pattern);

    if suffix.is_empty() {
        return Err("hostname pattern has empty domain suffix".into());
    }
    if suffix.starts_with('.') || suffix.contains("..") {
        return Err("hostname pattern has empty labels (consecutive dots)".into());
    }
    if suffix.contains('*') {
        return Err("hostname pattern has wildcard in invalid position".into());
    }
    if suffix.bytes().any(|b| b.is_ascii_control()) {
        return Err("hostname pattern contains control characters".into());
    }

    Ok(pattern.to_string())
}

/// Validates a raw SNI hostname per RFC 6066 section 3.
/// Rejects trailing dots, control characters, non-ASCII bytes, empty labels,
/// and IP address literals.
pub fn validate_sni_hostname(hostname: &str) -> std::io::Result<()> {
    if hostname.is_empty() {
        return Err(std::io::Error::other("empty SNI hostname"));
    }
    if hostname.len() > 253 {
        return Err(std::io::Error::other("SNI hostname exceeds 253 bytes"));
    }
    if hostname.ends_with('.') {
        return Err(std::io::Error::other("SNI hostname has trailing dot"));
    }
    if hostname.starts_with('.') {
        return Err(std::io::Error::other("SNI hostname has leading dot"));
    }
    if hostname.contains("..") {
        return Err(std::io::Error::other("SNI hostname has empty label"));
    }
    if hostname.split('.').any(|label| label.len() > 63) {
        return Err(std::io::Error::other("SNI hostname label exceeds 63 bytes"));
    }
    // RFC 6066: SNI must be ASCII (IDN hostnames use punycode).
    if !hostname.is_ascii() {
        return Err(std::io::Error::other("SNI hostname contains non-ASCII bytes"));
    }
    if hostname.bytes().any(|b| b.is_ascii_control()) {
        return Err(std::io::Error::other("SNI hostname contains control characters"));
    }
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err(std::io::Error::other("SNI hostname is an IP address literal"));
    }
    if hostname.starts_with('[') {
        return Err(std::io::Error::other("SNI hostname is a bracketed IP literal"));
    }
    Ok(())
}

/// Strips the port suffix from a Host header value.
/// Handles bracketed IPv6 (e.g. "[::1]:8080" -> "[::1]").
pub fn strip_host_port(host: &str) -> &str {
    if let Some(bracket_end) = host.rfind(']') {
        match host[bracket_end + 1..].find(':') {
            Some(offset) => &host[..bracket_end + 1 + offset],
            None => host,
        }
    } else if let Some(colon) = host.rfind(':') {
        if host[colon + 1..].bytes().all(|b| b.is_ascii_digit()) {
            &host[..colon]
        } else {
            host
        }
    } else {
        host
    }
}

/// Matches a hostname from an HTTP Host header against a domain pattern.
/// Comparison is ASCII case-insensitive per RFC 4343.
/// The caller must validate with `validate_host_header` before calling this.
///
/// Supported patterns:
///   `"example.com"`    -- exact match only
///   `"*.example.com"`  -- any subdomain, but not `example.com` itself
///   `".example.com"`   -- `example.com` and any subdomain
///   `"*"`              -- catch-all
pub fn matches_host_header(hostname: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        is_subdomain_of(hostname, suffix)
    } else if let Some(suffix) = pattern.strip_prefix('.') {
        hostname.eq_ignore_ascii_case(suffix) || is_subdomain_of(hostname, suffix)
    } else {
        hostname.eq_ignore_ascii_case(pattern)
    }
}

/// Validates an HTTP Host header hostname.
/// Rejects empty hostnames, hostnames exceeding DNS length limits (253 total,
/// 63 per label), trailing dots, leading dots, empty labels, non-ASCII bytes,
/// whitespace, or control characters.
pub fn validate_host_header(hostname: &str) -> std::io::Result<()> {
    if hostname.is_empty() {
        return Err(std::io::Error::other("empty Host header hostname"));
    }
    if hostname.len() > 253 {
        return Err(std::io::Error::other("Host header hostname exceeds 253 bytes"));
    }
    if hostname.ends_with('.') {
        return Err(std::io::Error::other("Host header hostname has trailing dot"));
    }
    if hostname.starts_with('.') {
        return Err(std::io::Error::other("Host header hostname has leading dot"));
    }
    if hostname.contains("..") {
        return Err(std::io::Error::other("Host header hostname has empty label"));
    }
    if hostname.split('.').any(|label| label.len() > 63) {
        return Err(std::io::Error::other("Host header hostname label exceeds 63 bytes"));
    }
    if !hostname.is_ascii() {
        return Err(std::io::Error::other("Host header hostname contains non-ASCII bytes"));
    }
    if hostname.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(std::io::Error::other("Host header hostname contains control characters"));
    }
    Ok(())
}

/// Returns true if `hostname` is a proper subdomain of `domain`
/// (i.e. has at least one additional label separated by a dot).
fn is_subdomain_of(hostname: &str, domain: &str) -> bool {
    hostname.len() > domain.len() + 1
        && hostname.as_bytes()[hostname.len() - domain.len() - 1] == b'.'
        && hostname[hostname.len() - domain.len()..].eq_ignore_ascii_case(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod normalize_hostname_pattern_tests {

        use super::*;

        fn norm(s: &str) -> Result<String, String> {
            normalize_hostname_pattern(s)
        }

        // Acceptance

        #[test]
        fn exact_domain() {
            assert_eq!(norm("example.com").unwrap(), "example.com");
        }

        #[test]
        fn wildcard_domain() {
            assert_eq!(norm("*.example.com").unwrap(), "*.example.com");
        }

        #[test]
        fn dot_shorthand() {
            assert_eq!(norm(".example.com").unwrap(), ".example.com");
        }

        #[test]
        fn catch_all_star() {
            assert_eq!(norm("*").unwrap(), "*");
        }

        #[test]
        fn single_label() {
            assert_eq!(norm("localhost").unwrap(), "localhost");
        }

        // Normalization

        #[test]
        fn trailing_dot_stripped_exact() {
            assert_eq!(norm("example.com.").unwrap(), "example.com");
        }

        #[test]
        fn trailing_dot_stripped_wildcard() {
            assert_eq!(norm("*.example.com.").unwrap(), "*.example.com");
        }

        #[test]
        fn trailing_dot_stripped_dot_shorthand() {
            assert_eq!(norm(".example.com.").unwrap(), ".example.com");
        }

        // Rejection

        #[test]
        fn empty_string() {
            assert!(norm("").is_err());
        }

        #[test]
        fn bare_dot() {
            assert!(norm(".").is_err());
        }

        #[test]
        fn star_dot() {
            assert!(norm("*.").is_err());
        }

        #[test]
        fn consecutive_dots() {
            assert!(norm("example..com").is_err());
        }

        #[test]
        fn consecutive_dots_in_wildcard_suffix() {
            assert!(norm("*.example..com").is_err());
        }

        #[test]
        fn consecutive_dots_in_dot_shorthand_suffix() {
            assert!(norm(".example..com").is_err());
        }

        #[test]
        fn null_byte() {
            assert!(norm("example\x00.com").is_err());
        }

        #[test]
        fn control_char() {
            assert!(norm("example\x1f.com").is_err());
        }

        #[test]
        fn del_char() {
            assert!(norm("example\x7f.com").is_err());
        }

        #[test]
        fn double_dot_after_wildcard_prefix() {
            assert!(norm("*..example.com").is_err());
        }

        #[test]
        fn double_dot_after_dot_shorthand_prefix() {
            assert!(norm("..example.com").is_err());
        }

        #[test]
        fn double_dot_only() {
            assert!(norm("..").is_err());
        }

        #[test]
        fn double_star() {
            assert!(norm("**").is_err());
        }

        #[test]
        fn double_star_dot_suffix() {
            assert!(norm("**.example.com").is_err());
        }

        #[test]
        fn star_dot_star() {
            assert!(norm("*.*").is_err());
        }

        #[test]
        fn star_dot_star_dot_suffix() {
            assert!(norm("*.*.example.com").is_err());
        }

        #[test]
        fn star_in_middle_label() {
            assert!(norm("foo.*.com").is_err());
        }

        #[test]
        fn star_in_suffix_label() {
            assert!(norm("*.foo.*.com").is_err());
        }

        #[test]
        fn star_embedded_in_label() {
            assert!(norm("fo*o.example.com").is_err());
        }

        #[test]
        fn tab_char() {
            assert!(norm("example\t.com").is_err());
        }

        #[test]
        fn carriage_return() {
            assert!(norm("example\r.com").is_err());
        }

        #[test]
        fn newline() {
            assert!(norm("example\n.com").is_err());
        }

        #[test]
        fn high_bit_bytes_accepted() {
            // Bytes > 0x7F are not rejected; IDN/punycode is the caller's concern.
            assert!(norm("caf\u{00e9}.example.com").is_ok());
        }

        #[test]
        fn single_label_suffix_after_dot_prefix() {
            assert_eq!(norm(".a").unwrap(), ".a");
        }

        #[test]
        fn single_label_suffix_after_wildcard_prefix() {
            assert_eq!(norm("*.a").unwrap(), "*.a");
        }

        #[test]
        fn whitespace_in_pattern() {
            assert!(norm("example .com").is_ok());
            assert!(norm(" example.com").is_ok());
        }

        #[test]
        fn trailing_dot_only_star() {
            // "*." is caught before trailing-dot stripping.
            assert!(norm("*.").is_err());
        }
    }
    mod validate_sni_hostname_tests {
        use super::*;

        fn ok(s: &str) {
            assert!(validate_sni_hostname(s).is_ok(), "expected Ok for {:?}", s);
        }

        fn err(s: &str) {
            assert!(
                validate_sni_hostname(s).is_err(),
                "expected Err for {:?}",
                s
            );
        }

        // Valid hostnames

        #[test]
        fn standard_domain() {
            ok("example.com");
        }

        #[test]
        fn three_labels() {
            ok("sub.example.com");
        }

        #[test]
        fn deep_nesting() {
            ok("a.b.c.d.example.com");
        }

        #[test]
        fn single_label() {
            ok("localhost");
        }

        #[test]
        fn punycode_encoded() {
            ok("xn--n3h.example.com");
        }

        #[test]
        fn single_char() {
            ok("a");
        }

        #[test]
        fn uppercase() {
            ok("EXAMPLE.COM");
        }

        #[test]
        fn hyphens() {
            ok("my-host.example.com");
        }

        #[test]
        fn digits_in_labels() {
            ok("host123.example.com");
        }

        #[test]
        fn all_digit_label_with_suffix() {
            ok("123.example.com");
        }

        #[test]
        fn numeric_looking_with_alpha_tld() {
            ok("1.2.3.4.example.com");
        }

        #[test]
        fn double_hyphens() {
            ok("example--host.com");
        }

        #[test]
        fn multiple_hyphens() {
            ok("a-b-c.example.com");
        }

        // Rejected: trailing dot

        #[test]
        fn trailing_dot() {
            err("example.com.");
        }

        #[test]
        fn bare_dot() {
            err(".");
        }

        // Rejected: leading dot

        #[test]
        fn leading_dot() {
            err(".example.com");
        }

        #[test]
        fn just_dot() {
            // Also caught by trailing dot, but leading dot check runs first
            err(".");
        }

        // Rejected: empty labels

        #[test]
        fn consecutive_dots() {
            err("example..com");
        }

        #[test]
        fn leading_consecutive_dots() {
            err("..example.com");
        }

        // Rejected: empty

        #[test]
        fn empty_string() {
            err("");
        }

        // Rejected: control characters

        #[test]
        fn null_byte() {
            err("example\x00.com");
        }

        #[test]
        fn unit_separator() {
            err("example\x1f.com");
        }

        #[test]
        fn del_char() {
            err("example\x7f.com");
        }

        #[test]
        fn tab() {
            err("example\t.com");
        }

        #[test]
        fn newline() {
            err("example\n.com");
        }

        #[test]
        fn carriage_return() {
            err("example\r.com");
        }

        // Rejected: non-ASCII

        #[test]
        fn combining_accent() {
            err("cafe\u{0301}.com");
        }

        #[test]
        fn latin_accented_char() {
            err("caf\u{00e9}.com");
        }

        // Rejected: IP literals

        #[test]
        fn ipv4_address() {
            err("192.168.1.1");
        }

        #[test]
        fn ipv6_address() {
            err("::1");
        }

        #[test]
        fn bracketed_ipv6() {
            err("[::1]");
        }

        #[test]
        fn ipv4_all_zeros() {
            err("0.0.0.0");
        }

        #[test]
        fn ipv4_loopback() {
            err("127.0.0.1");
        }

        // Rejected: length limits

        #[test]
        fn hostname_over_253_bytes() {
            // 4 x 63-char labels + 3 dots = 255, plus ".a" = 258
            let label = "a".repeat(63);
            let long = format!("{0}.{0}.{0}.{0}.a", label);
            assert!(long.len() > 253);
            err(&long);
        }

        #[test]
        fn hostname_exactly_253_bytes() {
            // 4 x 62-char labels + 3 dots = 251, plus ".ab" = 254 -- one too many
            // 4 x 62-char labels + 3 dots = 251, plus ".a" = 253
            let label = "a".repeat(62);
            let long = format!("{0}.{0}.{0}.{0}.a", label);
            assert_eq!(long.len(), 253);
            ok(&long);
        }

        #[test]
        fn label_over_63_bytes() {
            let long = format!("{}.example.com", "a".repeat(64));
            err(&long);
        }

        #[test]
        fn label_exactly_63_bytes() {
            let long = format!("{}.example.com", "a".repeat(63));
            ok(&long);
        }
    }

    mod strip_host_port_tests {
        use super::*;

        #[test]
        fn plain_hostname() {
            assert_eq!(strip_host_port("example.com"), "example.com");
        }

        #[test]
        fn hostname_with_port() {
            assert_eq!(strip_host_port("example.com:8080"), "example.com");
        }

        #[test]
        fn hostname_with_default_port() {
            assert_eq!(strip_host_port("example.com:443"), "example.com");
        }

        #[test]
        fn ipv4_with_port() {
            assert_eq!(strip_host_port("192.168.1.1:80"), "192.168.1.1");
        }

        #[test]
        fn ipv4_without_port() {
            assert_eq!(strip_host_port("192.168.1.1"), "192.168.1.1");
        }

        #[test]
        fn bracketed_ipv6_with_port() {
            assert_eq!(strip_host_port("[::1]:8080"), "[::1]");
        }

        #[test]
        fn bracketed_ipv6_without_port() {
            assert_eq!(strip_host_port("[::1]"), "[::1]");
        }

        #[test]
        fn empty_string() {
            assert_eq!(strip_host_port(""), "");
        }

        #[test]
        fn colon_only() {
            // ":8080" -- no hostname, colon at start
            assert_eq!(strip_host_port(":8080"), "");
        }

        #[test]
        fn trailing_colon_no_port() {
            // "example.com:" -- colon but empty port (all-digit check on empty is true)
            assert_eq!(strip_host_port("example.com:"), "example.com");
        }

        #[test]
        fn non_numeric_port() {
            // Not a valid port, so colon is kept (could be IPv6 without brackets)
            assert_eq!(strip_host_port("example.com:abc"), "example.com:abc");
        }

        #[test]
        fn port_with_spaces() {
            assert_eq!(strip_host_port("example.com: 80"), "example.com: 80");
        }

        #[test]
        fn multiple_colons_not_bracketed() {
            // Bare IPv6 without brackets -- rfind(':') finds the last colon, "1" is digits
            assert_eq!(strip_host_port("::1"), ":");
        }

        #[test]
        fn bracketed_ipv6_full() {
            assert_eq!(strip_host_port("[2001:db8::1]:443"), "[2001:db8::1]");
        }

        #[test]
        fn trailing_dot_with_port() {
            assert_eq!(strip_host_port("example.com.:8080"), "example.com.");
        }

        #[test]
        fn unmatched_bracket() {
            // No closing bracket, so rfind(':') finds the last colon in the
            // IPv6 address; "1" is all-digits so it looks like a port.
            assert_eq!(strip_host_port("[::1"), "[:");
        }
    }

    mod validate_host_header_tests {
        use super::*;

        fn valid(s: &str) {
            assert!(validate_host_header(s).is_ok(), "expected Ok for {:?}", s);
        }

        fn invalid(s: &str) {
            assert!(validate_host_header(s).is_err(), "expected Err for {:?}", s);
        }

        #[test]
        fn standard_domains() {
            valid("example.com");
            valid("sub.example.com");
            valid("a.b.c.d.example.com");
            valid("localhost");
        }

        #[test]
        fn hyphens_digits_underscores() {
            valid("my-host.example.com");
            valid("host123.example.com");
            valid("_dmarc.example.com");
            valid("example--host.com");
        }

        #[test]
        fn case_preserved() {
            valid("EXAMPLE.COM");
            valid("Example.Com");
        }

        #[test]
        fn empty() {
            invalid("");
        }

        #[test]
        fn trailing_dot() {
            invalid("example.com.");
            invalid(".");
        }

        #[test]
        fn leading_dot() {
            invalid(".example.com");
        }

        #[test]
        fn consecutive_dots() {
            invalid("example..com");
            invalid("..example.com");
        }

        #[test]
        fn control_characters() {
            invalid("example\x00.com");
            invalid("example\x1f.com");
            invalid("example\x7f.com");
            invalid("example\t.com");
            invalid("example\n.com");
            invalid("example\r.com");
        }

        #[test]
        fn non_ascii() {
            invalid("caf\u{00e9}.example.com");
            invalid("cafe\u{0301}.com");
        }

        #[test]
        fn whitespace() {
            invalid(" example.com");
            invalid("example.com ");
        }

        #[test]
        fn hostname_over_253_bytes() {
            let label = "a".repeat(63);
            let long = format!("{0}.{0}.{0}.{0}.a", label);
            assert!(long.len() > 253);
            invalid(&long);
        }

        #[test]
        fn hostname_exactly_253_bytes() {
            let label = "a".repeat(62);
            let long = format!("{0}.{0}.{0}.{0}.a", label);
            assert_eq!(long.len(), 253);
            valid(&long);
        }

        #[test]
        fn label_over_63_bytes() {
            invalid(&format!("{}.example.com", "a".repeat(64)));
        }

        #[test]
        fn label_exactly_63_bytes() {
            valid(&format!("{}.example.com", "a".repeat(63)));
        }

        // Unlike SNI, Host headers legitimately contain IP addresses.

        #[test]
        fn ipv4_accepted() {
            valid("192.168.1.1");
            valid("127.0.0.1");
            valid("0.0.0.0");
        }

        #[test]
        fn bracketed_ipv6_accepted() {
            valid("[::1]");
            valid("[2001:db8::1]");
        }
    }

    mod matches_host_header_tests {
        use super::*;

        #[test]
        fn exact_match() {
            assert!(matches_host_header("example.com", "example.com"));
        }

        #[test]
        fn exact_mismatch() {
            assert!(!matches_host_header("other.com", "example.com"));
        }

        #[test]
        fn wildcard_matches_subdomain() {
            assert!(matches_host_header("foo.example.com", "*.example.com"));
        }

        #[test]
        fn wildcard_matches_deep_subdomain() {
            assert!(matches_host_header(
                "a.b.c.example.com",
                "*.example.com"
            ));
        }

        #[test]
        fn wildcard_does_not_match_base() {
            assert!(!matches_host_header("example.com", "*.example.com"));
        }

        #[test]
        fn wildcard_no_partial_label_match() {
            assert!(!matches_host_header("fooexample.com", "*.example.com"));
        }

        #[test]
        fn dot_shorthand_matches_base() {
            assert!(matches_host_header("example.com", ".example.com"));
        }

        #[test]
        fn dot_shorthand_matches_subdomain() {
            assert!(matches_host_header("foo.example.com", ".example.com"));
        }

        #[test]
        fn dot_shorthand_matches_deep() {
            assert!(matches_host_header(
                "a.b.c.example.com",
                ".example.com"
            ));
        }

        #[test]
        fn dot_shorthand_no_partial_label_match() {
            assert!(!matches_host_header("fooexample.com", ".example.com"));
        }

        #[test]
        fn catch_all() {
            assert!(matches_host_header("anything.example.com", "*"));
            assert!(matches_host_header("localhost", "*"));
        }

        #[test]
        fn unrelated_domain() {
            assert!(!matches_host_header("other.net", "*.example.com"));
        }

        #[test]
        fn case_insensitive_exact() {
            assert!(matches_host_header("EXAMPLE.COM", "example.com"));
            assert!(matches_host_header("Example.Com", "example.com"));
            assert!(matches_host_header("example.com", "EXAMPLE.COM"));
        }

        #[test]
        fn case_insensitive_wildcard() {
            assert!(matches_host_header("FOO.EXAMPLE.COM", "*.example.com"));
            assert!(matches_host_header("Foo.Example.Com", "*.example.com"));
        }

        #[test]
        fn case_insensitive_dot_shorthand() {
            assert!(matches_host_header("EXAMPLE.COM", ".example.com"));
            assert!(matches_host_header("FOO.EXAMPLE.COM", ".example.com"));
        }

        #[test]
        fn hostname_is_pattern_prefix() {
            assert!(!matches_host_header(
                "example.com.evil.com",
                "example.com"
            ));
        }

        #[test]
        fn hostname_is_pattern_suffix() {
            assert!(!matches_host_header("evilexample.com", ".example.com"));
            assert!(!matches_host_header(
                "evilexample.com",
                "*.example.com"
            ));
        }

        #[test]
        fn punycode_exact() {
            assert!(matches_host_header(
                "xn--e1afmapc.xn--p1ai",
                "xn--e1afmapc.xn--p1ai"
            ));
        }

        #[test]
        fn pattern_edge_cases() {
            assert!(!matches_host_header("example.com", "."));
            assert!(!matches_host_header("example.com", "*."));
        }

        #[test]
        fn single_char_labels() {
            assert!(matches_host_header("a.b.c", "*.b.c"));
            assert!(matches_host_header("x.y", "x.y"));
        }

        #[test]
        fn ipv4_as_hostname() {
            assert!(matches_host_header("192.168.1.1", "192.168.1.1"));
            assert!(matches_host_header("192.168.1.1", "*.168.1.1"));
            assert!(matches_host_header("192.168.1.1", "*"));
        }
    }
}
