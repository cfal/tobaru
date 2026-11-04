---
title: HTTP routing
---

HTTP path-based routing is available when TLS is terminated or for plain HTTP.
An HTTP target requires `default_http_action`; `http_paths` is optional. Do not
mix HTTP settings with target-level raw forwarding `location`/`locations`.
The parser does not reject these mixed fields: with an inferred protocol,
`default_http_action` selects HTTP and raw locations are ignored. With raw
locations but no `default_http_action`, the target forwards raw bytes and
`http_paths` is ignored. Path rules then provide no access restriction.
Explicit `protocol: http` selects HTTP and requires `default_http_action`, but
does not make unknown raw fields an error.

```yaml
target:
  allowlist: 0.0.0.0/0
  http_paths:
    /api/:
      http_action:
        type: forward
        addresses:
          - api-backend:8080
    /static/:
      http_action:
        type: serve-directory
        path: /var/www/static
  default_http_action:
    type: forward
    addresses:
      - default-backend:8080
```

See [timeouts and resource limits](/operations/limits/#http-and-tls-timeouts) and [HTTP/2 policy](/http/http2/).



## Path Matching

Paths use longest-prefix matching at raw path-segment boundaries, excluding the
query string. Both `/api` and `/api/` match the bare mount and slash-separated
descendants, not sibling names such as `/apiculture`. Keys must start with `/`
and cannot contain `?` or `#`.

```yaml
http_paths:
  /api/:     # matches /api, /api?x=1, /api/, /api/users; not /apiculture
  /health:   # matches /health, /health?x=1, /health/live; not /healthcheck
```

Only the longest matching key is considered. If its required headers do not
match, `default_http_action` is used, not a shorter configured prefix.

Paths are not percent-decoded or normalized before routing. Align backend path
interpretation with routing; predicates alone are not an authorization boundary.

## Required Request Headers

Each path entry can require specific HTTP headers to match. Header keys are case-insensitive.

A string requires an exact value, an array accepts any listed value, and `null`
requires the header to be present with any value. Ordinary values are
case-sensitive; `host` uses hostname matching. Multiple received fields for a
required header are rejected, rather than merged or treated as alternatives.

```yaml
http_paths:
  /:
    - required_request_headers:
        x-api-key: secret123
      http_action:
        type: forward
        addresses: [backend:8080]

    - required_request_headers:
        host: app.example.com
      http_action:
        type: forward
        addresses: [app-backend:8080]
```

When multiple entries exist under the same path, they are evaluated in order. The first match wins.

## Host Header Routing

The `host` key in `required_request_headers` supports the same wildcard patterns as `sni_hostnames`. Port suffixes in the Host header (e.g., `example.com:8080`) are automatically stripped before matching.

Matching is case-insensitive, but received Host authorities must be valid; empty
hosts, invalid ports, and trailing-dot hosts are rejected. `null` is a
presence-only predicate, not a hostname pattern.

```yaml
http_paths:
  /:
    # Exact match
    - required_request_headers:
        host: app.example.com
      http_action:
        type: forward
        addresses: [app-backend:8080]

    # Wildcard subdomains
    - required_request_headers:
        host: "*.api.example.com"
      http_action:
        type: forward
        addresses: [api-backend:8080]

    # Base domain + all subdomains
    - required_request_headers:
        host: ".example.com"
      http_action:
        type: forward
        addresses: [default-backend:8080]

default_http_action:
  type: serve-message
  status_code: 404
```

When possible, prefer SNI-level routing (`sni_hostnames`) over Host header matching. SNI routing operates at the TLS layer before HTTP parsing, avoiding the overhead of decryption and request parsing. Host header routing is useful for plain HTTP, or when multiple virtual hosts share the same TLS certificate.
