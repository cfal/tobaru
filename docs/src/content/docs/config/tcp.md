---
title: TCP targets and routing
---

Each TCP target defines a forwarding destination with access control and optional TLS.

```yaml
targets:
  - allowlist: string | [string]   # IP masks or group names (required)
    location: string               # Single backend address (e.g., "backend:8080")
    locations: [string | object]   # Multiple backends (round-robin)
    server_tls: ServerTlsConfig    # Optional incoming TLS config
    tcp_nodelay: true              # Default: true
    tcp_keepalive: ...             # Same options as server-level (default idle: 120s, interval: 30s)
```

`target` (singular) is an alias for a single-element `targets` array.

## Location Formats

Locations specify where to forward traffic. Each location is either a plain address string or an object with additional settings.

An address string needs a port, such as `backend:8080`. Strings containing `/`
or no `:` are interpreted as UNIX socket paths; `location: backend` is a path,
not a hostname with an implicit port. Use the object form to make this explicit.

```yaml
# Simple string address
location: backend:8080

# UNIX domain socket path
location:
  path: /run/app.sock

# Address with outgoing TLS
location:
  address: upstream.example.com:443
  client_tls:
    verify: true

# Multiple backends (round-robin load balancing)
locations:
  - backend1:8080
  - backend2:8080
  - backend3:8080
```

The `address` and `addresses` field names are accepted as aliases for `location` and `locations`.

## Allowlist

Controls which source IPs may use this target. An IP outside this target's
allowlist may still use another eligible target on the listener. Connections
from IPs not matching any target's allowlist are rejected.

CIDRs are normalized to their network address: `192.0.2.123/26` means
`192.0.2.64/26`. Host bits are cleared without changing the prefix length, for
IPv4 and IPv6 literals and named-group entries. Equivalent spellings count as
the same network for duplicate checks. Bare addresses still match only that host.
Generated IPv4 firewall rules cover the portion of each CIDR within the mapped
IPv4 block (`::ffff:0:0/96`), including IPv6 prefixes that contain that entire block.

```yaml
# Allow all IPv4
allowlist: 0.0.0.0/0

# Multiple CIDR ranges
allowlist:
  - 192.168.1.0/24
  - 10.0.0.0/8

# Specific addresses
allowlist:
  - 1.2.3.4
  - 2001:db8::1

# Named IP groups
allowlist:
  - internal
  - trusted

# Mix of literals and groups
allowlist:
  - internal
  - 203.0.113.0/24
```

## Target Evaluation Order

TCP routing checks all applicable conditions before selecting a target. A TLS
target must match the source IP, SNI, and ALPN offer. A raw forwarding target
without `server_tls` accepts arbitrary bytes, including TLS. A plaintext HTTP
target is not an opaque TLS fallback.

Eligible targets are ranked in this order:

1. Longest matching source-IP prefix in the target's allowlist.
2. TLS over raw forwarding at the same IP prefix length.
3. Exact SNI over the deepest matching wildcard, then shallower wildcards, then `any`.
4. An explicitly matched ALPN protocol over `any`.
5. Earlier target in configuration order for remaining ties.

Passthrough and termination have equal priority. A more specific SNI pattern
whose IP or ALPN conditions fail does not hide eligible broader patterns.
When a target lists multiple IP prefixes or SNI patterns, its most specific
matching entry is used. Repeated IP prefixes across TCP targets are allowed;
duplicates within a single target's allowlist remain errors.

For example, a raw `/32` overrides a TLS `/0` for that source IP. At equal IP
prefix lengths, a matching TLS catch-all wins over a raw catch-all. Configuration
order does not override these specificity rules. UDP retains longest-prefix IP
routing without TLS inspection.

IP specificity is measured within the client's address family. For IPv4 clients,
`all`, `::/0`, and `0.0.0.0/0` have equal specificity; the internal IPv4-mapped
IPv6 representation does not give an IPv4 catch-all extra priority. IPv6 prefixes
covering the entire mapped IPv4 range likewise have IPv4 `/0` specificity.

```yaml
targets:
  # Internal users get admin backend
  - location: admin-backend:8080
    allowlist: 10.0.0.0/8
    server_tls:
      mode: passthrough
      sni_hostnames: app.example.com

  # Everyone else gets public backend
  - location: public-backend:8080
    allowlist: 0.0.0.0/0
    server_tls:
      mode: passthrough
      sni_hostnames: app.example.com
```

## Raw Catch-All

A `location` or `locations` target without `server_tls` is protocol-agnostic.
It remains eligible when no TLS route matches, including when another TLS
target allows the same source IP. Its position in the target list does not
make it override a more specific eligible route.

```yaml
targets:
  # Forward everything not selected by a more specific route, including TLS.
  - allowlist: 0.0.0.0/0
    location: /run/catch-all.sock

  - allowlist: 0.0.0.0/0
    location: /run/api.sock
    server_tls:
      mode: passthrough
      sni_hostnames: api.example.com
```

Here, TLS for `api.example.com` uses `/run/api.sock`; TLS for other names,
connections without SNI, and non-TLS traffic use `/run/catch-all.sock`.

When inspection is necessary, the ClientHello read has a five-second deadline.
Malformed, incomplete, or oversized ClientHellos may fall back to an eligible
raw target, replaying every buffered byte unchanged. Server-first protocols may
wait for this deadline. A raw target known to outrank every applicable TLS route
can be selected immediately without inspection. TLS-looking bytes never fall
back to a plaintext HTTP target.

Once a target is selected, TLS handshake/authentication errors and backend
connection errors terminate the connection. They do not retry another target.

**Access control:** a broad raw target intentionally grants fallback access,
including when a specific TLS target's IP or ALPN condition fails. A target's
allowlist is not a global deny rule for its SNI hostname. Remove or narrow the
raw fallback, and any broader TLS routes, when unmatched traffic must be rejected.
