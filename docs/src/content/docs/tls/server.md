---
title: Incoming TLS
---

Configures TLS handling for incoming connections.

```yaml
server_tls:
  mode: terminate | passthrough    # Default: terminate

  # SNI hostname matching
  sni_hostnames: string | [string] # Hostname patterns (see below)

  # ALPN protocol matching
  alpn_protocols: string | [string]

  # Certificate (required for terminate mode)
  cert: string                     # Path to certificate file
  key: string                      # Path to private key file

  # Client certificate authentication (terminate mode only)
  client_ca_certs: [string]        # Paths to CA certificate PEM files
  client_fingerprints: [string]    # SHA256 fingerprints

  # Deprecated
  optional: false                  # true is auto-migrated to two separate targets
```

## TLS Modes

**Passthrough** -- reads the SNI and ALPN from the TLS ClientHello without decrypting. The raw TLS stream is forwarded transparently to the backend. No certificate or key is needed on the proxy.

**Terminate** (default) -- performs a full TLS handshake, decrypts the traffic, and can inspect HTTP content before forwarding. Requires `cert` and `key`.

Both modes can coexist on the same port for different SNI hostnames:

```yaml
targets:
  # Passthrough for public API
  - location: api-backend:443
    allowlist: 0.0.0.0/0
    server_tls:
      mode: passthrough
      sni_hostnames: api.example.com

  # Terminate for admin panel
  - location: admin-backend:8080
    allowlist: 10.0.0.0/8
    server_tls:
      mode: terminate
      cert: admin.crt
      key: admin.key
      sni_hostnames: admin.example.com
```

## SNI Hostname Patterns

```yaml
sni_hostnames: example.com          # Exact match only
sni_hostnames: "*.example.com"      # Any subdomain, but NOT example.com itself
sni_hostnames: ".example.com"       # example.com AND all subdomains
sni_hostnames: any                  # Any SNI value
sni_hostnames: none                 # Connections with no SNI
sni_hostnames:                      # Multiple patterns
  - api.example.com
  - "*.cdn.example.com"
  - any
  - none
```

Among eligible TLS targets at the same IP prefix length, matching priority is
exact match > deepest wildcard > shallower wildcard > `any`. All matching
patterns are considered before applying the [target ranking](/config/tcp/#target-evaluation-order).

Hostnames are case-insensitive. Trailing dots are stripped.

Omitted, `null`, or empty `sni_hostnames` accepts both present and absent SNI.
An explicit `any` matches only present SNI; use `[any, none]` to spell out both.
Wildcard patterns must be quoted in YAML.

## TLS Handshake Timeout

TLS termination accepts a positive `server_tls.handshake_timeout_secs`.
It bounds handshake completion after ClientHello routing, independently of the
existing ClientHello read timeout. Omission uses ten seconds; explicit `null`
disables this deadline. A positive value is invalid for passthrough, where the
backend owns the handshake.
Terminated TLS does not accept 0-RTT early data.

```yaml
server_tls:
  cert: server.crt
  key: server.key
  handshake_timeout_secs: 10
```

## ALPN Protocol Matching

In passthrough mode, ALPN protocols from the ClientHello are matched against the configured list. In terminate mode, the configured protocols are advertised in the ServerHello.

```yaml
alpn_protocols: h2                 # Single protocol
alpn_protocols:                    # Multiple protocols
  - h2
  - http/1.1
alpn_protocols: any                # Match any nonempty ALPN offer
alpn_protocols: none               # Match only when no ALPN
```

`any` controls matching, not protocol negotiation. Termination advertises only
explicit protocol names; `any` without explicit names negotiates no ALPN.
`any` does not match an absent ALPN offer; use `[any, none]` to accept both.
Passthrough leaves negotiation to the backend. HTTP actions dispatch negotiated
`h2` to HTTP/2 and otherwise retain the HTTP/1 session, including legacy custom
ALPN names. Use `[h2, http/1.1, none]` to accept both standard protocols and clients
without ALPN. `any` does not by itself negotiate HTTP/2.

For terminating HTTP targets, omitted ALPN is derived from `http_protocols`:
`[h2, http/1.1, none]` by default, `[http/1.1, none]` for H1-only, or `[h2]` for
H2-only. Explicit ALPN lists are preserved and rejected if they permit a disabled
HTTP protocol. Custom names, `any`, and `none` require H1 enabled. Explicit empty
lists or `null` retain the generic no-ALPN behavior and also require H1 enabled.
Raw forwarding and TLS passthrough do not derive HTTP ALPN settings.

For raw forwarding and passthrough, omitted, `null`, or empty ALPN lists accept
both present and absent ALPN. A terminating raw target advertises only explicit
protocol names, so that unrestricted default negotiates no protocol.

## Client Certificate Authentication

Requires clients to present a valid certificate. Only available in terminate mode (TLS 1.3 sends client certificates inside the encrypted tunnel, so passthrough mode cannot inspect them).

Two methods are supported and can be combined:

- **`client_ca_certs`** -- accept any client certificate that chains to one of the provided CA certificates
- **`client_fingerprints`** -- accept client certificates matching specific SHA256 fingerprints

When both are configured, a certificate is accepted if it passes **either** check.

```yaml
server_tls:
  mode: terminate
  cert: server.crt
  key: server.key
  sni_hostnames: secure.example.com

  # Accept any cert signed by this CA
  client_ca_certs:
    - /path/to/ca.crt

  # Also accept these specific self-signed certs
  client_fingerprints:
    - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    - "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
```

Fingerprints require 32 bytes (64 hexadecimal digits), with optional colons or
spaces. Invalid fingerprints are rejected when loading configuration.

```bash
# Generate a CA and client certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=MyCA"
openssl ecparam -genkey -name prime256v1 -out client.key
openssl req -new -key client.key -out client.csr -subj "/CN=Client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

# Get a certificate's SHA256 fingerprint
openssl x509 -in client.crt -noout -fingerprint -sha256
```
