# Configuration Reference

tobaru uses YAML configuration files. Multiple configuration types can be combined in a single file or split across multiple files.

## Table of Contents
- [Configuration Structure](#configuration-structure)
- [Server Config](#server-config)
- [TCP Targets](#tcp-targets)
- [Server TLS](#server-tls)
- [Client TLS](#client-tls)
- [HTTP Routing](#http-routing)
- [HTTP Actions](#http-actions)
- [UDP Targets](#udp-targets)
- [IP Groups](#ip-groups)
- [URL-Based Configuration](#url-based-configuration)
- [Command Line](#command-line)

## Configuration Structure

A configuration file is a YAML array containing one or more entries. Each entry can be:

- **Server Config** -- defines a listener with one or more forwarding targets
- **IP Group** -- defines a reusable named set of IP ranges

```yaml
# Server config (has 'address')
- address: "0.0.0.0:443"
  transport: tcp
  targets:
    - location: backend:443
      allowlist: 0.0.0.0/0

# IP group (has 'group')
- group: internal
  ip_masks:
    - 192.168.0.0/16
    - 10.0.0.0/8
```

Multiple config files can be passed on the command line and are merged together. This is useful for separating IP group definitions from server definitions.

### Supported Formats

- **YAML**: `.yml` or `.yaml` extension (recommended)
- **JSON**: `.json` extension, with optional `//` single-line comments

## Server Config

```yaml
address: "0.0.0.0:8080"           # Bind address (required)

transport: tcp | udp               # Default: tcp

# TCP-specific settings (only when transport: tcp)
tcp_nodelay: true                  # Disable Nagle's algorithm (default: true)
tcp_keepalive: true | false | null | { idle_secs: int, interval_secs: int }

use_iptables: false                # Auto-configure iptables rules (default: false)

# One or more targets
target: TcpTargetConfig            # Single target
targets: [TcpTargetConfig]         # Multiple targets
```

### Address Format

```yaml
address: "0.0.0.0:8080"           # IPv4
address: "[::]:8080"              # IPv6
```

### TCP Keepalive

Controls TCP keepalive probes on the server-side (client-facing) socket.

```yaml
# Use defaults (idle: 300s, interval: 60s)
tcp_keepalive: true                # or omit the field

# Disable keepalive
tcp_keepalive: false
tcp_keepalive: null

# Custom values
tcp_keepalive:
  idle_secs: 120
  interval_secs: 30
```

### iptables Integration

When `use_iptables: true`, tobaru automatically configures iptables/ip6tables rules to drop packets from IPs not in the allowlist at the kernel level, before they reach the application.

Requires root or `CAP_NET_RAW` + `CAP_NET_ADMIN` capabilities. Supported on Linux only.

```bash
# Clear all tobaru-managed iptables rules
sudo tobaru --clear-iptables-all

# Clear rules for specific config files only
sudo tobaru --clear-iptables-matching config.yaml
```

## TCP Targets

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

### Location Formats

Locations specify where to forward traffic. Each location is either a plain address string or an object with additional settings.

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

### Allowlist

Controls which source IPs may connect to this target. Connections from IPs not matching any allowlist entry are rejected.

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

### Target Evaluation Order

When multiple targets are defined, they are evaluated in order. The first target whose allowlist matches the client IP (and whose TLS settings match the connection, if applicable) handles the connection.

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

## Server TLS

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
  optional: false                  # Auto-migrated to two separate targets
```

### TLS Modes

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

### SNI Hostname Patterns

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

Matching priority: exact match > deepest wildcard > shallower wildcard.

Hostnames are case-insensitive. Trailing dots are stripped.

### TLS Handshake Timeout

TLS termination accepts an optional positive `server_tls.handshake_timeout_secs`.
It bounds handshake completion after ClientHello routing, independently of the
existing ClientHello read timeout. Omitted or `null` disables the additional
deadline. It is invalid for passthrough, where the backend owns the handshake.
Terminated TLS does not accept 0-RTT early data.

```yaml
server_tls:
  cert: server.crt
  key: server.key
  handshake_timeout_secs: 10
```

### ALPN Protocol Matching

In passthrough mode, ALPN protocols from the ClientHello are matched against the configured list. In terminate mode, the configured protocols are advertised in the ServerHello.

```yaml
alpn_protocols: h2                 # Single protocol
alpn_protocols:                    # Multiple protocols
  - h2
  - http/1.1
alpn_protocols: any                # Match any ALPN
alpn_protocols: none               # Match only when no ALPN
```

### Client Certificate Authentication

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
    - "1122334455667788990011223344556677889900112233445566778899001122"
```

Fingerprints accept both colon-separated and plain hex formats.

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

## Client TLS

Configures TLS for outgoing connections to backend servers. Set within a location object.

```yaml
location:
  address: upstream.example.com:443
  client_tls:
    verify: true                   # Verify server cert via WebPKI (default: true)
    cert: string                   # Client certificate for mTLS
    key: string                    # Client private key for mTLS
    sni_hostname: string | null    # SNI to send (default: derived from address, null to disable)
    alpn_protocols: [string]       # ALPN protocols to negotiate
    server_fingerprints: [string]  # SHA256 fingerprints for cert pinning
```

### Shorthand Forms

```yaml
# Enable with defaults (verify: true)
client_tls: true

# Enable with verification disabled
client_tls: "no-verify"

# Full object form
client_tls:
  verify: true
  sni_hostname: custom.example.com
  server_fingerprints:
    - "AA:BB:CC:..."
```

`client_tls` cannot be used with passthrough mode (would cause TLS-in-TLS).

### Server Certificate Pinning

```yaml
client_tls:
  server_fingerprints:
    - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
```

```bash
# Get a server's certificate fingerprint
openssl s_client -connect example.com:443 < /dev/null 2>/dev/null | openssl x509 -outform PEM > server.crt
openssl x509 -in server.crt -noout -fingerprint -sha256
```

## HTTP Routing

HTTP path-based routing is available when TLS is terminated (or for plain HTTP). A target with `http_paths` and/or `default_http_action` is treated as an HTTP target.

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

### HTTP Timeouts

Timeouts belong to the HTTP target and apply to all of its routes. All are
disabled when omitted or `null`; configured values must be positive seconds.

```yaml
target:
  allowlist: 127.0.0.1/32
  http_timeouts:
    request_header_timeout_secs: 15
    response_header_timeout_secs: 30
    keepalive_idle_timeout_secs: 60
  default_http_action:
    type: forward
    location: 127.0.0.1:8080
```

- The request-header deadline starts when HTTP handling begins for the first
  request, or when the first byte of a subsequent request is received. Partial
  header progress does not reset it.
- The response-header deadline starts after upstream request headers are sent
  and lasts until final response headers arrive. Informational responses do not
  reset it. It includes any concurrent request upload and backend processing;
  choose a value suitable for those workloads or leave it disabled.
- The keepalive idle deadline bounds waiting for the next request's first byte.
  Once data arrives, the request-header deadline applies instead.

Expiration closes the affected HTTP session. These are not body-transfer or
whole-session deadlines; upgraded tunnels are not subject to them.

### Path Matching

Paths are matched by longest prefix. A trailing `/` in the path key matches that prefix and everything below it.

```yaml
http_paths:
  /api/:     # matches /api/, /api/users, /api/v2/foo, etc.
  /health:   # matches /health exactly
```

### Required Request Headers

Each path entry can require specific HTTP headers to match. Header keys are case-insensitive.

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

### Host Header Routing

The `host` key in `required_request_headers` supports the same wildcard patterns as `sni_hostnames`. Port suffixes in the Host header (e.g., `example.com:8080`) are automatically stripped before matching.

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

## HTTP Actions

### forward

Forwards the HTTP request to one or more backend servers. Supports connection keep-alive, WebSocket upgrades, and header manipulation.

```yaml
http_action:
  type: forward
  locations: [string | object]     # Backend address(es) -- round-robin if multiple
  replacement_path: string         # Rewrite the request path
  request_header_patch:            # Modify request headers
    default_headers:               #   Add if not already present
      X-Forwarded-For: "..."
    overwrite_headers:             #   Set unconditionally
      Host: backend.internal
    remove_headers:                #   Remove
      - X-Debug
  response_header_patch:           # Modify response headers (same structure)
    overwrite_headers:
      X-Served-By: tobaru
  request_id_header_name: string   # Add a unique request ID header to the request
  response_id_header_name: string  # Add a unique request ID header to the response
```

The `address`, `addresses`, and `location` field names are accepted as aliases for `locations`.

Backend reuse is local to a client connection and the selected HTTP action.
Changing Host/header rules to select another action opens a different backend
connection, even when the path prefix is unchanged. Round-robin selection occurs
when a backend connection is opened, not on every request.

Header names in patches are case-insensitive. Repeated received fields retain
their value order; an overwrite replaces all values for that name. Patches must
not change the received body's framing (for example, changing Content-Length or
removing chunked Transfer-Encoding). Such requests/responses are rejected and the
connection is closed; body bytes are not rewritten to match a patched length or
transfer-coding stack. Transfer-Encoding fields with parameters must remain
unchanged; their quoted values are not normalized. Patches also cannot manufacture
or relabel a successful protocol upgrade: the original and forwarded handshakes
must agree, including the case-sensitive protocol version when present.

Forwarding supports HEAD/bodyless responses, informational responses including
100 Continue and 103 Early Hints, and close-delimited response bodies. An early
final response during an unfinished upload is forwarded and both connections are
closed rather than reused. HTTP mode still accepts only origin-form HTTP/1.1
requests; it does not implement CONNECT or HTTP/2. For HTTP actions, configure TLS
ALPN as `http/1.1`, not `h2`.

### serve-message

Returns a static HTTP response.

```yaml
http_action:
  type: serve-message
  status_code: 200                 # HTTP status code (required)
  status_message: "OK"             # Custom status text (optional)
  content: "Hello, world!"        # Response body (default: "")
  response_headers:                # Custom response headers
    Content-Type: "text/plain"
  response_id_header_name: string  # Add a unique request ID header
```

### serve-directory

Serves static files from a directory. MIME types are automatically detected.

```yaml
http_action:
  type: serve-directory
  path: /var/www/static            # Directory path (required)
  response_headers:                # Custom response headers
    Cache-Control: "max-age=3600"
  response_id_header_name: string  # Add a unique request ID header
```

### close

Immediately closes the connection.

```yaml
http_action:
  type: close

# Shorthand string form
http_action: close
```

## UDP Targets

UDP forwarding with round-robin load balancing and stateful association tracking.

The optional listener-level `udp_max_associations` caps the total across all
targets. Omitted or `null` means unlimited; configured values must be positive
integers. At capacity, packets for new client addresses are dropped, while
existing associations continue forwarding. Idle cleanup frees capacity.

```yaml
- address: 0.0.0.0:53
  transport: udp
  udp_max_associations: 4096  # Optional, shared by all targets on this listener
  target:
    addresses: [string]            # Backend address(es) -- round-robin
    allowlist: string | [string]   # IP masks or group names
    association_timeout_secs: 200  # Timeout for UDP associations (default: 200, min: 5)
```

The `address`, `location`, and `locations` field names are accepted as aliases for `addresses`.

## IP Groups

Named, reusable sets of IP ranges. Define groups before referencing them in server configs (ordering within the file matters).

```yaml
# Define groups
- group: internal
  ip_masks:
    - 192.168.0.0/16
    - 10.0.0.0/8
    - 172.16.0.0/12

- group: trusted
  ip_masks:
    - 1.2.3.4
    - 5.6.7.8
    - internal                     # Groups can reference other groups

# Use in server config
- address: 0.0.0.0:8080
  transport: tcp
  target:
    location: backend:8080
    allowlist:
      - internal
      - trusted
```

The built-in group `all` is equivalent to `0.0.0.0/0` (all IPv4).

`ip_mask` (singular) is accepted as an alias for `ip_masks`.

## URL-Based Configuration

For simple forwarding, configs can be specified as URLs on the command line instead of YAML files.

```bash
# TCP forwarding
tobaru tcp://127.0.0.1:8080?target=192.168.1.10:80

# Multiple targets (round-robin)
tobaru "tcp://127.0.0.1:8080?target=backend1:80&target=backend2:80"

# Forward to UNIX socket
tobaru tcp://127.0.0.1:8080?target-path=/run/app.sock

# UDP forwarding
tobaru udp://127.0.0.1:53?target=8.8.8.8:53&target=8.8.4.4:53
```

URL configs always use `allowlist: 0.0.0.0/0` (allow all). For access control, use a YAML config file.

### URL Query Parameters

| Scheme | Parameter | Description |
|--------|-----------|-------------|
| `tcp` | `target` or `target-address` | Backend TCP address |
| `tcp` | `target-path` | Backend UNIX socket path |
| `udp` | `target` or `target-address` | Backend UDP address |

## Command Line

```
tobaru [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] ...

OPTIONS:
  -t, --threads NUM           Worker threads (default: auto-detected from CPU count)
  --clear-iptables-all        Clear all tobaru iptables rules and exit
  --clear-iptables-matching   Clear iptables rules for specified config files and exit
  -h, --help                  Show help
```

### Examples

```bash
# Run with a single config file
tobaru config.yaml

# Run with multiple config files (merged together)
tobaru servers.yaml ip_groups.yaml

# Simple TCP forwarding via URL
tobaru tcp://127.0.0.1:8080?target=192.168.1.10:80

# Custom thread count
tobaru --threads 4 config.yaml

# Clear iptables rules
sudo tobaru --clear-iptables-matching config.yaml
sudo tobaru --clear-iptables-all
```

### Hot Reloading

Configuration files are automatically watched for changes and reloaded without restart.

## Deprecated Fields

These fields are accepted with a deprecation warning and will be removed in a future version.

| Deprecated | Replacement |
|------------|-------------|
| `serverTls` | `server_tls` |
| `bindAddress` | `address` |
| `addresses` (in targets) | `locations` |
| `optional` (in server_tls) | Split into two explicit targets (auto-migrated) |
