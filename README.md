# tobaru

Advanced port forwarding tool written in Rust with powerful routing and TLS features:

## Key Features

- **Multiple routing strategies**: Route connections based on IP address, TLS SNI (with wildcard support), ALPN protocol, or HTTP path
- **Flexible TLS handling**:
  - **Passthrough mode**: Route TLS by SNI/ALPN without decryption (zero overhead, no private keys needed)
  - **Terminate mode**: Decrypt TLS and route based on SNI/ALPN or HTTP content
  - Mix both modes on the same port
  - Client certificate pinning (SHA256 fingerprint validation)
  - Server certificate pinning (SHA256 fingerprint validation)
- **HTTP proxy features**:
  - Path-based routing with prefix matching
  - Serve static files from directories
  - Serve custom responses with configurable status codes
  - Header manipulation (add/remove/modify headers)
  - WebSocket support with automatic upgrade handling
  - Connection keep-alive support
- **Hot reloading**: Config changes are automatically detected and applied
- **iptables integration**: Automatically configure firewall rules for IP allowlists
- **IP groups**: Reusable named groups of IP ranges
- **High performance**: Async I/O with Tokio, minimal allocations

## Quick Example

```yaml
# Simple TLS passthrough routing by SNI
- address: 0.0.0.0:443
  transport: tcp
  targets:
    # Route api.example.com without decryption
    - location: api-backend:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: api.example.com

    # Route www.example.com to different backend
    - location: web-backend:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: www.example.com
```

## Installation

### Pre-compiled Binaries

Download from [GitHub Releases](https://github.com/cfal/tobaru/releases) for:
- Linux x86_64
- macOS Apple Silicon (aarch64)

### Build from Source

Requires Rust 1.88+ and cargo:

```bash
cargo install tobaru
```

## Usage

```
USAGE:
    tobaru [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] [..]

OPTIONS:
    -t, --threads NUM           Number of worker threads (default: auto-detected)
    --dry-run                  Validate config, routing, and TLS files without binding listeners
    --clear-iptables-all        Clear all tobaru iptables rules and exit
    --clear-iptables-matching   Clear iptables rules for specified configs and exit
    -h, --help                  Show help

EXAMPLES:
    # Run with config file
    tobaru config.yaml

    # Run with multiple configs
    tobaru servers.yaml ip_groups.yaml

    # Simple TCP forwarding via URL
    tobaru tcp://127.0.0.1:8080?target=192.168.1.10:80

    # Clear iptables rules
    sudo tobaru --clear-iptables-matching config.yaml
```

## Configuration

See [CONFIG.md](./CONFIG.md) for the complete YAML configuration reference.

### TLS Passthrough Mode

Route TLS connections by SNI/ALPN without decryption - no private keys needed on the proxy:

```yaml
- address: 0.0.0.0:443
  transport: tcp
  targets:
    # Route api.example.com to backend1 (passthrough - no cert/key needed!)
    - location: backend1:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: api.example.com
        alpn_protocols:
          - h2
          - http/1.1

    # Route www.example.com to backend2
    - location: backend2:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: www.example.com
```

**Benefits:**
- No decryption/re-encryption overhead
- No private keys needed on proxy (improved security)
- Near-zero latency routing
- Full end-to-end encryption preserved

### TLS Terminate Mode

Decrypt TLS and route based on content:

```yaml
- address: 0.0.0.0:443
  transport: tcp
  targets:
    - location: backend:8080
      allowlist: 0.0.0.0/0
      server_tls:
        mode: terminate  # or omit mode (terminate is default)
        cert: app.crt
        key: app.key
        sni_hostnames: app.example.com
        alpn_protocols:
          - h2
          - http/1.1
```

### HTTP Proxy with Path Routing

```yaml
- address: 0.0.0.0:80
  transport: tcp
  target:
    allowlist: 0.0.0.0/0
    http_paths:
      # Serve static files
      /static/:
        http_action:
          type: serve-directory
          path: /var/www/static

      # Custom redirect
      /redirect:
        http_action:
          type: serve-message
          status_code: 302
          response_headers:
            Location: https://example.com

      # Forward to backend
      /api/:
        http_action:
          type: forward
          addresses:
            - backend:8080

    # Default for unmatched paths
    default_http_action:
      type: forward
      addresses:
        - default-backend:8080
```

### HTTP/2

HTTP ingress and backend protocol selection are independent. HTTP targets accept
both HTTP/1 and HTTP/2 by default (`http_protocols: [http1, http2]`). Plaintext
connections select H2 on the first four bytes `PRI `, otherwise H1. TLS uses
negotiated ALPN instead of sniffing. When the TLS ALPN setting is omitted, HTTP
targets derive `[h2, http/1.1, none]`, allowing both protocols and no-ALPN H1 clients:

```yaml
- address: 0.0.0.0:8443
  transport: tcp
  target:
    allowlist: 0.0.0.0/0
    server_tls:
      cert: server.crt
      key: server.key
    default_http_action:
      type: forward
      upstream_protocol: http2
      location:
        address: backend.example:443
        client_tls: true
```

Explicit TLS ALPN settings remain authoritative and must agree with
`http_protocols`. Other negotiated ALPN values retain the legacy HTTP/1 dispatch
behavior when H1 is enabled; use standard HTTP ALPN names for new deployments.
Set `http_protocols: [http1]` or `[http2]` to restrict ingress to one protocol.
H2-only TLS derives `[h2]` and requires negotiation; TLS without ALPN never sniffs.

`upstream_protocol` is `http1` (default) or `http2`, per forward action. HTTP/2 TLS
backends advertise and require exactly `h2`; omit the client's ALPN setting or set
it to `[h2]`. Existing certificate verification, pins, client certificates and SNI
settings still apply. There is no fallback or automatic request replay.

The old `http2.prior_knowledge` option is replaced by `http_protocols: [http2]`.
Mixed plaintext listeners buffer at most four new bytes for detection, replay
them unchanged, and let the selected handler validate the rest. Invalid H2
prefaces close the connection without fallback. The reserved `PRI` method is not
available as an H1 extension on mixed plaintext listeners; longer methods such
as `PRINT` remain H1. Detection has an absolute timeout, default 10 seconds, so
partial prefixes cannot hold a connection indefinitely. `Upgrade: h2c` remains
unsupported. A cleartext HTTP/2 backend uses prior knowledge over TCP or a Unix
socket, selected by `upstream_protocol: http2` without `client_tls`.

Enabling H2 also validates local response configuration for H2 compatibility.
Targets relying on H1-only local statuses or connection-specific headers must
explicitly select `[http1]`.

All three new forwarding paths (H2 to H1, H1 to H2, H2 to H2) stream bodies,
informational responses and trailers. H2 to H2 supports bidirectional streaming.
Repeated fields remain separate; binary field values are supported except through
the existing text-based H1 ingress parser. Cross-version forwarding rejects
ambiguous lengths, unsupported transfer codings, framing-changing header patches,
and conflicting Host/authority. H1 output uses chunking when trailers might follow.
Host patches change outgoing authority, not backend TLS identity. The logical
request scheme is preserved independently of the backend transport.

H2 backend connections are reused within one frontend connection and forward
action, never globally or across actions. Round-robin advances on each physical
backend connection, not each request. H2-to-H1 exchanges use dedicated H1 backend
connections. GOAWAY retires an H2 backend; a request racing retirement may fail
without being replayed. Local responses end one stream; the `close` action still
closes the entire frontend connection, including siblings.

HTTP/2 receive validation uses a [locally patched h2 dependency](vendor/h2/PROVENANCE.md).
This branch supports source installs and release binaries; registry packaging is
blocked until a published dependency incorporates the fixes, so Cargo cannot
silently replace the patched code.
Malformed or oversized trailer sections and raw request-target fragments are
rejected before the library can discard their validation metadata. Failed H1
uploads never receive a synthesized terminal chunk and their backend sockets
are not reused.

Run `cargo test --locked http::h2::tests::wire` for the raw H2/HPACK adversarial
corpus, then `node tests/http2_smoke.mjs target/release/tobaru` against a built
binary for independent Node HTTP/1 and HTTP/2 interoperability checks. Both run
in CI (the smoke uses the debug binary). Rerun them on dependency upgrades;
regression coverage is not a substitute for fuzzing or a security audit.

Optional `http2` settings and defaults:

| Setting | Default | Scope |
| --- | --- | --- |
| `max_concurrent_streams` | 64 | Each ingress H2 connection |
| `max_connections` | 256 | Ingress H2 connections per target/generation, after TLS |
| `max_backend_connections` | 256 | Separate target-wide limits on new-path transports and active exchanges |
| `max_header_list_size` | 65536 | Decoded header/trailer bytes |
| `header_timeout_secs` | 10 | Plaintext detection and incomplete frame/header-block deadlines |
| `connect_timeout_secs` | 10 | Backend setup and ingress H2 handshake |
| `body_progress_timeout_secs` | 30 | Exchange inactivity, shared by upload and response |
| `drain_timeout_secs` | 5 | H2 connection drain after reload or idle expiry |

Limits must be positive; streams are capped at 4096, connection limits at 65536,
header limits at 1024 through 1048576 bytes, and H2 timeouts at 86400 seconds.
Each frontend retains at most 16 live H2 backend connections, including draining
ones. Other fixed bounds include 128 fields per section, 16 informational responses,
64 KiB stream/1 MiB connection receive windows and 16 KiB forwarding chunks.
Excess work fails rather than accumulating an unbounded admission queue.

On new paths, default response-header timeout is 30 seconds after upload completion;
waiting for Expect's 100/final response is also bounded by 30 seconds. Explicit
`http_timeouts.response_header_timeout_secs` instead starts with response processing
and stays absolute across informational responses, as on the H1 path. Explicit
request-header and idle timeouts override H2 defaults. Idle means no live streams,
with a 60-second default. Partial-frame timeouts close the connection, not just a
stream. Listener reload sends GOAWAY and bounds each H2 owner's drain; established
H1/raw sessions retain their existing reload behavior.

CONNECT, extended CONNECT/WebSocket, server push and H3 are not implemented on these
new paths. Existing H1-to-H1 Upgrade handling is unchanged; H1 Upgrade requests
directed to H2-only backends are rejected. Local H2 actions require a final status
(at least 200); custom H1 reason phrases do not appear on the H2 wire.

### Mixed TLS Modes on Same Port

```yaml
- address: 0.0.0.0:443
  transport: tcp
  targets:
    # Passthrough: public API (no keys needed)
    - location: api-backend:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: api.example.com

    # Terminate: admin panel (decrypt and inspect)
    - location: admin-backend:8080
      allowlist:
        - 10.0.0.0/8      # Internal network only
      server_tls:
        mode: terminate
        cert: admin.crt
        key: admin.key
        sni_hostnames: admin.example.com
```

### Wildcard SNI Matching

Route all subdomains of a domain to a single backend:

```yaml
- address: 0.0.0.0:443
  transport: tcp
  targets:
    # *.example.com matches foo.example.com, bar.example.com, etc.
    # but NOT example.com itself
    - location: wildcard-backend:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: "*.example.com"

    # .example.com matches example.com AND all subdomains
    - location: dot-backend:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: ".other.com"

    # Exact match takes priority over wildcards
    - location: api-backend:443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: passthrough
        sni_hostnames: api.example.com
```

Matching priority: exact match > deepest wildcard > shallower wildcard > no match.

### Host Header Routing

Route HTTP requests by the `Host` header, with the same wildcard pattern support as SNI matching. When the `host` key is used in `required_request_headers`, values are automatically treated as hostname patterns:

```yaml
- address: 0.0.0.0:80
  transport: tcp
  target:
    allowlist: 0.0.0.0/0
    http_paths:
      /:
        # Route app.example.com to the app backend
        - required_request_headers:
            host: app.example.com
          http_action:
            type: forward
            addresses:
              - app-backend:8080

        # Route all *.api.example.com subdomains to the API backend
        - required_request_headers:
            host: "*.api.example.com"
          http_action:
            type: forward
            addresses:
              - api-backend:8080

    default_http_action:
      type: serve-message
      status_code: 404
```

The same patterns are supported: `example.com` (exact), `*.example.com` (subdomains only), `.example.com` (base domain + subdomains), and `*` (catch-all). Port suffixes in the `Host` header (e.g. `example.com:8080`) are stripped before matching.

**Note:** When possible, prefer routing by SNI (`sni_hostnames`) over `Host` header matching. SNI routing operates at the TLS layer before any HTTP parsing, making it more efficient. Host header routing is useful for plain HTTP, or when multiple virtual hosts share the same TLS certificate.

### Client Certificate Pinning

Authenticate clients using SHA256 certificate fingerprints (no CA needed):

```yaml
- address: 0.0.0.0:8443
  transport: tcp
  targets:
    - location: secure-backend:8443
      allowlist: 0.0.0.0/0
      server_tls:
        mode: terminate
        cert: server.crt
        key: server.key
        sni_hostnames: secure.example.com
        # Only allow these client certificate fingerprints
        client_fingerprints:
          - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
          - "1122334455667788990011223344556677889900112233445566778899001122" # colons optional
```

**Generate client certificate and get fingerprint:**
```bash
# Generate key
openssl ecparam -genkey -name prime256v1 -out client.key

# Create self-signed certificate
openssl req -new -x509 -nodes -key client.key -out client.crt -days 365 -subj "/CN=Client"

# Get SHA256 fingerprint
openssl x509 -in client.crt -noout -fingerprint -sha256
```

### Outgoing TLS with Server Certificate Pinning

Connect to upstream TLS servers and pin their certificates:

```yaml
- address: 0.0.0.0:8080
  transport: tcp
  targets:
    - allowlist: 0.0.0.0/0
      locations:
        - address: upstream.example.com:443
          client_tls:
            # Verify server certificate via WebPKI (default: true)
            verify: true

            # Pin server certificate by SHA256 fingerprint
            server_fingerprints:
              - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

            # Present client certificate for authentication
            key: client.key
            cert: client.crt

            # Custom SNI hostname (default: derive from address)
            sni_hostname: custom.example.com
            # Or disable SNI: sni_hostname: null

            # ALPN protocols to negotiate
            alpn_protocols:
              - h2
              - http/1.1
```

**Get server certificate fingerprint:**
```bash
# Fetch certificate
openssl s_client -connect example.com:443 < /dev/null 2>/dev/null | openssl x509 -outform PEM > server.crt

# Get SHA256 fingerprint
openssl x509 -in server.crt -noout -fingerprint -sha256
```

### IP-Based Routing

```yaml
- address: 0.0.0.0:8080
  transport: tcp
  targets:
    # Internal network → backend1
    - location: backend1:8080
      allowlist:
        - 192.168.1.0/24
        - 10.0.0.0/8

    # Specific IPs → backend2
    - location: backend2:8080
      allowlist:
        - 1.2.3.4
        - 2001:db8::1

    # Everyone else → backend3
    - location: backend3:8080
      allowlist: 0.0.0.0/0
```

### IP Groups

Define reusable IP groups:

```yaml
# Define IP groups
- group: internal
  ip_masks:
    - 192.168.0.0/16
    - 10.0.0.0/8

- group: trusted
  ip_masks:
    - 1.2.3.4
    - 5.6.7.8

# Use IP groups in servers
- address: 0.0.0.0:8080
  transport: tcp
  target:
    location: backend:8080
    allowlist:
      - internal
      - trusted
```

### Load Balancing (Round-Robin)

```yaml
- address: 0.0.0.0:8080
  transport: tcp
  target:
    # Distribute across multiple backends
    locations:
      - backend1:8080
      - backend2:8080
      - backend3:8080
      - backend4:8080
    allowlist: 0.0.0.0/0
```

### iptables Integration

Automatically configure firewall rules:

```yaml
- address: 0.0.0.0:8080
  transport: tcp
  use_iptables: true  # Enable iptables auto-configuration
  target:
    location: backend:8080
    allowlist:
      - 192.168.1.0/24
      - 10.0.0.0/8
    # Packets from other IPs will be dropped by iptables
```

**Note:** Requires root or `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.

### UDP Forwarding

```yaml
- address: 0.0.0.0:53
  transport: udp
  target:
    addresses:
      - 8.8.8.8:53
      - 8.8.4.4:53
    allowlist: 0.0.0.0/0
    # Optional: association timeout in seconds (default: 200)
    association_timeout_secs: 300
```

### UNIX Domain Sockets

```yaml
- address: 0.0.0.0:8080
  transport: tcp
  target:
    # Forward to UNIX socket
    location:
      path: /run/app.sock
    allowlist: 0.0.0.0/0
```

## Configuration Format

Supports both **YAML** and **JSON** formats. Config is an array of objects, where each object is either:
- A server configuration (`address` + `transport` + `target`/`targets`)
- An IP group definition (`group` + `ip_masks`)

### Server Configuration Fields

**Required fields:**
- `address`: The address to listen on (e.g., `0.0.0.0:443`)
- `transport`: Either `tcp` or `udp`
- `target` or `targets`: Single target or array of targets

**Optional fields:**
- `use_iptables`: Enable iptables rules (default: `false`)
- `tcp_nodelay`: Disable Nagle's algorithm (default: `true`, TCP only)

### Target Configuration Fields

**For TCP targets:**

**Location** (one of):
- `location`: Single address string (e.g., `backend:8080`)
- `locations`: Array of addresses for round-robin
- `location` with object form:
  - `address`: TCP address
  - `path`: UNIX socket path
  - `client_tls`: Outgoing TLS config (see below)

**Required:**
- `allowlist`: IP mask, IP group name, or array of either (e.g., `0.0.0.0/0`, `["internal", "1.2.3.4"]`)

**Optional TLS:**
- `server_tls`: Incoming TLS configuration
  - `mode`: `passthrough` or `terminate` (default: `terminate`)
  - `cert`: Path to certificate file (required for `terminate`)
  - `key`: Path to private key file (required for `terminate`)
  - `sni_hostnames`: Single hostname, wildcard pattern, or array (or `any`, `none`)
    - `example.com` -- exact match only
    - `*.example.com` -- matches any subdomain, but not `example.com` itself
    - `.example.com` -- matches both `example.com` and any subdomain
  - `alpn_protocols`: Single protocol or array (or `any`, `none`)
  - `client_fingerprints`: Array of SHA256 fingerprints for client certificate pinning

**Optional HTTP:**
- `http_protocols`: Ingress allowlist, default `[http1, http2]`; one protocol disables plaintext detection
- `http_paths`: Map of path prefixes to HTTP actions
  - Each path can have one or more configs with `required_request_headers` and `http_action`
  - `required_request_headers`: Map of header names to expected values (keys are case-insensitive)
    - The `host` key supports wildcard patterns: `*.example.com`, `.example.com`, `*`
- `default_http_action`: Fallback HTTP action

**Client TLS configuration (`client_tls`):**
- `verify`: Verify server certificate (default: `true`)
- `key`: Path to client private key (for client certificate auth)
- `cert`: Path to client certificate (for client certificate auth)
- `sni_hostname`: SNI hostname to send (default: derive from address, or `null` to disable)
- `alpn_protocols`: Array of ALPN protocols to negotiate
- `server_fingerprints`: Array of SHA256 fingerprints for server certificate pinning

## URL-Based Configuration

For simple TCP forwarding, use URL format:

```bash
# TCP forwarding
tobaru tcp://127.0.0.1:8080?target=192.168.1.10:80

# Forward to UNIX socket
tobaru tcp://127.0.0.1:8080?target-path=/run/app.sock
```

## Hot Reload

Config files are automatically watched and reloaded when changed. No restart needed!

## Advanced Examples

See the [examples](examples/) directory for complete working configurations:
- [`sni_passthrough.yml`](examples/sni_passthrough.yml) - TLS passthrough routing examples
- [`wildcard_sni.yml`](examples/wildcard_sni.yml) - Wildcard SNI hostname matching
- [`host_header_routing.yml`](examples/host_header_routing.yml) - HTTP Host header virtual hosting
- [`bookmarks.yml`](examples/bookmarks.yml) - HTTP path-based routing for URL bookmarks

## Performance

- **Async I/O**: Built on Tokio for high concurrency
- **Zero-copy**: Efficient buffer management with minimal allocations
- **Passthrough mode**: Near-zero overhead TLS routing
- **Connection pooling**: HTTP keep-alive support

## Upgrading

See [UPGRADING.md](UPGRADING.md) for migration guides from older versions.

## License

MIT
