# tobaru

Advanced port forwarding tool written in Rust with powerful routing and TLS features:

## Key Features

- **🔀 Multiple routing strategies**: Route connections based on IP address, TLS SNI, ALPN protocol, or HTTP path
- **🔒 Flexible TLS handling**:
  - **Passthrough mode**: Route TLS by SNI/ALPN without decryption (zero overhead, no private keys needed)
  - **Terminate mode**: Decrypt TLS and route based on SNI/ALPN or HTTP content
  - Mix both modes on the same port
  - Client certificate pinning (SHA256 fingerprint validation)
  - Server certificate pinning (SHA256 fingerprint validation)
- **🌐 HTTP proxy features**:
  - Path-based routing with prefix matching
  - Serve static files from directories
  - Serve custom responses with configurable status codes
  - Header manipulation (add/remove/modify headers)
  - WebSocket support with automatic upgrade handling
  - Connection keep-alive support
- **🔥 Hot reloading**: Config changes are automatically detected and applied
- **🛡️ iptables integration**: Automatically configure firewall rules for IP allowlists
- **📦 IP groups**: Reusable named groups of IP ranges
- **⚡ High performance**: Async I/O with Tokio, minimal allocations

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

Requires Rust 1.70+ and cargo:

```bash
cargo install tobaru
```

## Usage

```
USAGE:
    tobaru [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] [..]

OPTIONS:
    -t, --threads NUM           Number of worker threads (default: auto-detected)
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
- ✅ No decryption/re-encryption overhead
- ✅ No private keys needed on proxy (improved security)
- ✅ Near-zero latency routing
- ✅ Full end-to-end encryption preserved

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
  - `sni_hostnames`: Single hostname or array (or `any`, `none`)
  - `alpn_protocols`: Single protocol or array (or `any`, `none`)
  - `client_fingerprints`: Array of SHA256 fingerprints for client certificate pinning

**Optional HTTP:**
- `http_paths`: Map of path prefixes to HTTP actions
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
