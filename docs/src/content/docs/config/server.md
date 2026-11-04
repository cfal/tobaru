---
title: Listeners
---

```yaml
address: "0.0.0.0:8080"           # Bind address (required)

transport: tcp | udp               # Default: tcp

# TCP-specific settings (only when transport: tcp)
tcp_nodelay: true                  # Disable Nagle's algorithm (default: true)
tcp_keepalive: true | false | null | { idle_secs: int, interval_secs: int }
tcp_max_connections: null          # No cap by default; positive integer enables it

use_iptables: false                # Auto-configure iptables rules (default: false)

# One or more targets
target: TcpTargetConfig            # Single target
targets: [TcpTargetConfig]         # Multiple targets
```

This is a schema sketch, not runnable YAML. UDP listeners use [UDP targets](/config/udp/)
instead and accept `udp_max_associations` and `udp_queue_capacity`. Listener
addresses accept an IP literal or hostname with a port. Hostnames are resolved
during configuration loading. Use bracketed IPv6.

`tcp_max_connections` counts accepted connections across reload generations of
the same bind address, including TLS detection and handshakes. At capacity, new
connections are closed. Lowering the cap does not evict existing connections.
See [listener resources](/operations/limits/#listener-resources) for sizing.

## Address Format

```yaml
address: "0.0.0.0:8080"           # IPv4
address: "[::]:8080"              # IPv6
```

## TCP Keepalive

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

## iptables Integration

When `use_iptables: true`, tobaru automatically configures iptables/ip6tables rules to drop packets from IPs not in the allowlist at the kernel level, before they reach the application.

Requires root or `CAP_NET_RAW` + `CAP_NET_ADMIN` capabilities. Supported on Linux only.

```bash
# Clear all tobaru-managed iptables rules
sudo tobaru --clear-iptables-all

# Clear rules for specific config files only
sudo tobaru --clear-iptables-matching config.yaml
```
