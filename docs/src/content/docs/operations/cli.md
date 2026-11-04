---
title: CLI and reload
---

```
tobaru [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] ...

OPTIONS:
  -t, --threads NUM           Worker threads (default: auto-detected from CPU count)
  --dry-run                  Validate config, routing, and TLS files without binding listeners
  --clear-iptables-all        Clear all tobaru iptables rules and exit
  --clear-iptables-matching   Clear iptables rules for specified config files and exit
  -h, --help                  Show help
```

Configuration file changes, including atomic replacements, are debounced for
three seconds while current listeners continue serving. Invalid replacement
configuration retains the last-good listeners. Valid replacements stop and await
old listener tasks before rebinding, so reload is not gapless. Existing TCP
sessions keep their old configuration until completion; UDP associations restart.
Unexpected listener errors or panics exit the process nonzero. Bind and firewall
failures also exit nonzero, including during reload. `--dry-run` does not verify
that ports can be bound or firewall commands can succeed.

## Examples

```bash
# Run with a single config file
tobaru config.yaml

# Run with multiple config files (merged together)
tobaru servers.yaml ip_groups.yaml

# Simple TCP forwarding via URL
tobaru 'tcp://127.0.0.1:8080?target=192.168.1.10:80'

# Custom thread count
tobaru --threads 4 config.yaml

# Clear iptables rules
sudo tobaru --clear-iptables-matching config.yaml
sudo tobaru --clear-iptables-all
```

## Hot Reloading

Configuration files are automatically watched for changes and reloaded without restart.

Only configuration paths are watched, not TLS certificate/key files or static
directory contents. After replacing certificate files, update a watched config
file to prepare new TLS settings. Existing sessions retain the previous settings.
URL shortcuts are reconstructed on reload but have no file to watch themselves.

## Logging

`RUST_LOG` controls logging and defaults to `info`:

```sh
RUST_LOG=warn tobaru config.yaml
```

Release builds compile out debug and trace logging. Access logs omit queries,
but paths can still contain sensitive identifiers; configure access controls,
rotation, and retention. See [metadata and logging limits](/operations/limits/#http-metadata-and-logging).

## URL-Based Configuration

For simple forwarding, configs can be specified as URLs on the command line instead of YAML files.

These are `tcp://` and `udp://` forwarding shortcuts, not URLs for downloading
remote configuration files.

```bash
# TCP forwarding
tobaru 'tcp://127.0.0.1:8080?target=192.168.1.10:80'

# Multiple targets (round-robin)
tobaru "tcp://127.0.0.1:8080?target=backend1:80&target=backend2:80"

# Forward to UNIX socket
tobaru 'tcp://127.0.0.1:8080?target-path=/run/app.sock'

# UDP forwarding
tobaru 'udp://127.0.0.1:5353?target=8.8.8.8:53&target=8.8.4.4:53'
```

URL configs use `allowlist: all` (IPv4 and IPv6), disable built-in firewall
handling, and retain unlimited connection/association defaults. Non-loopback
binds warn but are not silently changed. Use YAML for access control and limits.
Quote URLs so shell metacharacters such as `?` and `&` remain part of the argument.

## URL Query Parameters

| Scheme | Parameter | Description |
|--------|-----------|-------------|
| `tcp` | `target` or `target-address` | Backend TCP address |
| `tcp` | `target-path` | Backend UNIX socket path |
| `udp` | `target` or `target-address` | Backend UDP address |
