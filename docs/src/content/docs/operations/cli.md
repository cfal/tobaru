---
title: CLI and reload
---

```
tobaru [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] ...
tobaru [OPTIONS] static [STATIC OPTIONS] [DIRECTORY]

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
old listener tasks before rebinding, so reload is not gapless. Existing non-tunnel TCP
sessions keep their old configuration until completion; UDP associations restart.
Unexpected listener errors or panics exit the process nonzero. Bind and firewall
failures also exit nonzero, including during reload. `--dry-run` does not verify
that ports can be bound or firewall commands can succeed.

Every successfully prepared reload closes all reverse-tunnel transports, including
active streams, even for unrelated edits or unchanged saves. Invalid reloads leave
them running. See [tunnel lifecycle and limits](/operations/limits/#reverse-tunnels).

## Static File Server

`tobaru static` serves files from the current directory at `http://127.0.0.1:8080/`,
without a configuration file. An optional directory replaces the current directory.
The root must exist and be a directory; invalid roots fail at startup.

```sh
tobaru static
tobaru static -p 9000 -c 0 ./dist
tobaru static -a 0.0.0.0 -p 8080
tobaru -t 1 static --dry-run ./dist
```

| Option | Meaning |
|--------|---------|
| `-a`, `--address IP` | IPv4 or IPv6 literal; default `127.0.0.1`. Use `::1` for IPv6 loopback. Hostnames are not resolved. |
| `-p`, `--port PORT` | Port from 0 through 65535; default 8080. Zero requests an available port. |
| `-c`, `--cache SECONDS` | Nonnegative integer `Cache-Control` max-age in seconds; default 3600, like `static`/node-static. Zero sends `max-age=0`. |
| `-t`, `--threads NUM` | Worker threads, as in configuration mode. |
| `--dry-run` | Validate the directory and HTTP setup without binding a listener. |
| `-h`, `--help` | Show static-server help. |
| `--` | End options; useful for directory names beginning with `-`. |

Options take separate values, for example `--cache 60`. Global `-t` and
`--dry-run` may appear before or after `static`. Only one directory is accepted;
configuration files/URLs and `--clear-iptables-*` cannot be combined with this mode.
`static` is recognized only as the first positional argument. To load a configuration
file literally named `static`, use `tobaru ./static`.

The listener supports HTTP/1.1 and plaintext HTTP/2 prior knowledge using the
existing [serve-directory action](/http/actions/#serve-directory). GET and HEAD
serve files with MIME detection; directories serve `index.html`. Missing files
and directories without an index return 404 with a `Not Found` body and
`Content-Type: text/plain`; HEAD omits the body. There are no directory listings,
SPA fallbacks, or trailing-slash redirects; use `/subdir/` when opening a directory
index whose assets use relative URLs.

Cache headers apply to successful file responses, including HEAD and directory
indexes. `-c 0` makes responses immediately stale, which is useful during development;
it does not prohibit storage. This shortcut does not add ETag, Last-Modified, or
conditional 304 responses. Files are opened on each request, so edits need no
restart, but browsers may retain fresh responses until the configured max-age
expires. No configuration watcher is started.

The `Listening (TCP): ADDRESS` line appears only after a successful bind and reports
the actual port, including when `-p 0` was used. An occupied port fails with a nonzero
exit rather than silently selecting another port. Stop the server with Ctrl-C.

Non-loopback addresses warn but are honored. All source addresses are allowed,
with no authentication, TLS, or built-in firewall rules. Every readable file
inside the root, including `.env` and `.git` contents, may be served. Only expose
trusted directories; the existing canonical containment checks do not eliminate
concurrent symlink-replacement races. Use configuration files for access controls
or TLS.

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
file to prepare new TLS settings. Surviving sessions retain the previous settings.
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
