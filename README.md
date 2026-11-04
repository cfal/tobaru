# tobaru

Port forwarding in Rust with TCP and UDP listeners, source-IP allowlists,
TLS SNI/ALPN routing, TLS termination, and HTTP/1 and HTTP/2 forwarding.
Targets can use TCP or UNIX sockets, round-robin backends, and optional outgoing
TLS. Configuration files are watched for reloads.

**[Documentation](https://tobaru-rs.github.io/)** |
[Installation](https://tobaru-rs.github.io/start/installation/) |
[Configuration](https://tobaru-rs.github.io/start/configuration-model/) |
[Examples](https://tobaru-rs.github.io/start/examples/)

The site currently documents **dev**, not a stable release. Its header links to
the exact source revision. Documentation source lives in [`docs/`](docs/README.md)
and is published by [tobaru-rs.github.io](https://github.com/tobaru-rs/tobaru-rs.github.io).

## Install

Download a binary from [GitHub Releases](https://github.com/cfal/tobaru/releases),
or build this checkout with Rust 1.88 or newer:

```sh
CARGO_BUILD_JOBS=1 cargo install --locked --path .
```

This preserves the pinned HTTP/2 fork's validation fixes. The initial build needs
GitHub access. `cargo install tobaru` installs an older crates.io release, not
this development revision. See [dependency details](https://tobaru-rs.github.io/operations/dependencies/).

## Start

Run the self-contained loopback example from this checkout:

```sh
tobaru --dry-run examples/first-config.yml
tobaru examples/first-config.yml
```

Then request `http://127.0.0.1:8080/`. See the
[first configuration](https://tobaru-rs.github.io/start/first-config/) for details.
For an existing service on port 9000:

```sh
tobaru 'tcp://127.0.0.1:8080?target=127.0.0.1:9000'
```

Use YAML for explicit allowlists, TLS, HTTP routes, and resource limits. Review
[target precedence](https://tobaru-rs.github.io/config/tcp/#target-evaluation-order)
and [deployment contracts](https://tobaru-rs.github.io/operations/limits/) before
exposing a listener. A broad raw target permits unmatched TLS; an allowlist on
another target does not deny that fallback access.

## Reference

- [Listeners](https://tobaru-rs.github.io/config/server/), [TCP](https://tobaru-rs.github.io/config/tcp/), and [UDP](https://tobaru-rs.github.io/config/udp/)
- [Incoming TLS](https://tobaru-rs.github.io/tls/server/) and [outgoing TLS](https://tobaru-rs.github.io/tls/client/)
- [HTTP routing](https://tobaru-rs.github.io/http/routing/), [actions](https://tobaru-rs.github.io/http/actions/), and [HTTP/2](https://tobaru-rs.github.io/http/http2/)
- [CLI and reload](https://tobaru-rs.github.io/operations/cli/), [limits](https://tobaru-rs.github.io/operations/limits/), and [upgrading](https://tobaru-rs.github.io/operations/upgrading/)
- [Tests](tests/README.md) and [documentation development](docs/README.md)

## License

[MIT](LICENSE)
