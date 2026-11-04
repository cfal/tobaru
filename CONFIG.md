# Configuration Reference

The maintained reference is now the [documentation site](https://tobaru-rs.github.io/start/configuration-model/).
Its source lives in [`docs/src/content/docs/`](docs/src/content/docs/).

- [Listeners](https://tobaru-rs.github.io/config/server/), [TCP targets](https://tobaru-rs.github.io/config/tcp/), [UDP](https://tobaru-rs.github.io/config/udp/), and [IP groups](https://tobaru-rs.github.io/config/ip-groups/)
- [Incoming TLS](https://tobaru-rs.github.io/tls/server/) and [outgoing TLS](https://tobaru-rs.github.io/tls/client/)
- [HTTP routing](https://tobaru-rs.github.io/http/routing/), [actions](https://tobaru-rs.github.io/http/actions/), and [HTTP/2](https://tobaru-rs.github.io/http/http2/)
- [CLI and URL shortcuts](https://tobaru-rs.github.io/operations/cli/) and [limits](https://tobaru-rs.github.io/operations/limits/)

## Reverse Tunnels

See [reverse-tunnel configuration](https://tobaru-rs.github.io/config/reverse-tunnels/)
for named TCP/Unix exports, mTLS identities, and public routing.

## Target Evaluation Order

See [target precedence](https://tobaru-rs.github.io/config/tcp/#target-evaluation-order).

## Raw Catch-All

See [raw fallback behavior and access control](https://tobaru-rs.github.io/config/tcp/#raw-catch-all).
