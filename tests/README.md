# Protocol Tests

The Rust suite includes deterministic protocol tests and local TCP, Unix, and
TLS session tests:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked
```

Configuration watcher tests cover atomic replacement, symlink retargeting, and
reusing recreated target directories. CI also runs these tests on native macOS
to exercise the FSEvents backend:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked lifecycle::tests::config_watches_
```

The CLI smoke test starts the actual binary with a temporary configuration and
uses Node's standard HTTP implementation as its peer. Node 22 or newer is
required; no npm packages are needed.

```sh
CARGO_BUILD_JOBS=1 cargo build --release --locked
node tests/http_smoke.mjs target/release/tobaru
node tests/http2_smoke.mjs target/release/tobaru
node tests/tcp_routing_smoke.mjs target/release/tobaru
```

Omitting the argument selects `target/release/tobaru` relative to the repository.
With a custom `CARGO_TARGET_DIR`, pass that directory's binary explicitly.
Temporary listeners use ephemeral ports and localhost-only allowlists. Fixtures
are created beneath `$HOME/tmp` and removed on completion or failure. The test
has a 30-second deadline and cleans up its child process and sockets. It also
checks that invalid reloads retain the last-good configuration and repeated
atomic file replacements remain observable.
Listener-failure checks cover occupied ports and TCP accept failure under a
child-local file-descriptor limit; both must exit nonzero without panicking.

The HTTP/2 test additionally requires `openssl` for ephemeral certificates. Its
independent Node HTTP/2 peers cover default plaintext H1/H2 detection, protocol
allowlists, derived and explicit TLS ALPN (including empty/null lists), competing
TLS targets selected by source IP/SNI/ALPN, optional-TLS read-ahead replay,
no-ALPN H1 fallback, rejection of invalid prefaces without fallback, H2-to-H1 and
H1-to-H2 translation, H2-to-H2 duplex progress, withheld Expect uploads, 100/103,
repeated cookies, request/response trailers, backend reuse, Unix prior knowledge,
outbound pins and CA verification failures, inbound and outbound mTLS, and rejection
of a backend that cannot negotiate H2. It does not measure Internet-scale throughput
or claim exhaustive RFC conformance.

The TCP routing smoke test also requires `openssl`. It checks the actual CLI's
configuration registration and routing: raw forwarding of unmatched TLS,
specific routes and competing catch-alls, source-IP/SNI/ALPN precedence,
absent SNI/ALPN, fallback across wildcard patterns, plaintext HTTP isolation,
immediate server-first raw overrides, configuration-order ties, and terminal
client-authentication failures. The Rust tests additionally exercise fragmented
and malformed ClientHellos, byte-exact replay after inspection timeouts, IPv6
precedence, and handshake/backend failures without fallback.
Raw replay coverage includes inspection-buffer exhaustion with unread trailing
records, not only rejection of oversized record-length fields. The CLI's
authentication-failure check counts raw backend TCP accepts, including connections
whose TLS handshake never completes. It also verifies that auto-migrated optional
TLS forwarding targets receive unmatched and malformed TLS at their raw backend.

Configuration CLI checks also require `openssl`. Preflight cases use `--dry-run`
without binding listeners. They cover shortcut exposure diagnostics, CIDR
normalization, named groups, overlapping-prefix order, and duplicate-network errors
across raw TCP, TLS passthrough, TLS termination, and UDP. Firewall cases start
ephemeral listeners with stubbed `iptables` and `ip6tables` commands; they check
mapped IPv4 coverage without requiring privileges or changing real firewall rules:

```sh
node tests/config_cli.mjs target/release/tobaru
```
