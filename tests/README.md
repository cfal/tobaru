# HTTP Smoke Tests

The Rust suite includes deterministic protocol tests and local TCP, Unix, and
TLS session tests:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked
```

The CLI smoke test starts the actual binary with a temporary configuration and
uses Node's standard HTTP implementation as its peer. Node 22 or newer is
required; no npm packages are needed.

```sh
CARGO_BUILD_JOBS=1 cargo build --release --locked
node tests/http_smoke.mjs target/release/tobaru
node tests/http2_smoke.mjs target/release/tobaru
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
