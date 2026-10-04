# HTTP Smoke Test

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
```

Omitting the argument selects `target/release/tobaru` relative to the repository.
With a custom `CARGO_TARGET_DIR`, pass that directory's binary explicitly.
Temporary listeners use ephemeral ports and localhost-only allowlists. Fixtures
are created beneath `$HOME/tmp` and removed on completion or failure. The test
has a 15-second deadline and cleans up its child process and sockets.
