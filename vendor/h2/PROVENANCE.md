# h2 Source Provenance

This directory contains the source, examples, benches, manifests, README,
changelog, and MIT license from the published `h2 0.4.19` crate.

- Upstream: https://github.com/hyperium/h2
- Revision: `d57d1b852fec9dda6d42d3454502006d52104da8`
- Crate SHA-256: `ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16`
- Rust minimum supported version: 1.63 (tobaru requires 1.88).

Registry cache markers, the upstream development lockfile, contribution guide,
and GitHub configuration are omitted. The initial import is otherwise unchanged.
Local receive-validation fixes are maintained as separate commits. Do not edit
the Cargo registry copy or replace this dependency with upstream 0.4.19: it loses
pseudoheaders and oversize information when exposing trailers to applications.

Local changes:

- `src/proto/streams/recv.rs`: reject oversized or pseudo-header-bearing trailers
  with `PROTOCOL_ERROR` before receive-side closure and conversion to regular fields.
- `src/server.rs`: reject raw `:path` fragments before `http::Uri` can discard them.

The application depends directly on this path without a registry version.
Cargo removes `[patch.crates-io]` overrides when packaging; a versioned fallback
would silently restore the unpatched library. The unversioned path intentionally
blocks `cargo package` and `cargo publish`. Source installs and release-binary
builds remain supported. Restore registry publishing only after a released h2
version contains equivalent fixes and passes the regression corpus.

Before replacing this source, run `cargo test --locked http::h2::tests::wire`
against the replacement as well as the full test suite and HTTP/2 smoke test.
The raw-wire corpus covers request and response trailers, pre-normalization
request targets, framing, cancellation, and sibling isolation.
