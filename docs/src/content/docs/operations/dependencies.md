---
title: HTTP/2 dependency
---

HTTP/2 receive validation uses our [h2 fork](https://github.com/cfal/h2/tree/tobaru-receive-validation-2026-11-20),
pinned to commit `6d1f3d6e44aca39ce977feeb7f08fa686cd28e8f` in `Cargo.toml` and
`Cargo.lock`. It rebases the four patches from the previous pin
`d5f47a4fe3f400c94ed0d9e3cfc58f1e5e1a8721`, based on upstream
`e64c1662ebb14794fc19cbcbb5b5dd0f67925f27`, onto
[`4beb4842cf353b98e7238092e6e5685e98d97a65`](https://github.com/hyperium/h2/commit/4beb4842cf353b98e7238092e6e5685e98d97a65),
the upstream development tip checked on 2026-11-20. All four patches are retained
without semantic changes, including the inclusive header-list limit correction.

This is still `h2 0.4.20`, now with seven unreleased upstream commits. The five
new commits fix released receive credit after a window shrink, preserve a peer's
non-success GOAWAY reason over later transport errors when no streams remain,
avoid indexed HPACK encoding of sensitive fields matching a dynamic-table entry,
size header-map preallocation from recent field counts (capped at 64), and add an
upstream PR-description check. The earlier END_STREAM-preservation fix and
early-response cancellation regression coverage remain included. Active-stream
I/O errors are not hidden by GOAWAY, and Tobaru does not automatically replay
rejected requests.

The HPACK encoder fix protects values already marked sensitive, but Tobaru does
not mark forwarded or generated values sensitive. The upstream decoder still
discards incoming never-indexed metadata, so this update does not change Tobaru's
current output or establish end-to-end never-indexed preservation through
forwarding. That is an existing limitation, not a new regression.

The fork rejects pseudoheaders in trailers, oversized trailer sections, and
raw `:path` fragments. Trailer checks apply only while the receive side is still
streaming; other states retain upstream's state validation, including connection
`GOAWAY(PROTOCOL_ERROR)` for unexpected HEADERS after request END_STREAM.
Valid exact-limit trailers are retained in full; one-byte-over sections are
rejected according to the configured receive policy. The shared decoder also
applies the inclusive boundary to initial headers and PUSH_PROMISE; its larger
abuse thresholds remain unchanged. The fork retains upstream's MIT license and
expanded request/response, HPACK recovery, and PUSH_PROMISE regression tests.
Upstream submissions [#987](https://github.com/hyperium/h2/pull/987),
[#988](https://github.com/hyperium/h2/pull/988), and
[#989](https://github.com/hyperium/h2/pull/989) remain open as of that check.
The latest non-yanked release, `0.4.20`, does not contain these patches.
No stable public API, dependency feature, or Tobaru MSRV change is required.
The unsupported `unstable` feature's HEADERS/PUSH_PROMISE loaders gain a capacity
argument; Tobaru does not use those APIs.

Keep `tobaru-receive-validation-2026-11-20`, `tobaru-receive-validation-2026-10-31`, and the original
`tobaru-receive-validation-tip` branch reachable while their revisions are pinned;
do not rewrite or delete their only branch or tag.

The Git dependency deliberately has no registry-version fallback. This supports
source installs and release binaries, but blocks `cargo package` and
`cargo publish` rather than allowing Cargo to substitute an unpatched registry
release. Restore registry publishing only after a released dependency includes
equivalent fixes and passes the fork's receive-validation regressions, including
stream-state error ordering, plus Tobaru's raw-wire corpus, full suite, and HTTP/2
smoke test.
