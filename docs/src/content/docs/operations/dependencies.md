---
title: HTTP/2 dependency
---

HTTP/2 receive validation uses our [h2 fork](https://github.com/cfal/h2/tree/tobaru-receive-validation-2026-10-31),
pinned to commit `d5f47a4fe3f400c94ed0d9e3cfc58f1e5e1a8721` in `Cargo.toml` and
`Cargo.lock`. It retains the previous `1a0ec784f3e23757768676645a91f540649cda96`
patch series on upstream
[`e64c1662ebb14794fc19cbcbb5b5dd0f67925f27`](https://github.com/hyperium/h2/commit/e64c1662ebb14794fc19cbcbb5b5dd0f67925f27),
still the latest upstream tip when checked on 2026-10-31. This is `h2 0.4.20`
plus two unreleased commits: received-END_STREAM preservation on connection
error/EOF and early-response cancellation regression coverage. There is no new
upstream delta in this update; the additional fix makes the configured header-list
limit inclusive rather than rejecting exactly-at-limit sections.

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
No public API, dependency feature, or Tobaru MSRV change is required.

Keep `tobaru-receive-validation-2026-10-31` and the original
`tobaru-receive-validation-tip` branch reachable while their revisions are pinned;
do not rewrite or delete their only branch or tag.

The Git dependency deliberately has no registry-version fallback. This supports
source installs and release binaries, but blocks `cargo package` and
`cargo publish` rather than allowing Cargo to substitute an unpatched registry
release. Restore registry publishing only after a released dependency includes
equivalent fixes and passes the fork's receive-validation regressions, including
stream-state error ordering, plus Tobaru's raw-wire corpus, full suite, and HTTP/2
smoke test.
