---
title: HTTP/2
---

`http_protocols` is an ingress allowlist, default `[http1, http2]`. It must be a
nonempty list without duplicates; select `[http1]` or `[http2]` to disable the
other protocol. The old `http2.prior_knowledge` option is no longer accepted;
replace `prior_knowledge: true` with target-level `http_protocols: [http2]`.

With both protocols enabled, plaintext connections are detected incrementally:
`PRI ` selects H2; the first mismatch selects H1. All consumed bytes, including
any read-ahead from optional TLS detection, are replayed unchanged. The H2 library
validates the remaining preface. Invalid prefaces never fall back to H1. This
reserves `PRI` as an H2-only method on mixed plaintext listeners, while longer H1
methods such as `PRINT` still work. Detection runs only once per connection, not
for each keepalive request. Single-protocol listeners skip detection entirely.

Detection uses one absolute deadline from entry into HTTP dispatch, including
waiting for the first byte: `http_timeouts.request_header_timeout_secs` when set,
otherwise `http2.header_timeout_secs` (10 seconds) when omitted. Explicit `null`
disables that frontend timer. Byte progress does not extend it. After selection,
the existing handler's header/handshake deadlines apply.

TLS never sniffs HTTP bytes. Negotiated `h2` selects H2; `http/1.1`, custom ALPN
names, and no ALPN select H1, provided that protocol is enabled. Omitted TLS ALPN
is derived as described in [incoming TLS](/tls/server/#alpn-protocol-matching);
explicit ALPN is authoritative. H2-only TLS
requires `h2` negotiation. Generic TLS target matching still precedes HTTP
dispatch. Raw streams and TLS passthrough are unaffected. Upgrade-based h2c is
not supported.

A forward action independently selects `upstream_protocol: http1 | http2`
(default `http1`). H2 egress uses prior knowledge over clear TCP/Unix sockets or
requires negotiated `h2` over TLS. Omit client ALPN to derive `[h2]`, or configure
exactly `[h2]`; incompatible explicit lists are rejected. No automatic fallback.

```yaml
target:
  allowlist: 127.0.0.1/32
  http_protocols: [http1, http2]
  http2:
    max_concurrent_streams: 64
    max_connections: 256
    max_backend_connections: 256
    max_header_list_size: 65536
    header_timeout_secs: 10
    connect_timeout_secs: 10
    body_progress_timeout_secs: 30
    drain_timeout_secs: 5
  default_http_action:
    type: forward
    upstream_protocol: http2
    location:
      address: backend.example:443
      client_tls: true
```

Protocol policy and limit values shown are defaults. Enabling H2 validates local
response statuses and headers for H2 compatibility, even when an explicit ALPN
list restricts TLS to H1. Use `[http1]` for H1-only local response configurations.
`max_concurrent_streams` is per ingress H2 connection (maximum 4096).
`max_connections` bounds admitted H2 connections per compiled target/generation,
after TLS negotiation. `max_backend_connections` initializes two separate
target-global limits: active new-path exchanges and live new-path backend
transports, including dialing, idle and draining connections. Both connection
limits are capped at 65536. Each frontend additionally retains at most 16 H2
backend drivers across all actions. Admission refuses excess work rather than
creating an unbounded queue. H1-to-H1 connections retain their existing policy.

Header limits are 1024 through 1048576 decoded bytes, with a fixed 128-field cap.
Receive windows are 64 KiB per stream and 1 MiB per connection; forwarding chunks
are at most 16 KiB. Up to 16 informational responses are forwarded. Encoded
field-section bytes and pre-consumption response-section counts are also bounded.
Trailer fields are validated independently of initial headers and header patches.
Pseudoheaders and oversized trailer sections are rejected before conversion to
ordinary fields, for both ingress requests and upstream H2 responses, using the
[pinned h2 fork fixes](/operations/dependencies/). Literal `#` fragments are rejected
before URI normalization on both H2 ingress and H1-to-H2 forwarding, so the backend
cannot receive a different path from the one used for routing. Encoded `%23`
remains permitted. These checks require no additional configuration flags.

For sections received over HTTP/2, `max_header_list_size` is an inclusive receive
policy, counting each field's name, value, and 32-byte overhead. Valid trailer
sections exactly at the limit are preserved in full; sections one byte over it
are rejected, not truncated. HTTP/1 fields on translation paths retain their
existing accounting: raw field-line length, including the colon and whitespace,
plus 32 bytes. The configured policy is distinct from the H2 decoder's additional
abuse limits, which can terminate the connection rather than only the stream.

All H2 timeouts must be positive and at most 86400 seconds. The connect deadline
includes action-slot waiting, DNS/TCP/Unix setup, TLS and H2 handshake/readiness.
The header deadline is absolute for incomplete frames/header blocks, not extended
by trickling bytes; expiry closes the connection. Existing explicit request-header
timeout overrides the ingress frame/header default. Generic pre-ALPN TLS handshake
policy remains controlled by `server_tls.handshake_timeout_secs`.

Response-header and upstream-body progress deadlines are disabled by default.
An explicit response-header deadline is absolute from request-head submission,
including concurrent upload and informational responses. An explicit upstream-body
progress deadline bounds stalled upstream I/O, not downstream backpressure or
waiting for frontend upload bytes. `http2.body_progress_timeout_secs` still
protects frontend upload reads and downstream writes. See the complete
[timeout contract](/operations/limits/#upstream-owned-latency).

Frontend idle means no active streams, default 60 seconds, overridden or disabled
with `http_timeouts.keepalive_idle_timeout_secs`. Reload/idle retirement sends
GOAWAY and bounds each owner's drain; top-level reload does not synchronously
join established TCP sessions.

H2 preserves the logical request scheme and authority independently of backend
TLS/SNI. Host patches update outgoing authority. Repeated headers, DATA and trailers
are preserved; H1 ingress retains its existing UTF-8 restriction. Cross-version
translation rejects unsupported transfer-coding chains and framing-changing
patches, and uses H1 chunking when trailers may follow. H2-to-H1 backend leases are
exclusive and not cached. H2 backend reuse is frontend/action-scoped, without
cross-action coalescing or automatic retries; round-robin advances per physical
connection, not per stream.

H2-to-H1 requests use one canonical Host, `Connection: close`, no incoming
Content-Length or TE field, and chunked framing whenever the upload is open.
DATA bytes cannot supply their own chunk boundaries. Failed uploads are not
completed with a synthesized terminal chunk, and their backend sockets are never
reused. If an early response is already in progress, upload failure half-closes
the backend write side so an EOF-dependent response can finish.

CONNECT, extended CONNECT/WebSocket, H3 and push are not supported on H2 paths.
H1 upgrades directed to an H2-only action receive 501. Local H2 responses must be
final statuses; HEAD/204/205/304 do not transmit payload. Custom reason phrases
are H1-only. `close` intentionally closes the entire H2 connection and its siblings;
ordinary local responses end only their stream.
