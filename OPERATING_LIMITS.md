# Operating Limits and Deployment Contracts

Tobaru limits admitted work and protocol metadata independently of upstream application
latency. Upstream response-header and body-progress deadlines are disabled by default.
Enable them only when an application needs a deadline enforced by the proxy.

## Listener Resources

TCP listeners default to `tcp_max_connections: 256`. A permit covers the entire accepted
connection, including protocol detection and TLS. At capacity, new connections are closed
without starting a forwarding task. Existing connections count across reloads of the same
bind address, including removal and re-addition while connections survive. Lowering a cap
does not evict existing connections; admission resumes when their count falls below it.
Explicit `null` disables the cap. Unlimited generations are still counted for later reloads.

UDP listeners default to `udp_max_associations: 128` and `udp_queue_capacity: 8` packets
per association. New associations and packets are dropped at capacity; existing associations
continue. `udp_max_associations: null` disables the association cap. Queue depth must be
between 1 and 65,535. Both settings are listener fields, alongside `address` and `transport`.

The UDP defaults allow at most approximately 64 MiB of queued maximum-size payload per
listener (128 times 8 times 64 KiB). In-flight payloads, sockets, tasks, and kernel buffers
are additional. Multiple listeners multiply the budget. Raising both settings can grow
memory consumption dramatically. TCP limits likewise exclude backend sockets and other
listeners; size them against the process FD and memory limits. These are conservative
defaults, not throughput guarantees.

TCP and UDP URL shortcuts use these same defaults. They still allow all peers and disable
built-in firewall handling. Non-loopback shortcut binds produce one warning per URL load;
the bind address is never silently changed.

## HTTP and TLS Timeouts

`http_timeouts` belongs to each HTTP target:

```yaml
http_timeouts:
  # Omission uses 10 seconds for H1 and http2.header_timeout_secs for H2/detection.
  request_header_timeout_secs: 10
  response_header_timeout_secs: null
  upstream_body_progress_timeout_secs: null
  keepalive_idle_timeout_secs: 60
  local_body_timeout_secs: 10
```

Omitting the object, using `{}`, or supplying only some fields retains the defaults for
the remaining fields. Explicit `null` disables the applicable optional timer; positive
integer seconds enable it. Zero, negatives, fractional values, and unknown timeout fields
are rejected.

- H1 request headers have an absolute 10-second default, not a per-byte timer. A keepalive
  connection first waits for input under its separate idle budget, then reads headers.
- H2 and plaintext protocol detection inherit `http2.header_timeout_secs` when the request
  header setting is omitted. An explicit value overrides it; `null` disables that frontend
  timer, but not framing validation, header-size accounting, or separate H2 setup limits.
- Keepalive defaults to 60 seconds. H2 idle retirement applies only with no active stream
  tasks. `null` disables idle retirement for both protocols, not reload draining.
- H1 local actions drain request bodies under an absolute 10-second default, including
  trailers. `local_body_timeout_secs: null` disables this deadline. H2 local actions keep
  their existing protocol-specific progress and drain behavior.
- `server_tls.handshake_timeout_secs` defaults to 10 seconds in termination mode only.
  `null` disables it. Passthrough omission remains valid; a positive termination-handshake
  setting is invalid for passthrough.

### Upstream-Owned Latency

Omitted or `null` response-header and upstream-body settings impose no application latency
deadline in any H1/H2 forwarding combination. A stalled backend may retain an admitted
connection or stream until cancellation or closure. Resource caps still apply.

An explicit `response_header_timeout_secs` is an absolute budget from submission of the
request head through receipt of the final response head. It includes concurrent upload
time. Informational responses, including `100` and `103`, do not extend it. It does not
bound response-body transfer.

An explicit `upstream_body_progress_timeout_secs` bounds stalled upstream body reads and
upstream upload writes/capacity waits, including trailers and EOF. It is a progress budget,
not a maximum transfer lifetime. Downstream backpressure and waiting for frontend upload
bytes do not consume an upstream I/O budget. It does not change raw tunnels or upgrades.

Existing H2 connection/setup limits and incomplete-frame/header-block watchdogs remain
active independently. Backend silence between complete messages is not an incomplete
frame. Encoded and decoded metadata limits remain active even with response timers off.

For forwarding involving H2, `http2.body_progress_timeout_secs` retains its frontend
upload-read and downstream-write protection. `Expect: 100-continue` upload timing starts
only after Continue is forwarded or upload bytes arrive. An early final response replaces
a pending expectation without requiring the client to upload. A successful early response
does not otherwise cancel an active duplex upload. Long backend pauses do not consume the
next frontend operation's initial progress budget.

Legacy H1-to-H1 streaming and raw tunnels retain unlimited frontend streaming lifetimes.
No new mandatory upstream setup, raw inactivity, or whole-connection deadline is imposed.

## HTTP Metadata and Logging

Legacy H1 request limits remain unchanged: less than 4 KiB per line, at most 38 fields plus
the start line. H1 responses permit at most 128 fields, 16 KiB per line, and 64 KiB for the
complete head including CRLFs. At most 16 informational responses precede a final response.

Legacy H1 chunked trailers permit at most 128 fields and 64 KiB of field lines including
their CRLFs, excluding the final empty line. Over-limit fields are rejected before being
forwarded. H2 and translation paths retain their separate bounded field-list accounting.

H1 access logs omit query strings and escape control characters in paths. Request-line
and malformed-header errors do not echo raw contents. Paths may still contain sensitive
application identifiers; use appropriate log access controls, filters, rotation, and
deployment rate limits. Startup/configuration errors are not suppressed.

## Deployment Contracts

- Routing matches raw, undecoded path segments, excluding queries. Escaped separators,
  dot segments, and repeated slashes are not normalized. Align backend interpretation and
  authorization with routing; do not use route predicates alone as an authorization boundary.
- Static serving roots and their ancestors must be controlled by trusted writers. Stable-tree
  traversal checks are not a race-resistant sandbox against hostile filesystem replacement.
- Built-in firewall commands require a trusted PATH and executable directories. Rules are
  protocol/port-wide, not specific to the listener's bind address; earlier rules affect their
  effect. Prefer externally managed rules for shared ports/addresses or multiple instances.
- Reload validation failures retain the running configuration. Successful preparation stops
  old listeners before replacement binding; subsequent bind failure is not transactional and
  can interrupt service. Use a supervisor. H2 graceful shutdown and bounded draining remain.
- Backend selection remains one-attempt round-robin on connection establishment, with H2
  connection reuse. Requests are not replayed and no proactive health checks are performed.
- UDP hostname resolution remains per association through the system resolver. Results are
  not permanently pinned at configuration load and no proxy-managed DNS cache is introduced.

YAML remains supported through the pinned `yaml_serde` continuation of `serde_yaml`, with
the existing Rust crate name preserved. Configuration compatibility fixtures cover aliases,
scalar typing, custom actions, duplicate keys, explicit nulls, and literal merge keys.
The vendored H2 validation patches remain in use.
