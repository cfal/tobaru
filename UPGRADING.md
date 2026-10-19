# Upgrading

## TCP Target Routing

TCP target selection now checks complete routing conditions before ranking
eligible targets by source-IP prefix length, TLS/SNI/ALPN specificity, and
configuration order. Passthrough no longer has implicit priority over termination.
Broader SNI patterns remain eligible when a narrower pattern fails its IP or ALPN
conditions. Equal IP prefixes across TCP targets are accepted and use the same
ranking rules; duplicate entries within one target's allowlist remain invalid.

Raw forwarding targets without `server_tls` are now genuine catch-alls. They can
receive unmatched TLS and malformed, incomplete, or oversized ClientHellos,
with all buffered bytes replayed unchanged. Previously, the presence of any
TLS route for a source IP could prevent its raw catch-all from receiving TLS.
Plaintext HTTP targets are not opaque TLS fallbacks. Selected TLS routes still
fail closed on handshake, client authentication, and backend connection errors.

Review configurations that depended on the old routing or implicit rejections:

- A broad raw target grants fallback access even when a specific TLS target's
  IP or ALPN condition fails. Remove or narrow fallback routes when that traffic
  must be rejected. The same consideration applies to broader TLS SNI patterns.
- Deprecated `server_tls.optional: true` expands into TLS and non-TLS targets
  with the same action and allowlist. For `location`/`locations` forwarding, the
  generated non-TLS target is now a raw fallback too: unmatched or malformed TLS
  reaches the backend unchanged, even if that backend expects plaintext. To
  reject it, remove `optional: true` and avoid an equivalent raw fallback; use a
  separate listener if plaintext access is also required. Generated plaintext
  HTTP targets still reject TLS-looking traffic rather than treating it as HTTP.
- More-specific IP prefixes now take priority across raw and TLS routes, and
  across TLS targets. Configuration order breaks ties rather than determining
  every match.
- IPv4/IPv6 split TCP listeners can change even without TLS. For IPv4 clients,
  `all`, `::/0`, and other IPv6 prefixes covering `::ffff:0:0/96` now tie with
  `0.0.0.0/0`; configuration order decides. Previously, `0.0.0.0/0` always won
  among non-TLS targets regardless of order. Put the IPv4-only target first to
  preserve a family split. This also applies to raw/HTTP competition, where
  plaintext can move from raw forwarding to HTTP handling. UDP is unchanged.
- Configurations relying on passthrough always winning over termination should
  use distinct conditions or put the intended winner first when conditions tie.
- A per-host passthrough rule used only to reach an existing raw catch-all can
  be removed when the raw target's allowlist already admits that source.

No new configuration fields or dependency changes are required. See
[target precedence](CONFIG.md#target-evaluation-order) and
[raw catch-all behavior](CONFIG.md#raw-catch-all) for the complete contract.

## Upgrading from 0.7.1 and lower

### Breaking changes

The config format has changed slightly, due to switching to serde to simplify config deserialization.
YAML is now also supported.

There are two breaking changes:

- For server configuration, a `transport` field needs to be specified with either value of `tcp` or `udp`.

- Previously when setting up multiple servers. `servers` and `ipGroups` were two keys in a JSON object. They are now parsed as a single array.
  For this to work, IP group definitions have also changed from a key-value mapping of group name to IP ranges to an array format with `group` and `ip_masks` fields.

  Before:

  ```js
  {
    "servers": [<server config 1>, <server config 2>, ...],
    "ipGroups": {
      "groupName": ["1.2.3.4", "2.3.4.5"],
      "groupName2": ["3.4.5.6", "5.6.7.8"]
    }
  }
  ```

  After (JSON):

  ```js
  [
    <server config 1>,
    <server config 2>,
    {
      "group": "groupName",
      "ip_masks": ["1.2.3.4", "2.3.4.5"],
    },
    {
      "group": "groupName2",
      "ip_masks": ["3.4.5.6", "5.6.7.8"]
    }
  ]
  ```

  After (YAML):

  ```yaml
  - <server config 1>
  - <server config 2>
  - group: groupName
    ip_masks:
    - 1.2.3.4
    - 2.3.4.5
  - group: groupName2
    ip_masks:
    - 3.4.5.6
    - 5.6.7.8
  ```

### Deprecations

- Server configuration field `bindAddress` has been renamed to `address`.
- Target object configuration field `address` (or `addresses`) has been renamed to `location` (or `locations`) due to the addition of UNIX domain socket support.
- Target object configuration field `serverTls` has been renamed to `server_tls` for consistency with other snake-cased fields.
