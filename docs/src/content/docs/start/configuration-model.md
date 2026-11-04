---
title: Configuration model
---

A configuration file is a YAML array containing one or more entries. Each entry can be:

- **Server Config** -- defines a listener with one or more forwarding targets
- **IP Group** -- defines a reusable named set of IP ranges

```yaml
# Server config (has 'address')
- address: "0.0.0.0:443"
  transport: tcp
  targets:
    - location: backend:443
      allowlist: 0.0.0.0/0

# IP group (has 'group')
- group: internal
  ip_masks:
    - 192.168.0.0/16
    - 10.0.0.0/8
```

Multiple config files can be passed on the command line and are merged together. This is useful for separating IP group definitions from server definitions.

Every listener requires `address` and `target` or `targets`. `transport` defaults
to `tcp`; set it explicitly for clarity or use `udp` for datagrams. Each
target requires an `allowlist`. A TCP target chooses either raw forwarding through
`location`/`locations`, or HTTP handling with a required `default_http_action`
and optional `http_paths`. Do not combine raw and HTTP actions in one target.

The optional target-level `protocol` selects `raw` or `http` explicitly. Without
it, `default_http_action` selects HTTP; `http_paths` alone is not sufficient.
Mixed raw and HTTP fields are not rejected: inferred HTTP ignores target-level
raw locations, while raw locations with `http_paths` but no `default_http_action`
forward raw bytes and ignore the path rules. Do not rely on those ignored rules
for access control. Explicit `protocol: http` requires a default HTTP action but
still does not reject unknown raw fields.

Relative certificate, key, UNIX socket, and static directory paths resolve from
the process working directory, not from the configuration file's directory.
Use absolute paths in service deployments. Validate all input files together:

```sh
tobaru --dry-run ip-groups.yaml servers.yaml
```

Reference pages use schema sketches and partial YAML fragments to describe
fields. These are not complete runnable files; use the [tracked examples](/start/examples/)
for complete configurations. YAML wildcard values beginning with `*` must be quoted.

## Supported Formats

- **YAML**: `.yml` or `.yaml` extension (recommended)
- **JSON**: `.json` extension, with optional `//` single-line comments
