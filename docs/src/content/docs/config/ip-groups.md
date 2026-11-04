---
title: IP groups
---

Named, reusable sets of IP ranges. A group can reference only previously defined
groups, including those from earlier input files. Listener allowlists are expanded
after all files are loaded, so listeners may reference groups defined later.
Group names must be unique and must not look like IP masks. The built-in `all`
group cannot be redefined.

```yaml
# Define groups
- group: internal
  ip_masks:
    - 192.168.0.0/16
    - 10.0.0.0/8
    - 172.16.0.0/12

- group: trusted
  ip_masks:
    - 1.2.3.4
    - 5.6.7.8
    - internal                     # Groups can reference other groups

# Use in server config
- address: 0.0.0.0:8080
  transport: tcp
  target:
    location: backend:8080
    allowlist:
      - trusted
```

The built-in group `all` is equivalent to `::/0`, covering both IPv4 and IPv6.
Use `0.0.0.0/0` to allow only IPv4.

`ip_mask` (singular) is accepted as an alias for `ip_masks`.
