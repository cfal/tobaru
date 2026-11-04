---
title: UDP forwarding
---

UDP forwarding with round-robin load balancing and stateful association tracking.

UDP routes by longest matching source-IP prefix, with no TLS or HTTP inspection.
Each source IP/port pair gets an association and a selected backend. Hostnames
are resolved through the system resolver per association. Backends are not
health-checked and requests are not automatically retried.

The optional listener-level `udp_max_associations` caps the total across all
targets. Omitted or `null` means unlimited; configured values must be positive
integers. At capacity, packets for new client addresses are dropped, while
existing associations continue forwarding. Idle cleanup frees capacity.

```yaml
- address: 0.0.0.0:53
  transport: udp
  udp_max_associations: 4096  # Optional, shared by all targets on this listener
  udp_queue_capacity: 1024   # Packets per association; range 1 through 65535
  target:
    addresses: [string]            # Backend address(es) -- round-robin
    allowlist: string | [string]   # IP masks or group names
    association_timeout_secs: 200  # Timeout for UDP associations (default: 200, min: 5)
```

The `address`, `location`, and `locations` field names are accepted as aliases for `addresses`.

The block above is a schema sketch. `udp_queue_capacity` drops packets at a full
queue; it does not block admission until space appears. Association timeout
omission or `null` uses 200 seconds; values below five seconds are raised to five.
UDP associations restart on configuration reload. See [resource sizing](/operations/limits/#listener-resources).
