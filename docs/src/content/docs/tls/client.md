---
title: Outgoing TLS
---

Configures TLS for outgoing connections to backend servers. Set within a location object.

```yaml
location:
  address: upstream.example.com:443
  client_tls:
    verify: true                   # Verify server cert via WebPKI (default: true)
    cert: string                   # Client certificate for mTLS
    key: string                    # Client private key for mTLS
    sni_hostname: string | null    # SNI to send (default: derived from address, null to disable)
    alpn_protocols: [string]       # ALPN protocols to negotiate
    server_fingerprints: [string]  # SHA256 fingerprints for cert pinning
```

TLS is disabled when `client_tls` is omitted. Explicit `false` and `null` are
rejected. When enabled,
verification defaults to `true`; client certificates require both `cert` and `key`.
Explicit `sni_hostname: null` suppresses SNI but does not disable certificate
verification. Set a hostname for a UNIX-socket TLS backend when its certificate
needs hostname verification.

## Shorthand Forms

```yaml
# Enable with defaults (verify: true)
client_tls: true

# Enable with verification disabled
client_tls: "no-verify"

# Full object form
client_tls:
  verify: true
  sni_hostname: custom.example.com
  server_fingerprints:
    - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
```

`client_tls` cannot be used with passthrough mode (would cause TLS-in-TLS).

`verify: false` and `no-verify` disable WebPKI certificate verification. Without
configured certificate pins, an active attacker can impersonate the backend;
use verification or explicit SHA256 pins for untrusted networks.

## Server Certificate Pinning

Pins are SHA256 hashes of the complete DER certificate, not public-key hashes.
Each fingerprint requires 32 bytes (64 hexadecimal digits), with optional colons
or spaces. With `verify: true`, both WebPKI verification and a configured pin
must pass. Pins do not override a chain failure. With `verify: false`, configured
pins still constrain the accepted certificate. An empty pin set imposes no pin
restriction. Obtain expected fingerprints through a trusted channel; copying a
certificate from an unverified connection is not authentication.

```yaml
client_tls:
  server_fingerprints:
    - "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
```

```bash
# Get a server's certificate fingerprint
openssl s_client -connect example.com:443 < /dev/null 2>/dev/null | openssl x509 -outform PEM > server.crt
openssl x509 -in server.crt -noout -fingerprint -sha256
```
