---
title: tobaru
description: TCP, UDP, TLS, and HTTP forwarding with explicit routing and access control.
head:
  - tag: title
    content: tobaru documentation
sidebar:
  label: Overview
---

tobaru is a port forwarding tool written in Rust. Route TCP and UDP traffic by
source IP, inspect TLS SNI and ALPN without decryption, terminate TLS, or forward
HTTP requests by hostname and path. YAML configuration combines listeners,
allowlists, destinations, and reusable IP groups in one process.

## Get started

- [Install tobaru](/start/installation/) and run a [first configuration](/start/first-config/).
- Learn the [configuration model](/start/configuration-model/) or copy a complete [example](/start/examples/).
- Configure [TCP targets](/config/tcp/), [UDP forwarding](/config/udp/), and [IP groups](/config/ip-groups/).
- Export named TCP/Unix services behind NAT with [reverse tunnels](/config/reverse-tunnels/).
- Set up [incoming TLS](/tls/server/) and [outgoing TLS](/tls/client/), including certificate authentication.
- Configure [HTTP routing](/http/routing/), [actions](/http/actions/), and [HTTP/2](/http/http2/).
- Review [resource limits and deployment contracts](/operations/limits/) before exposing a listener.

## Traffic handling

TCP targets can forward opaque streams to TCP or UNIX sockets, with round-robin
backend selection. TLS passthrough and termination can share a listener. HTTP
targets support HTTP/1 and HTTP/2 independently on ingress and egress, header and
path rewriting, static files, and local responses. WebSocket upgrades are
supported only on HTTP/1-to-HTTP/1 paths; CONNECT and HTTP/3 are not supported.

Each target's allowlist grants access to that target, not a global deny rule for
other routes. A raw catch-all can receive unmatched or malformed TLS. Read
[target precedence](/config/tcp/#target-evaluation-order) before combining routes.

Configuration files are watched and reloaded. Invalid replacements retain the
last-good configuration; successful reloads stop listeners before rebinding and
are not gapless. Use a supervisor and review [reload behavior](/operations/cli/).

This reference describes the source revision in the header. **dev** documentation
is unreleased and may describe behavior absent from the latest release binary.
