---
title: Installation
description: Install a release binary or build the documented source revision.
---

## Release binaries

Download the archive for your platform from [GitHub Releases](https://github.com/cfal/tobaru/releases).
Release builds include Linux x86_64/ARM64 and macOS Intel/Apple Silicon;
inspect the chosen release's assets for availability. Extract the binary,
place it on your `PATH`, and run `tobaru --help`.

The site currently documents **dev**, not a versioned release. Use a source build
of the revision linked in the header when you need the exact documented behavior.

## Build from source

Requires Rust 1.88 or newer, Cargo, Git, and a native C/C++ build toolchain for
the TLS dependencies. Replace `SOURCE_COMMIT` with the full commit linked in the
page header to build that exact revision:

```sh
git clone https://github.com/cfal/tobaru.git
cd tobaru
git checkout SOURCE_COMMIT
CARGO_BUILD_JOBS=1 cargo install --locked --path .
tobaru --help
```

The first build requires GitHub access to fetch the pinned HTTP/2 fork. Cached
checkouts can support later offline builds. `cargo install tobaru` installs the
older crates.io release, not this source revision. Registry publishing is
intentionally blocked while these [HTTP/2 fixes](/operations/dependencies/) need
a Git dependency.

For a local build without installation:

```sh
CARGO_BUILD_JOBS=1 cargo build --release --locked
./target/release/tobaru --help
```

## Permissions

Start with a loopback listener on an unprivileged port. Binding privileged ports
or managing Linux firewall rules requires additional permissions; ordinary
forwarding does not require root. See [iptables integration](/config/server/#iptables-integration).

Continue with the [first configuration](/start/first-config/).
