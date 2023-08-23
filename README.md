# tobaru

Port forwarding tool written in Rust with advanced features, such as:

- **Multiple target addresses**: Forwards to different target addresses based on IP and TLS SNI/ALPN
  - **IPv4/IPv6 allowlists**: Only forwards connections from known IP ranges
  - **TLS support**:
    - Allow both TLS and non-TLS clients on a single port
    - Connect to TLS and non-TLS endpoints
- **Hot reloading**: Updated configs are automatically reloaded
- **iptables support**: Automatically configures iptables to drop packets from unallowed ranges
- **IP groups**: named groups of IPs that can be reused amongst different server configurations

Here's a quick example:

```yaml
- address: 0.0.0.0:443
  transport: tcp
  targets:

    # target 1: non-TLS clients from any IP will be forwarded to 127.0.0.1:2999.
    - location: 127.0.0.1:2999
      allowlist: 0.0.0.0/0

    # target 2: TLS clients from specified IP masks asking for SNI example.com and
    # ALPN protocol http/1.1 will be forwarded to a listening UNIX domain socket.
    - location: /run/service.sock
      server_tls:
        cert: cert.pem
        key: key.pem
        sni_hostnames: example.com
        alpn_protocols: http/1.1
      allowlist:
        - 1.2.3.4
        - 2.3.0.0/16

    # target 3: TLS clients from ip 1.2.3.4 asking for SNI example.com or test.com,
    # and any other ALPN protocol, or no ALPN negotiation, will be forwarded here.
    - location: 127.0.0.1:3001
      server_tls:
        cert: cert.pem
        key: key.pem
        sni_hostnames:
          - example.com
          - test.com
        alpn_protocols:
          - any
          - none
      allowlist: 1.2.3.4
```

## Installation

Precompiled binaries for x86_64 and Apple aarch64 are available on [Github Releases](https://github.com/cfal/tobaru/releases).

Else, if you have a fairly recent Rust and cargo installation on your system, tobaru can be installed with `cargo`.

```bash
cargo install tobaru
```

## Usage

```
USAGE:

    tobaru [OPTIONS] <CONFIG PATH or CONFIG URL> [CONFIG PATH or CONFIG URL] [..]

OPTIONS:

    -t, --threads NUM
        Number of worker threads, defaults to an estimated amount of parallelism.

    --clear-iptables-all
        Clear all tobaru-created rules from iptables and exit immediately.

    --clear-iptables-matching
        Clear tobaru-created rules for the addresses specified in the specified
        config files and exit immediately.

    -h, --help
        Show this help screen.

IPTABLES PERMISSIONS:

    To run iptable commands, this binary needs to have CAP_NET_RAW and CAP_NET_ADMIN
    permissions, or else be invoked by root.

EXAMPLES:

    tobaru -t 1 config1.yaml config2.yaml

        Run servers from configs in config1.yaml and config2.yaml on a single thread.

    tobaru tcp://127.0.0.1:1000?target=127.0.0.1:2000

        Run a tcp server on 127.0.0.1 port 1000, forwarding to 127.0.0.1 port 2000.

    sudo tobaru --clear-iptables-matching config1.yaml

        Clear iptable configs only for the config addresses in config1.yaml.
```

## URL-based configuration

Simple TCP forwarding can be done using the config URL format:

```
tcp://<bind ip>:<bind port>?target=<target ip>:<target port>
```

TCP forwarding to a UNIX domain socket can be done with the `target-path` key:


```
tcp://<bind ip>:<bind port>?target-path=<unix domain socket path>
```

## File-based configuration

Configuration files are in the YAML or JSON file format. tobaru expects to read an array of objects, where each object is a server configuration, or an IP mask group.

### Server object configuration

`address`: The address to listen on.

`transport`: The transport protocol, a string of either `tcp` or `udp`.

`use_iptables` (_optional_, default: `false`): Whether to enable iptables support.
  - IP masks in allowlists specified in the targets would be added to iptables, and unspecified IP masks would be denied.

`targets` (or `target`): An target location object or an array of target location objects that specify where to forward to.

`tcp_nodelay` (_optional_, default: `true`): Specifies whether to disable Nagle's algorithm on the accepted socket.
  - Only accepted when `transport` is `tcp`.

#### Target object configuration (TCP transport)

`locations` (or `location`): A single TCP location, or an array of TCP locations.

  - When an array of multiple locations is provided, connections will be forwarded in a round-robin fashion.

`allowlist`: A single IP mask or IP group name, or an array of IP mask or IP group names.

`tcp_nodelay` (_optional_, default: `true`): Specifies whether to disable Nagle's algorithm on the target connected socket.

`server_tls` (_optional_, default: `null`): A server TLS object. When non-null, only TLS connections will be accepted for this target. The object keys are:
  - `cert`: A file path to the TLS certificate.
  - `key`: A file path to the TLS private key.
  - `optional` (_optional_, default: `false`): Specifies whether TLS is optional. When true, this means that non-TLS streams will also be accepted and forwarded.
  - `sni_hostnames` (_optional_, default: `any, none`): A SNI hostname, or an array of SNI hostnames, with special keywords:
    - `any`: Accept any provided SNI hostname.
    - `none`: Accept handshakes without SNI negotiation.
  - `alpn_protocols` (_optional_: default: `any, none`): An accepted ALPN protocol, or an array of supported ALPN protocols, with special keywords:
    - `any`: Accept any provided ALPN protocol.
    - `none`: Accept handshakes without ALPN protocol selection.

#### TCP location configuration

A TCP location can be specified as:

- an address string. eg. `127.0.0.1:1234`
- a UNIX domain socket path. eg. `/path/to/something.sock`
- an object with the following keys:

  `address`: an address string.
    - only one of `address` or `path` can be specified.

  `path`: a UNIX domain socket path.
    - only one of `address` or `path` can be specified.

  `client_tls` (_optional_, default: `false`): Specifies whether to handle TLS when connecting to this location. The supported values are:
    - `true`: Enables client TLS handling, with certificate verification.
    - `no-verify`: Enables client TLS handling, without certificate verification.
    - `false`: Disables client TLS handling.

#### Target object configuration (UDP transport)

`addresses` (or `address`): A single address string, or an array of `host:port` address strings

`allowlist`: A single IP mask or IP group name, or an array of IP mask or IP group names.

`association_timeout_secs` (_optional_, default: `200`): Number of seconds before an inactive UDP association times out.

### IP group object configuration

`group`: Name of the IP group

`ip_masks` (or `ip_mask`): A single IP mask or IP group name, or an array of IP mask or IP group names.

A default IP group with name `all` and IP mask `0.0.0.0/0` is automatically added.

## Examples

### TCP to TCP forwarding, all IPs allowed

```yaml
- address: 0.0.0.0:8080
  transport: tcp
  target:
    location: 192.168.8.1:80
    allowlist: all
```

or with multiple servers and specific IP ranges:

```yaml
# Forward port 8080 to 192.168.8.1 port 80 for some IP ranges.
- address: 0.0.0.0:8080
  transport: tcp
  targets:
    - address: 192.168.8.1:80
      allowlist:
        # Some local IP ranges..
        - 192.168.9.0/24
        - 192.168.10.0/24

        # .. and some specific IPs
        - 12.34.56.78
        - fa71::e09d:92fa:beef:1234

    - address: 192.168.8.2:80
      allowlist:
        - 192.168.11.0/24
        - 192.168.12.0/24

# Forward port 8081 to 192.168.8.2 port 80 for all IPs.
- address: 0.0.0.0:8081
  transport: udp
  target:
    - address: 192.168.8.3:80
      allowlist:
        - all
```

Connections from addresses that are not specified in `allowlist` will either be dropped (if `iptables` is set to `true`), or be immediately closed after accept.

### Round-robin forwarding

```js
{
  // Listen on all interfaces, port 8080.
  "bindAddress": "0.0.0.0:8080",
  "transport": "tcp",
  "target": {
    // Round-robin forward to different addresses.
    "addresses": [
      "192.168.8.1:80",
      "192.168.8.2:80",
      "192.168.8.3:80",
      "192.168.8.4:80"
    ],
    "allowlist": "all"
  }
}
```

### Multiple destinations based on IP address

```js
{
  // Listen on port 8080
  "bindAddress": "0.0.0.0:8080",
  "transport": "tcp",
  "targets": [
    // Forward some IP ranges to 192.168.8.1 port 80.
    {
      "address": "192.168.8.1:80",
      "allowlist": [
        "192.168.1.0/24",
        "192.168.2.0/24"
      ]
    },
    // Forward other IP ranges to 192.168.8.2 port 80.
    {
      "address": "192.168.8.2:80",
      "allowlist": [
        "192.168.3.0/24",
        "192.168.4.0/24"
      ]
    }
  ]
}
```

### TLS support

```js
[
    // Server listening on port 443 (HTTPS).
    {
      "bindAddress": "192.168.0.1:443",
      "target": {
        // All connections need to use TLS.
        // Enable TLS by specifying the path to the certificate and private key.
        "serverTls": {
          "cert": "/path/to/cert.pem",
          "key": "/path/to/key.pem",
          // Allow clients to connect without TLS.
          "optional": true
        },

        // Also connect to the destination HTTPS server using TLS.
        // '+' (plus sign) means to use TLS.
        "address": "192.168.2.1:+443",
        "allowlist": "all"
      }
    },

    // Server listening on port 443 (HTTPS).
    // Forward in a round-robin manner to various HTTP servers that do not have
    // TLS enabled.
    {
      "bindAddress": "192.168.0.2:443",
      "target": {
        "serverTls": {
          "cert": "/path/to/cert.pem",
          "key": "/path/to/key.pem"
        },
        "addresses": [
          "192.168.2.1:80",
          "192.168.2.2:80",
          "192.168.2.3:80"
        ],
        "allowlist": "all"
      }
    }
]
```

### iptables support

Note that tobaru will need root access in order to configure iptables. It might be possible to do this without root by using `setcap(8)`. Please file a pull request with instructions if you are able to do so.

```js
{
  "bindAddress": "0.0.0.0:8080",
  // Enable iptables auto-configuration.
  "iptables": true,
  "target": {
    "address": "192.168.8.1:80",
    // Allow only the following IP ranges. Packets from other IPs will be dropped.
    "allowlist": [
      "192.168.2.2/24",
      "192.168.2.3/24",
      "192.168.100.50"
    ]
  }
}
```

### IP groups

IP groups can be used to quickly specify groups of IPs in multiple servers. Note that IP ranges can be specified in any file and can be reused across different files, for example, it could be convenient invoke tobaru with all IP groups in an individual file: `tobaru ip_groups.json http_servers.json ssh_servers.json`

```js
{
  "ipGroups": {
    "local": [
      "192.168.0.0/24",
      "192.168.1.0/24",
      "192.168.2.0/24",
      "192.168.3.0/24"
    ],
    "friends": [
      "1.2.3.4",
      "2.3.4.5"
    ]
  },

  "servers": [
    {
      "bindAddress": "0.0.0.0:8080",
      "target": {
        "address": "192.168.5.1:8080",
        // Only allow IP ranges from 'local' and 'friends' to connect.
        "allowlist": [
          "local",
          "friends"
        ]
      }
    },
    {
      "bindAddress": "0.0.0.0:8081",
      "target": {
        "address": "192.168.5.2:8080",
        // Only allow IP ranges from 'local'.
        "allowlist": "@local"
      }
    }
  ]
}
```

### Upgrading from 0.7.1 or lower

See [UPGRADING.md](UPGRADING.md).
