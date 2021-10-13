# tobaru

Port forwarding tool written in Rust with advanced features, such as:

- **Allowlists**: Only forwards connections from known IPv4 or IPv6 ranges.
- **iptables support**: Automatically configures iptables to drop packets from unallowed ranges.
- **Multiple target addresses**: Forwards to different target addresses based on IP.
- **TLS encryption/decryption**: Accepts unencrypted and TLS-enabled connections, and connects to both unencrypted and TLS-enabled destinations.
- **TLS detection**: Allows clients to optionally use TLS, and forward them without the TLS layer if they aren't.
- **IP groups**: named groups of IPs that can be reused amongst different server configurations.

## Usage

`tobaru <config URL or file> [config URL or file..]`

## Simple configuration

Simple configuration can be done by passing in URLs on the command line. The format is as follows:

```
<protocol>://<bind ip>:<bind port>?to=<target ip>:<target port>&key=value&key2=value2&...
```

- **protocol**: one of `tcp` or `udp`.
- **bind ip** and **bind port**: ip of the interface and port to listen on

Supported query keys:

- **to, targetAddress, target**: address to forward to.
- **allowlist**: list of comma separated netmasks to allow. if this is omitted, all source addresses are allowed.
- **tcp_nodelay, nodelay, tcpNodelay**: enables tcp_nodelay.
- **early_connect, earlyConnect**: enables early connect.

## Advanced Configuration

Advanced configuration is done using JSON files. One difference from JSON is that configuration files can contain comment lines that begin with `//`.

## Examples

### Simple forwarding (command line)

```bash
tobaru 'udp://0.0.0.0:5353?to=192.168.8.1:8053'
```

Listens for udp traffic on port 5353 of all interfaces, and forwards to 192.168.8.1 port 8053. All source addresses are allowed.


### Simple forwarding (config file)

```js
{
  // Listen on all interfaces, on port 8080.
  "bindAddress": "0.0.0.0:8080",
  "target": {
    // Forward to 192.168.8.1 port 80.
    "address": "192.168.8.1:80",
    // Allow connections from all addresses. 'all' is a special alias for 0.0.0.0/0.
    "allowlist": "all"
  }
}
```

or with multiple servers and specific IP ranges:

```js
{
  "servers": [
    // Forward port 8080 to 192.168.8.1 port 80, but only for some IP ranges.
    {
      "bindAddress": "0.0.0.0:8080",
      "target": {
        "address": "192.168.8.1:80",
        "allowlist": [
          // Some local IP ranges..
          "192.168.9.0/24",
          "192.168.10.0/24",
          // ..and some specific IPs.
          "162.39.217.12",
          "fa71::e09d:92fa:fd2c:8297"
        ]
      }
    },
    // Forward port 8081 to 192.168.8.2 port 80, for any IP.
    {
      "bindAddress": "0.0.0.0:8081",
      "target": {
        "address": "192.168.8.2:80",
        "allowlist": "all"
      }
    }
  ]
}
```

Connections from addresses that are not specified in `allowlist` will either be dropped (if `iptables` is set to `true`), or be immediately closed after accept.

### Round-robin forwarding

```js
{
  // Listen on all interfaces, port 8080.
  "bindAddress": "0.0.0.0:8080",
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
{
  "servers": [
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
}
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
        // Use '@' to specify IP groups.
        // Only allow IP ranges from 'local' and 'friends' to connect.
        "allowlist": [
          "@local",
          "@friends"
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
