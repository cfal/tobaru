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

```js
{
  "bindAddress": "0.0.0.0:443",
  "protocol": "tcp",
  "targets": [
    // target 1: non-TLS clients from any IP will be forwarded here.
    {
      "address": "127.0.0.1:2999",
      "allowlist": [ "0.0.0.0/0" ]
    },
    // target 2: TLS clients from any IP asking for SNI example.com and ALPN protocol
    // http/1.1 will be forwarded here.
    {
      "address": "127.0.0.1:3000",
      "serverTls": {
        "cert": "cert.pem",
        "key": "cert.pem",
        "sni_hostnames": [ "example.com" ],
        "alpn_protocols": [ "http/1.1" ]
      },
      "allowlist": [ "0.0.0.0/0" ]
    },
    // target 3: TLS clients from ip 1.2.3.4 asking for SNI example.com and any other
    // ALPN protocol, or no ALPN negotiation, will be forwarded here.
    {
      "address": "127.0.0.1:3001",
      "serverTls": {
        "cert": "cert.pem",
        "key": "cert.pem",
        "sni_hostnames": [ "example.com" ],
        // allow any alpn protocol, or to skip ALPN negotiation.
        "alpn_protocols": [ "any", "none" ]
      },
      "allowlist": [ "1.2.3.4" ]
    },
    // target 4: TLS clients from ip 1.2.3.4 asking for SNI test.com will be forwarded here.
    {
      "address": "127.0.0.1:3002",
      "serverTls": {
        "cert": "cert.pem",
        "key": "cert.pem",
        "sni_hostnames": [ "test.com" ],
        "alpn_protocols": [ "any", "none" ]
      },
      "allowlist": [ "5.6.7.8" ]
    }
  ]
}
```

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

- **to, target**: address to forward to.
- **allowlist**: list of comma separated netmasks to allow. if this is omitted, all source addresses are allowed.
- **tcp_nodelay**: enables tcp_nodelay.

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
