# Upgrading

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
