# Rules

By defining rules, you can granularly control how spoofdpi handles connections to specific domains or IP addresses. You can define per-domain bypass strategies, DNS settings, or simply block connections.

!!! note
    Rules are only available via the TOML config file and cannot be set via command-line flags.

## Structure

The top-level `[[rules]]` array contains one table per rule. Each rule consists of matching criteria (`match`) and per-section overrides (`dns`, `https`, `udp`, `connection`).

## Rule Fields

| Field      | Type   | Description                                      |
| :--------- | :----- | :----------------------------------------------- |
| `name`     | String | A descriptive name for the rule.                 |
| `priority` | Int    | Order of precedence. Higher numbers take priority.|
| `block`    | Bool   | If `true`, completely blocks connections matching this rule. |

## Match Criteria (`match`)

You can specify a `domain` list or an `addr` list (containing `cidr` and `port`).

| Field    | Type   | Description                                                                 |
| :------- | :----- | :-------------------------------------------------------------------------- |
| `domain` | Array  | List of domain patterns. Supports wildcards (`*`, `**`).                    |
| `addr`   | Array  | List of address rules. Each rule requires `cidr` and `port`.                |

### Address Rule (`addr`)

| Field  | Type   | Description                                                                 |
| :----- | :----- | :-------------------------------------------------------------------------- |
| `cidr` | String | IP range in CIDR notation (e.g., `192.168.0.0/24`).                         |
| `port` | String | Port or port range (e.g., `80`, `80-443`, `all`).                          |

## DNS Override (`dns`)

Customize how domain names are resolved for matched traffic. The available fields mirror the global [DNS Configuration](dns.md).

| Field       | Type   | Description                                      |
| :---------- | :----- | :----------------------------------------------- |
| `mode`      | String | Resolver to use: `"udp"`, `"https"` (DoH), or `"system"`. |
| `addr`      | String | Custom upstream server (e.g., `8.8.8.8:53`).     |
| `https-url` | String | Custom DoH URL (e.g., `https://dns.google/dns-query`). |
| `qtype`     | String | Query type: `"ipv4"`, `"ipv6"`, or `"all"`.      |
| `cache`     | Bool   | If `true`, enables caching for this rule.        |

## HTTPS Override (`https`)

Customize how HTTPS connections are established. The available fields mirror the global [HTTPS Configuration](https.md).

| Field         | Type   | Description                                           |
| :------------ | :----- | :---------------------------------------------------- |
| `disorder`    | Bool   | Send Client Hello packets out of order.               |
| `fake-count`  | Int    | Number of fake packets to send.                       |
| `fake-packet` | Array  | List of bytes for the fake packet (e.g., `[0x16]`).   |
| `split-mode`  | String | Split strategy: `"chunk"`, `"sni"`, `"random"`, etc.  |
| `chunk-size`  | Int    | Size of chunks when `split-mode` is `"chunk"`.        |
| `skip`        | Bool   | If `true`, bypasses DPI modifications (standard TLS). |

## Example

```toml
# Example A: Allow YouTube with specific DPI bypass settings
[[rules]]
    name = "allow youtube"
    priority = 50
    match = { domain = ["*.youtube.com"] }
    https = { disorder = true, fake-count = 7 }

# Example B: Bypass DPI for local network traffic (Standard Connection)
[[rules]]
    name = "skip local"
    priority = 51
    match = { addr = [{ cidr = "192.168.0.0/24", port = "all" }] }
    https = { skip = true }

# Example C: Block a specific domain
[[rules]]
    name = "block ads"
    priority = 100
    match = { domain = ["ads.example.com"] }
    block = true
```

## Deprecated: `[[policy.overrides]]`

Earlier versions used `[[policy.overrides]]` instead of `[[rules]]`. The old key is still accepted for backward compatibility but emits a deprecation warning at startup. Migrate to the top-level `[[rules]]` form — it removes the `[policy]` indirection that no longer carries any other configuration.

```toml
# Deprecated form — still works, prints a warning
[[policy.overrides]]
    name = "allow youtube"
    match = { domain = ["*.youtube.com"] }
    https = { fake-count = 7 }
```
