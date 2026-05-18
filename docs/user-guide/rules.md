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

You can specify a `domains` list or a `cidrs` list.

| Field     | Type   | Description                                                                 |
| :-------- | :----- | :-------------------------------------------------------------------------- |
| `domains` | Array  | List of domain patterns. Supports wildcards (`*`, `**`).                    |
| `cidrs`   | Array  | List of IP ranges in CIDR notation (e.g., `["10.0.0.0/8"]`).               |

### File-based match lists

Both `domains` and `cidrs` accept items with a `file:` prefix. The path after the prefix is read line by line, and each non-empty, non-comment line is treated as an additional item.

```toml
[[rules]]
name = "streaming"
match = { domains = ["file:assets/streaming-domains.txt", "*.youtube.com"] }
https = { fake-count = 5 }
```

**Path resolution**

| Prefix / form         | Resolved against            |
| :-------------------- | :-------------------------- |
| Relative path         | Directory of the config file |
| Absolute path (`/…`)  | Used as-is                  |
| `~/…`                 | User home directory          |
| `$VAR/…`              | Environment variable         |

**File format rules**

- Lines beginning with `#` are treated as comments and ignored.
- Blank lines are ignored.
- If the file does not exist, a warning is emitted at startup and the entry is skipped (the server still starts).
- Any other I/O error (e.g. permission denied) is fatal.

```
# assets/streaming-domains.txt
*.netflix.com
*.nflxvideo.net
# add more below
```

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
match = { domains = ["*.youtube.com"] }
https = { disorder = true, fake-count = 7 }

# Example B: Bypass DPI for local network traffic (Standard Connection)
[[rules]]
name = "skip local"
priority = 51
match = { cidrs = ["192.168.0.0/24"] }
https = { skip = true }

# Example C: Block a specific domain
[[rules]]
name = "block ads"
priority = 100
match = { domains = ["ads.example.com"] }
block = true
```

## Deprecated: `[[policy.overrides]]`

Earlier versions used `[[policy.overrides]]` instead of `[[rules]]`. The old key is still accepted for backward compatibility but emits a deprecation warning at startup. Migrate to the top-level `[[rules]]` form — it removes the `[policy]` indirection that no longer carries any other configuration.

```toml
# Deprecated form — still works, prints a warning
[[policy.overrides]]
name = "allow youtube"
match = { domains = ["*.youtube.com"] }
https = { fake-count = 7 }
```
