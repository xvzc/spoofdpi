# Rules

By defining rules, you can granularly control how spoofdpi handles connections to specific domains or IP addresses. You can define per-domain bypass strategies, DNS settings, or simply block connections.

!!! note
    Rules are only available via the TOML config file and cannot be set via command-line flags.

## Structure

The top-level `[[rules]]` array contains one table per rule. Each rule consists of matching criteria (`match`) and per-section overrides (`dns`, `tls`, `udp`, `connection`).

## Rule Fields

| Field      | Type   | Description                                      |
| :--------- | :----- | :----------------------------------------------- |
| `name`     | String | A descriptive name for the rule.                 |
| `priority` | Int    | Order of precedence. Higher numbers take priority.|
| `block`    | Bool   | If `true`, completely blocks connections matching this rule. |

## Rule Selection

Each TCP connection, and each UDP datagram, uses exactly one rule. Its address is matched against `cidrs` and, when its domain name is known, the name is matched against `domains`. The higher-priority of the two matches is selected, and the address match wins a tie. All of the selected rule's settings apply: `block`, `tls`, `udp`, `connection` and `dns`. When no rule matches, the global settings apply.

| Traffic                | Address                           | Domain name                          |
| :--------------------- | :-------------------------------- | :----------------------------------- |
| SOCKS5 `CONNECT`       | Requested or resolved address     | Requested name, if any               |
| HTTP and HTTPS proxy   | Requested or resolved address     | Requested host, if a name            |
| TUN TCP                | Destination of the packets        | TLS SNI, if present                  |
| TUN UDP                | Destination of the packets        | None                                 |
| SOCKS5 `UDP ASSOCIATE` | Resolved address of each datagram | Name the datagram is sent to, if any |

For SOCKS5 `CONNECT` and the HTTP and HTTPS proxy, a requested name is matched before it is resolved, so the domain rule's `dns` settings decide how it is looked up. A rule's `dns` settings apply only when the rule is matched by domain. SOCKS5 `UDP ASSOCIATE` resolves names with the system resolver (see [UDP traffic](#udp-traffic)).

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
tls = { fake-preflight = 5 }
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

### UDP traffic

UDP traffic is matched per datagram, by its destination, so one flow of datagrams can use different settings for different destinations. A SOCKS5 client may send each datagram to a domain name instead of an address; the name is resolved with the system resolver, so `dns` overrides do not apply to it.

A matching rule with `block = true` drops the datagrams to that destination. In TUN mode the flow is closed; a SOCKS5 association stays open for the client's other destinations.

A SOCKS5 association selects and applies a rule for each datagram, and keeps one flow per client address and destination address and port. Names that resolve to the same address and port share that flow even when they select different rules:

- `block` drops each datagram whose rule blocks it; the flow stays open for the others.
- Fake packets are sent only at the start of a flow, with the `udp` and `connection` settings of the rule its first datagram selects.
- The flow's `udp-idle-timeout` follows the rule of its latest datagram.

A SOCKS5 association keeps at most 256 flows; opening another closes the one used least recently. All of its flows close when the association ends.

## DNS Override (`dns`)

Customize how domain names are resolved for matched traffic. The available fields mirror the global [DNS Configuration](dns.md).

| Field       | Type   | Description                                      |
| :---------- | :----- | :----------------------------------------------- |
| `mode`      | String | Resolver to use: `"udp"`, `"https"` (DoH), or `"system"`. |
| `addr`      | String | Custom upstream server (e.g., `8.8.8.8:53`).     |
| `https-url` | String | Custom DoH URL (e.g., `https://dns.google/dns-query`). |
| `qtype`     | String | Query type: `"ipv4"`, `"ipv6"`, or `"all"`.      |
| `cache`     | Bool   | If `true`, enables caching for this rule.        |
| `timeout`   | Int    | Milliseconds to wait for each DNS lookup.        |

## TLS Override (`tls`)

Customize how TLS connections are established. The available fields mirror the global [TLS Configuration](tls.md). The previous name `https` still works but prints a deprecation warning; if a rule sets both, `https` is ignored.

| Field             | Type   | Description                                                   |
| :---------------- | :----- | :------------------------------------------------------------ |
| `disorder`        | Bool   | Send Client Hello packets out of order.                       |
| `fake-preflight`  | Int    | Number of fake packets to send before the Client Hello.       |
| `fake-stutter`    | Int    | Number of fake segments to send before each segment.          |
| `fake-packet`     | Array  | List of bytes for the fake packet (e.g., `[0x16]`).           |
| `fake-seq-offset` | Int    | Offset added to the sequence number of fake packets.          |
| `fake-ack-offset` | Int    | Offset added to the acknowledgment number of fake packets.    |
| `fake-bad-md5sig` | Bool   | Add a TCP MD5 signature option with a random digest to fakes. |
| `syn-ack-timeout` | Int    | Milliseconds to wait for the SYN/ACK before sending fakes.    |
| `split-mode`      | String | Split strategy: `"sni"`, `"chunk:N"`, `"random"`, etc.        |
| `custom-split`    | Array  | Segment plans for `split-mode = "custom"`.                    |
| `skip`            | Bool   | If `true`, bypasses DPI modifications (standard TLS).         |

## UDP Override (`udp`)

Customize how UDP traffic is sent to matched destinations. The available fields mirror the global [UDP Configuration](udp.md).

| Field            | Type  | Description                                                   |
| :--------------- | :---- | :------------------------------------------------------------ |
| `skip`           | Bool  | If `true`, bypasses DPI modifications (no fake packets).      |
| `fake-preflight` | Int   | Number of fake packets to send before the real datagrams.     |
| `fake-packet`    | Array | List of bytes for the fake packet (e.g., `[0x00, 0x01]`).     |

## Connection Override (`connection`)

Customize the connection settings of matching connections. The available fields mirror the global [Connection Configuration](connection.md).

| Field               | Type | Description                                                                     |
| :------------------ | :--- | :------------------------------------------------------------------------------ |
| `hop-count-default` | Int  | Hop count to the server assumed until it is learned.                            |
| `hop-count-offset`  | Int  | Added to the hop count, learned or default, to give the TTL of fakes (`-1`).    |
| `hop-count-min`     | Int  | Lower bound of the hop count used for fake packets.                             |
| `hop-count-max`     | Int  | Upper bound of the hop count used for fake packets.                             |
| `tcp-timeout`       | Int  | Milliseconds to wait for TCP connections.                                       |
| `udp-idle-timeout`  | Int  | Milliseconds a UDP connection may stay idle before it closes.                   |

## Example

```toml
# Example A: Allow YouTube with specific DPI bypass settings
[[rules]]
name = "allow youtube"
priority = 50
match = { domains = ["*.youtube.com"] }
tls = { disorder = true, fake-preflight = 7 }

# Example B: Bypass DPI for local network traffic (Standard Connection)
[[rules]]
name = "skip local"
priority = 51
match = { cidrs = ["192.168.0.0/24"] }
tls = { skip = true }

# Example C: Block a specific domain
[[rules]]
name = "block ads"
priority = 100
match = { domains = ["ads.example.com"] }
block = true
```
