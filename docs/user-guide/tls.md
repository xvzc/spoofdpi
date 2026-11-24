# TLS Configuration

Settings for manipulating TLS packets (such as HTTPS) to bypass DPI.

!!! note
    This section was previously named `[https]`, with `--https-*` flags. The old names still work but print a deprecation warning. If both `[https]` and `[tls]` are set, `[https]` is ignored. On the command line, a `--tls-*` flag takes precedence over the same `--https-*` flag.

## `split-mode`

`type: string`

### Description

Specifies the default packet fragmentation strategy to use for the Client Hello packet. `(default: "sni")`

### Allowed Values

- `sni`: Splits the packet right after the SNI extension.
- `random`: Splits the packet at a random position.
- `chunk` or `chunk:N`: Splits the packet into chunks of N bytes (1 to 255). `chunk` alone always uses 35. Try lower values if the default fails to bypass the DPI, but a very small size splits the Client Hello into hundreds of packets, which costs performance (more so with [`fake-stutter`](#fake-stutter)).
- `first-byte`: Splits only the first byte of the packet.
- `custom`: Splits at the positions in [`custom-split`](#custom-split) (TOML only).
- `none`: Disables fragmentation.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-split-mode chunk:10
```

**TOML Config**
```toml
[tls]
split-mode = "chunk:10"
```

!!! note
    The chunk size was previously set with `chunk-size` (`--https-chunk-size`). It is no longer supported: spoofdpi ignores it and prints a warning. Use `split-mode = "chunk:N"` instead.

---

## `disorder`

`type: boolean`

### Description

Specifies whether to disorder fragmented Client Hello packets. `(default: false)`

When enabled, this option varies the TTL of fragmented Client Hello packets, potentially causing them to arrive out of order. This complicates the packet reassembly process for DPI systems.

!!! note
    If split mode is `none`, disordering does not occur.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-disorder
```

**TOML Config**
```toml
[tls]
disorder = true
```

---

## `fake-preflight`

`type: uint8`

### Description

Specifies the number of fake packets to be sent before the actual Client Hello. `(default: 0)`

!!! note
    This option was previously named `fake-count` (`--tls-fake-count`). The old name still works but prints a deprecation warning. If both are set in the TOML config, `fake-count` is ignored.

Sending fake packets can trick DPI systems into inspecting invalid traffic, allowing the real Client Hello to pass through.
Each fake packet is split the same way as the real Client Hello.

Fake packets are not sent to a server found to be on the local link (0 hops away), since no TTL can stop them before such a server. spoofdpi logs a warning with the server's address the first time it skips them for a server. To turn fake packets off for other servers, such as those on a LAN or a corporate network, use a [rule](rules.md), for example `tls = { fake-preflight = 0, fake-stutter = 0 }` for their CIDRs.

Fake packets, from this option and [`fake-stutter`](#fake-stutter), are sent to IPv4 servers only for now. For an IPv6 server they are skipped, and the Client Hello is still split; spoofdpi logs a warning the first time it skips them.

Fake packets go out through a raw IP socket on every OS and need no gateway: a default route through a point-to-point interface, such as PPP, works. While a full-tunnel VPN carries the traffic, fake packets are off for the whole run, as the censor would not see them: spoofdpi logs a warning at startup, and the Client Hello is still split. In TUN mode, spoofdpi does not start then (see [Full-Tunnel VPNs](app.md#full-tunnel-vpns)).

By default, fake packets carry the connection's real TCP sequence and acknowledgment numbers, learned from the server's SYN/ACK, so they overlap the real Client Hello. See [`fake-seq-offset`](#fake-seq-offset), [`fake-ack-offset`](#fake-ack-offset) and [`syn-ack-timeout`](#syn-ack-timeout) to change this.

!!! note
    Fake packets, from this option and [`fake-stutter`](#fake-stutter), require root privileges and packet capture capabilities.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-fake-preflight 7
```

**TOML Config**
```toml
[tls]
fake-preflight = 7
```

---

## `fake-stutter`

`type: uint8`

### Description

Specifies the number of fake segments to be sent before each segment of the Client Hello. `(default: 0)`

Each fake segment covers the same bytes as the real segment that follows it: it has the same length and sequence number, and its content is the [`fake-packet`](#fake-packet) bytes at the same position, padded with zeros past its end. So DPI that reassembles the stream sees a fake at every position before the real data. Fake segments use the same TTL as other fake packets and can be combined with [`fake-preflight`](#fake-preflight).

[`fake-seq-offset`](#fake-seq-offset) and [`fake-ack-offset`](#fake-ack-offset) apply to fake segments too. Keep `fake-seq-offset` at the default `0`, so that each fake covers exactly the position of its real segment; any other value moves the fakes away from it. To keep fakes that reach the server (for example when the hop count is wrong) from breaking the connection, adjust `fake-ack-offset` instead, such as `fake-ack-offset = -1073741824`: the server drops such fakes, while their position is unchanged. [`fake-bad-md5sig`](#fake-bad-md5sig) is an alternative that leaves the numbers unchanged; see its caveats.

A fake segment longer than the connection's MSS is sent in MSS-sized pieces, as the kernel sends the real data, so no fake exceeds the path MTU. With [`fake-bad-md5sig`](#fake-bad-md5sig), the pieces are 20 bytes smaller to leave room for the option.

The number of packets grows to the number of segments times (N + 1), so a [`split-mode`](#split-mode) that makes many segments, such as a small `chunk:N`, sends many packets.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-split-mode chunk:10 --tls-fake-stutter 1
```

**TOML Config**
```toml
[tls]
split-mode = "chunk:10"
fake-stutter = 1
```

---

## `fake-packet`

`type: byte array`

### Description

Customizes the content of the fake packets used by [`fake-preflight`](#fake-preflight) and [`fake-stutter`](#fake-stutter). `(default: built-in fake packet)`

The value should be a sequence of bytes representing a valid (or semi-valid) TLS Client Hello or other protocol data.

### Usage

**Command-Line Flag**
Provide a comma-separated string of hexadecimal bytes (e.g., `0x16, 0x03, 0x01, ...`).

```console
$ spoofdpi --tls-fake-packet "0x16, 0x03, 0x01, 0x00, 0xa1, ..."
```

**TOML Config**
Provide an array of integers (bytes).

```toml
[tls]
fake-packet = [0x16, 0x03, 0x01, 0x00]
```

---

## `fake-seq-offset`

`type: int64`

### Description

Adds an offset (mod 2^32) to the connection's real TCP sequence number in fake packets, both [`fake-preflight`](#fake-preflight) and [`fake-stutter`](#fake-stutter). It may be negative; its absolute value must be less than 2^32. `(default: 0)`

With the default `0`, each fake overlaps the real Client Hello, which works against DPI that tracks the TCP window. If a fake outlives its TTL and reaches the server, though, the server accepts it as data and the connection breaks.

The server drops a fake that reaches it only if the fake lies entirely before the data it has already received, that is, when the offset is at most minus the length of the [`fake-packet`](#fake-packet). For example, `-10000`. A negative offset smaller than that is not safe: the end of each fake still overlaps the real data. spoofdpi does not check this.

DPI that checks the TCP window strictly may ignore such fakes too. Which offsets a DPI accepts varies by network, so test them on yours. To make fakes safe for the server while keeping the sequence number DPI expects, see [`fake-ack-offset`](#fake-ack-offset).

!!! note
    With [`fake-stutter`](#fake-stutter), keep this at `0` and adjust [`fake-ack-offset`](#fake-ack-offset) instead. Stutter fakes are meant to cover the same position as the real segments, and any other offset moves them away.

If the real number cannot be learned (see [`syn-ack-timeout`](#syn-ack-timeout)), a random number chosen once per connection is used in its place.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-fake-preflight 2 --tls-fake-seq-offset -10000
```

**TOML Config**
```toml
[tls]
fake-preflight = 2
fake-seq-offset = -10000
```

---

## `fake-ack-offset`

`type: int64`

### Description

Adds an offset (mod 2^32) to the connection's real TCP acknowledgment number in fake packets, both [`fake-preflight`](#fake-preflight) and [`fake-stutter`](#fake-stutter), with the same range as [`fake-seq-offset`](#fake-seq-offset). This is one way to make [`fake-stutter`](#fake-stutter) fakes safe for the server; [`fake-bad-md5sig`](#fake-bad-md5sig) is another. `(default: 0)`

Changing only the acknowledgment number keeps the sequence number DPI expects, while a server that receives the fake should drop it if the number is out of range. Following [RFC 793](https://www.rfc-editor.org/rfc/rfc793) and [RFC 5961](https://www.rfc-editor.org/rfc/rfc5961), as Linux does, a server drops a segment whose acknowledgment number:

- acknowledges data it has not sent yet: an offset from `1` to `2147483647`; or
- is older than any receive window the client can advertise (65535 × 2^14 bytes): an offset from `-1073725441` down to `-2147483647`.

Offsets in between, from `-1073725440` to `0`, may be accepted depending on the window, and offsets beyond ±2^31 wrap around to the other side.

Some DPI ignores fakes that acknowledge data the server has not sent, so the recommended value is `-1073741824` (-2^30).

Services handle such fakes differently, though: some drop them, while others accept them and the connection breaks. So it is recommended to set this option per service with a [rule](rules.md), rather than globally:

```toml
[[rules]]
name = "fake-ack-offset for example.com"
match = { domains = ["example.com", "*.example.com"] }
tls = { fake-ack-offset = -1073741824 }
```

Which offsets a DPI accepts also varies by network, so test them on yours.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-fake-preflight 2 --tls-fake-ack-offset -1073741824
```

**TOML Config**
```toml
[tls]
fake-preflight = 2
fake-ack-offset = -1073741824
```

---

## `fake-bad-md5sig`

`type: boolean`

### Description

If set to `true`, fake packets, both [`fake-preflight`](#fake-preflight) and [`fake-stutter`](#fake-stutter), carry a TCP MD5 signature option ([RFC 2385](https://www.rfc-editor.org/rfc/rfc2385)) with a random digest. `(default: false)`

The option is meant to make a fake that outlives its TTL and reaches the server harmless: a server that has no MD5 key for the connection should drop such a packet before reading its data, while DPI, which usually does not check the option, still sees the fake. Unlike [`fake-ack-offset`](#fake-ack-offset), the sequence and acknowledgment numbers stay exactly as DPI expects.

Services handle the MD5 signature option differently, though: some drop such fakes, while others break the connection entirely. So it is recommended to enable this option per service with a [rule](rules.md), rather than globally:

```toml
[[rules]]
name = "md5sig for example.com"
match = { domains = ["example.com", "*.example.com"] }
tls = { fake-bad-md5sig = true }
```

Fakes normally expire before the server anyway; this option only matters when the hop count is wrong. Also note:

- Some middleboxes drop packets that carry this option. If one sits between you and the DPI, the fakes never reach the DPI.
- The option adds 20 bytes to each fake. Fakes are split so that they still fit the connection's MSS.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-fake-stutter 1 --tls-fake-bad-md5sig
```

**TOML Config**
```toml
[tls]
fake-stutter = 1
fake-bad-md5sig = true
```

---

## `syn-ack-timeout`

`type: uint16`

### Description

The maximum time in milliseconds to wait, before sending fake packets, for the server's SYN/ACK to be captured. `(default: 100)`

The SYN/ACK gives the connection's real sequence numbers and the number of hops to the server, which sets the TTL of fake packets. spoofdpi waits for it on every connection that sends fake packets.

The wait ends as soon as the SYN/ACK is processed. If it is not processed in time, random sequence numbers and the default TTL are used. `0` disables waiting: only numbers already learned are used.

Only IPv4 servers are learned; spoofdpi does not wait for IPv6 servers.

On an interface whose link type spoofdpi cannot capture on (it supports Ethernet, loopback, raw IP, and PPP), nothing is learned: spoofdpi logs a warning at startup and fake packets use the default hop count and random sequence numbers.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-syn-ack-timeout 50
```

**TOML Config**
```toml
[tls]
syn-ack-timeout = 50
```

---

## `skip`

`type: boolean`

### Description

If set to `true`, TLS traffic will be processed without any DPI bypass techniques (fragmentation, disordering, etc.). It effectively treats the connection as a standard proxy connection.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tls-skip
```

**TOML Config**
```toml
[tls]
skip = true
```

---

## `custom-split`

`type: array of segment plans`

### Description

Defines the positions at which the Client Hello packet is split, for fine-grained control. This option is only used when `split-mode` is set to `"custom"`.

!!! note
    This option was previously named `custom-segments`. The old name still works but prints a deprecation warning. If both are set, `custom-segments` is ignored.

Each segment plan specifies where to split the packet relative to a reference point (`from`) with an offset (`at`).

!!! note
    This option is only available via the TOML config file.

!!! important
    When using `custom` split-mode, the global `disorder` option is **ignored**. Use the `lazy` field in each segment plan to control packet ordering instead.

### Segment Plan Fields

| Field   | Type    | Required | Description |
| :------ | :------ | :------- | :---------- |
| `from`  | String  | Yes      | Reference point: `"head"` (start of packet) or `"sni"` (start of SNI extension). |
| `at`    | Int     | Yes      | Byte offset from the reference point. Negative values count backwards. |
| `lazy`  | Boolean | No       | If `true`, delays sending this segment (equivalent to disorder). `(default: false)` |
| `noise` | Int     | No       | Adds random noise (in bytes) to the split position. `(default: 0)` |

### Usage

**TOML Config**

```toml
[tls]
split-mode = "custom"
custom-split = [
    { from = "head", at = 2 },                    # Split 2 bytes from start
    { from = "sni", at = 0 },                     # Split at SNI start
    { from = "sni", at = -5, lazy = true },       # Split 5 bytes before SNI, delayed
    { from = "head", at = 100, noise = 10 },      # Split at ~100 bytes with ±10 noise
]
```
