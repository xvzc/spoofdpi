# Connection Configuration

Settings for network connection timeouts and packet configuration.

## `tcp-timeout`

`type: uint32`

### Description

Specifies the timeout (in milliseconds) for TCP connections. `(default: 10000, min: 1, max: 3600000)`

The timeout applies to each connection attempt. When a name resolves to several addresses, the attempts to further addresses start 250 ms apart (see [Record Types](dns.md#record-types)), so connecting can take longer than the timeout in total.

In HTTP and SOCKS5 mode, it also bounds how long the proxy waits for a client's request after the client connects. A client that sends no request in time, or speaks another protocol, is disconnected.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --tcp-timeout 5000
```

**TOML Config**
```toml
[connection]
tcp-timeout = 5000
```

---

## `udp-idle-timeout`

`type: uint32`

### Description

Specifies the idle timeout (in milliseconds) for UDP connections. `(default: 120000, min: 1, max: 3600000)`

The connection will be closed if there is no read/write activity for this duration. Each read or write operation resets the timeout.

The default follows RFC 4787, which requires a UDP mapping idle timeout of at least 2 minutes, so quiet flows such as games or VoIP keep their mapping.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --udp-idle-timeout 30000
```

**TOML Config**
```toml
[connection]
udp-idle-timeout = 30000
```

---

## `hop-count-default`

`type: uint8`

### Description

The hop count to the server assumed until spoofdpi learns it. `(default: 8)`

Fake packets should pass the DPI but expire before reaching the server, so they are sent with a [Time To Live (TTL)](https://en.wikipedia.org/wiki/Time_to_live), the hop limit over IPv6, of the hop count to the server plus [`hop-count-offset`](#hop-count-offset), which is the hop count minus 1 by default. spoofdpi learns the hop count from the TTL or hop limit left on the server's replies, separately for TCP and UDP. Fake packets use the hop count learned over their own protocol, or else the one learned over the other protocol; until either is learned, this value is used.

!!! note
    This option was previously named `default-fake-ttl` (`--default-fake-ttl`). The old name still works but prints a deprecation warning. If both are set in the TOML config, `default-fake-ttl` is ignored.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --hop-count-default 10
```

**TOML Config**
```toml
[connection]
hop-count-default = 10
```

---

## `hop-count-offset`

`type: int8`

### Description

Added to the hop count to give the TTL of fake packets: the TTL is the hop count plus this offset. `(default: -1)`

It applies to every hop count alike, whether learned or [`hop-count-default`](#hop-count-default), after [`hop-count-min` and `hop-count-max`](#hop-count-min-hop-count-max) bound it. The TTL is at least 1. The default of `-1` makes fake packets expire at the last router before the server.

The hop count is learned by assuming that the server started from a common initial TTL (64, 128 or 255), which is not always true, and the path back from the server can differ from the path to it. A lower offset makes fake packets expire earlier, for networks where the learned hop count tends to be too high and fakes reach the server.

If spoofdpi logs "the server answered the Client Hello with a TLS alert" with `decode_error`, `illegal_parameter` or `unexpected_message` while fake packets are on, the fakes may have reached the server: the server read the fake Client Hello and rejected it. Lower this offset by 1, or check the site with [`spoofdpi probe`](probe.md). Other causes give the same alert too, so treat it as a hint, not a diagnosis.

!!! note
    The offset used to default to `0`, apply to learned hop counts only, and be followed by a fixed minus 1. If you set `hop-count-offset` yourself, the same value now gives a TTL 1 higher: subtract 1 from it to keep your TTL, for example `-3` becomes `-4`. It now also applies to `hop-count-default`, and is added after `hop-count-min` and `hop-count-max` apply, so with those bounds set, check the TTL of hop counts they clip.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --hop-count-offset=-3
```

**TOML Config**
```toml
[connection]
hop-count-offset = -3
```

---

## `hop-count-min` / `hop-count-max`

`type: uint8`

### Description

Bounds for the hop count used for fake packets, applied before [`hop-count-offset`](#hop-count-offset) is added. `(default: 0 / 255, no bounds)`

`hop-count-max` caps a hop count that was learned far too high, which would let fake packets reach the server. `hop-count-min` keeps fake packets from expiring before they reach the DPI. For example, if the DPI is 10 hops away and servers are farther than 15 hops, `hop-count-min = 11` and `hop-count-max = 15` keep the TTL of fake packets between 10 and 14 with the default offset.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --hop-count-min 11 --hop-count-max 15
```

**TOML Config**
```toml
[connection]
hop-count-min = 11
hop-count-max = 15
```
