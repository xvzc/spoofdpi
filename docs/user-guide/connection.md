# Connection Configuration

Settings for network connection timeouts and packet configuration.

## `tcp-timeout`

`type: uint16`

### Description

Specifies the timeout (in milliseconds) for TCP connections. `(default: 10000, max: 65535)`

A value of `0` means no timeout.

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

`type: uint16`

### Description

Specifies the idle timeout (in milliseconds) for UDP connections. `(default: 25000, max: 65535)`

The connection will be closed if there is no read/write activity for this duration. Each read or write operation resets the timeout.

A value of `0` means no timeout.

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

Fake packets should pass the DPI but expire before reaching the server, so they are sent with a [Time To Live (TTL)](https://en.wikipedia.org/wiki/Time_to_live) of the hop count to the server minus 1. spoofdpi learns the hop count from the TTL left on the server's replies; until then, this value is used.

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

Added to a learned hop count before it sets the TTL of fake packets. `(default: 0)`

The hop count is learned by assuming that the server started from a common initial TTL (64, 128 or 255), which is not always true, and the path back from the server can differ from the path to it. A negative offset makes fake packets expire earlier, for networks where the learned hop count tends to be too high and fakes reach the server.

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

Bounds for the hop count used for fake packets, applied after [`hop-count-offset`](#hop-count-offset). `(default: 0 / 255, no bounds)`

`hop-count-max` caps a hop count that was learned far too high, which would let fake packets reach the server. `hop-count-min` keeps fake packets from expiring before they reach the DPI. For example, if the DPI is 10 hops away and servers are farther than 15 hops, `hop-count-min = 11` and `hop-count-max = 15` keep the TTL of fake packets between 10 and 14.

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
