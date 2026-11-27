# UDP Configuration

Settings for UDP packet manipulation and bypass techniques.

## `skip`

`type: boolean`

### Description

If set to `true`, UDP traffic will be processed without any DPI bypass techniques (fake packets, etc.). It effectively treats the connection as a standard UDP proxy connection. `(default: false)`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --udp-skip
```

**TOML Config**
```toml
[udp]
skip = true
```

---

## `fake-preflight`

`type: int`

### Description

Specifies the number of fake packets to be sent before actual UDP packets. `(default: 0)`

!!! note
    This option was previously named `fake-count` (`--udp-fake-count`). The old name still works but prints a deprecation warning. If both are set in the TOML config, `fake-count` is ignored.

Sending fake packets can trick DPI systems into inspecting invalid traffic, allowing real packets to pass through.

Fake packets are not sent to a server found to be on the local link (0 hops away), since they would reach it no matter their TTL. spoofdpi logs a warning with the server's address the first time it skips them for a server. The hop count is learned from the server's replies, so the first flow to a new server still sends them; use a [rule](rules.md) to turn them off for such servers.

On an interface whose link type spoofdpi cannot capture on (it supports Ethernet, loopback, raw IP, and PPP), no hop counts are learned: spoofdpi logs a warning at startup and fake packets use the default hop count.

Fake packets are sent to IPv4 servers only for now. For an IPv6 server they are skipped, and spoofdpi logs a warning the first time it skips them.

Fake packets go out through a raw IP socket on every OS and follow the system's route to the internet, which needs no gateway: a default route through a point-to-point interface, such as PPP, works. In TUN mode, fake packets are pinned to the interface of the system's route found at startup, as spoofdpi's own connections are: on Linux the socket is bound to the interface and marked, on macOS it is bound to the interface, and on FreeBSD it uses the FIB set by [`freebsd-fib`](app.md#freebsd-fib), whose default route goes through that interface. In the HTTP and SOCKS5 modes, the system routes them. While a full-tunnel VPN carries the traffic, fake packets are off for the whole run, as the censor would not see them: spoofdpi logs a warning at startup, and the datagrams are still sent. In TUN mode, spoofdpi does not start then (see [Full-Tunnel VPNs](app.md#full-tunnel-vpns)).

In the HTTP and SOCKS5 modes, spoofdpi also checks the route to each server: a server that a VPN carries, such as through a split tunnel, gets no fake packets, and spoofdpi logs a warning the first time. Each server's result is kept for 5 seconds.

Fake packets share the flow of the real datagrams and rely on their TTL to expire before the server. If the hop count is overestimated, a fake can reach the server, and the server's reply to it is passed on to the application like any other.

!!! note
    This feature requires root privileges and packet capture capabilities.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --udp-fake-preflight 5
```

**TOML Config**
```toml
[udp]
fake-preflight = 5
```

---

## `fake-packet`

`type: byte array`

### Description

Customizes the content of the fake packets used by `udp-fake-preflight`. `(default: 64 bytes of zeros)`

The value should be a sequence of bytes representing the fake packet data.

### Usage

**Command-Line Flag**
Provide a comma-separated string of hexadecimal bytes (e.g., `0x00, 0x01, 0x02, ...`).

```console
$ spoofdpi --udp-fake-packet "0x00, 0x01, 0x02, 0x03, 0x04"
```

**TOML Config**
Provide an array of integers (bytes).

```toml
[udp]
fake-packet = [0x00, 0x01, 0x02, 0x03, 0x04]
```
