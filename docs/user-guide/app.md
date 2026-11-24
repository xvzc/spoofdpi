# App Configuration

Application-level settings including mode, logging, and system integration.

## `app-mode`

`type: string`

### Description

Specifies the proxy mode. `(default: "http")`

### Allowed Values

- `http`: HTTP proxy mode
- `socks5`: SOCKS5 proxy mode
- `tun`: TUN interface mode (transparent proxy)

!!! warning
    **SOCKS5** and **TUN** modes are currently Experimental. You might encounter unexpected behaviors or bugs. Feedback and bug reports are highly appreciated!

### IPv6 in TUN Mode

TUN mode does not proxy IPv6 yet. What happens to IPv6 traffic depends on the global [`ipv6`](#ipv6) option only.

With `ipv6` off (the default), spoofdpi routes no IPv6 traffic into the TUN interface. IPv6 traffic keeps the system's routes and bypasses spoofdpi. When the system has an IPv6 route to the internet, spoofdpi logs a warning at startup: enable `ipv6`, or disable IPv6 on the system, so that no traffic bypasses it.

With `ipv6` on, when [`auto-configure-network`](#auto-configure-network) sets up the TUN routes and the system has an IPv6 route to the internet, spoofdpi also routes global IPv6 addresses (`2000::/3`) into the TUN interface and refuses every connection to them: TCP connections are reset, and UDP datagrams get an ICMPv6 "port unreachable". Applications that support both IP versions, such as browsers and curl, then fall back to IPv4, which spoofdpi proxies. spoofdpi logs a warning at startup when it adds this route.

With `ipv6` on:

- Destinations reachable only over IPv6 are unreachable in TUN mode.
- A DNS server at a global IPv6 address is refused too; the system then uses its other DNS servers, if it has any.
- Link-local, unique local (`fc00::/7`) and multicast IPv6 addresses keep their normal routes.
- Pings to global IPv6 addresses get replies, but spoofdpi sends them itself; a reply does not mean IPv6 works.
- When the system has no IPv6 route to the internet, spoofdpi adds no IPv6 route. On Linux it also adds none when IPv6 is disabled on the TUN interface.
- If the system refuses the IPv6 route, spoofdpi logs a warning and keeps running with IPv4 only; IPv6 traffic then bypasses spoofdpi.

TUN mode needs no gateway when the default route goes through a point-to-point interface such as PPP: spoofdpi then routes its own traffic out of that interface directly.

In TUN mode, the operating system and the applications resolve names and choose the IP version, so the [`ipv6`](rules.md#rule-fields) of rules and all [DNS settings](dns.md), global and in rules, are ignored. spoofdpi logs this at startup when a rule sets `ipv6` or the DNS settings differ from the defaults.

### IPv6 Link-Local Destinations

A link-local IPv6 address (`fe80::/10`) is reachable only through the interface its zone names, as in `fe80::1%en0`.

- In HTTP mode, write the zone in the request target with `%25` for `%` (RFC 6874), for example `CONNECT [fe80::1%25en0]:443`.
- In SOCKS5 mode, an IPv6 address has no zone. Send a zoned address as a domain name instead, for example `fe80::1%en0`. A `CONNECT` to a link-local address without a zone gets the reply "address type not supported" (`0x08`).
- SOCKS5 `UDP ASSOCIATE` drops datagrams to a link-local address, and to any address sent with a zone.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --app-mode socks5
```

**TOML Config**
```toml
[app]
mode = "socks5"
```

---

## `listen-addr`

`type: <ip:port>`

### Description

Specifies the IP address and port to listen on. `(default: 127.0.0.1:8080 for http, 127.0.0.1:1080 for socks5)`

If you want to run spoofdpi remotely (e.g., on a physically separated machine), set the IP part to `0.0.0.0`. Otherwise, it is recommended to leave this option as default for security.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --listen-addr "0.0.0.0:8080"
```

**TOML Config**
```toml
[app]
listen-addr = "0.0.0.0:8080"
```

---

## `ipv6`

`type: boolean`

### Description

Enables IPv6. `(default: false)`

With IPv6 enabled, DNS lookups ask for both A and AAAA records; without it, for A records only (see [Record Types](dns.md#record-types)).

A [rule](rules.md#rule-fields) can set its own `ipv6`; a rule that does not set it follows this option. TUN mode follows this option only (see [IPv6 in TUN Mode](#ipv6-in-tun-mode)).

With this option off, only DNS and the IPv6 handling are off: an IPv6 literal requested through the HTTP or SOCKS5 proxy, such as `[2001:db8::1]`, is still connected to. To keep a site on IPv4, set `ipv6 = false` in its rule (see [IPv6](rules.md#ipv6)).

!!! warning
    IPv6 support is currently Experimental, and spoofdpi logs a warning at startup when this option is set.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --ipv6
```

**TOML Config**
```toml
[app]
ipv6 = true
```

---

## `log-level`

`type: string`

### Description

Specifies the logging verbosity.

Available values are `debug`, `trace`, `info`, `warn`, `error`, and `disabled`. `(default: "info")`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --log-level trace
```

**TOML Config**
```toml
[app]
log-level = "trace"
```

---

## `no-tui`

`type: boolean`

### Description

Disables the TUI and runs in headless mode. When set, the ASCII art banner is also suppressed. `(default: false)`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --no-tui
```

**TOML Config**
```toml
[app]
no-tui = true
```

---

## `auto-configure-network`

`type: boolean`

### Description

Specifies whether to automatically set up the system-wide proxy configuration. `(default: false)`

The system proxy points at the address in [`listen-addr`](#listen-addr). When that address is `0.0.0.0` or `[::]`, it points at `127.0.0.1` instead, on the same port.

!!! important
    This option is currently only supported on **macOS**.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --auto-configure-network
```

**TOML Config**
```toml
[app]
auto-configure-network = true
```

---

## `config`

`type: string`

### Description

Specifies the path to a custom `TOML` config file. `(default: none)`

If this option is set, spoofdpi will not search the default directories.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --config ~/spoofdpi.toml
```

**TOML Config**
```toml
# This option is not available in TOML config
```

---

## `clean`

`type: boolean`

### Description

Specifies whether to ignore all configuration files and run with default settings. `(default: false)`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --clean
```

**TOML Config**
```toml
# This option is not available in TOML config
```

---

## `gateway`

`type: <ip> or array of <ip>`

### Description

Specifies the default gateway instead of discovering it automatically. `(default: auto-detect)`

The value is an IPv4 address, an IPv6 address, or one of each; two addresses of the same family are rejected. A link-local IPv6 address may name its interface with a zone, as in `fe80::1%en0`; no other address may have a zone. An empty value means automatic discovery: an empty array (`gateway = []`), an empty string, an empty flag value (`--gateway ""`), or only empty entries. The IPv6 address is accepted but not used yet.

The gateway is only used for fake packets ([`tls.fake-preflight`](tls.md#fake-preflight), [`tls.fake-stutter`](tls.md#fake-stutter) or [`udp.fake-preflight`](udp.md#fake-preflight) above 0) and for TUN mode. When this option is set, spoofdpi skips automatic discovery and uses the network interface whose subnet contains the gateway. This helps when automatic discovery fails or picks the wrong route, for example on machines with multiple interfaces or a VPN.

What that interface is used for depends on the system:

- On Linux, fake packets are sent on that interface, to the gateway's MAC address. Packet capture and TUN mode's route out of the TUN use it too.
- On macOS and FreeBSD, the option selects the interface that packet capture runs on and TUN mode's route out of the TUN. Where fake packets go depends on the mode:
    - In the HTTP and SOCKS5 modes, fake packets follow the system's routing table, like any other packet, so the option does not change where they go.
    - In TUN mode, fake packets leave through the selected interface, like TUN mode's own connections: on macOS they are bound to it, and on FreeBSD they use the FIB ([`freebsd-fib`](#freebsd-fib)) whose default route goes via the gateway.

If no interface is on the same subnet as the gateway, spoofdpi fails to start. If neither fake packets nor TUN mode is enabled, this option is ignored with a warning.

When this option is not set, fake packets and TUN mode need an IPv4 default route. If the system has none, for example on an IPv6-only network, spoofdpi fails to start with an error that says so and whether the system has an IPv6 route. IPv6-only networks are not supported yet.

### Usage

**Command-Line Flag**

Repeat the flag, or separate the addresses with commas. The flag replaces the whole `gateway` of the TOML config.

```console
$ spoofdpi --gateway 192.168.1.1
$ spoofdpi --gateway 192.168.1.1 --gateway fe80::1%en0
$ spoofdpi --gateway 192.168.1.1,fe80::1%en0
```

**TOML Config**
```toml
[app]
gateway = "192.168.1.1"
# or, with an IPv6 gateway too
gateway = ["192.168.1.1", "fe80::1%en0"]
```

---

## `freebsd-fib`

`type: integer`

### Description

Specifies the FIB (Forwarding Information Base) ID for FreeBSD routing table. `(default: 1)`

Valid range is 1-15. This option is only applicable on **FreeBSD** systems when using TUN mode.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --freebsd-fib 3
```

**TOML Config**
```toml
[app]
freebsd-fib = 3
```

---

## `version`

`type: boolean`

### Description

Prints the version string and exits. `(default: false)`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --version
```

**TOML Config**
```toml
# This option is not available in TOML config
```
