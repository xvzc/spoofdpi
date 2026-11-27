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

With `ipv6` on but IPv6 disabled at startup, because no usable IPv6 route was found or a full-tunnel VPN carries IPv6 (see [`ipv6`](#ipv6)), spoofdpi runs as with `ipv6` off. When the system still has an IPv6 route to the internet, spoofdpi logs a warning that IPv6 was disabled and that IPv6 traffic bypasses spoofdpi.

With `ipv6` on, when [`auto-configure-network`](#auto-configure-network) sets up the TUN routes and the system has an IPv6 route to the internet, spoofdpi also routes global IPv6 addresses (`2000::/3`) into the TUN interface and refuses every connection to them: TCP connections are reset, and UDP datagrams get an ICMPv6 "port unreachable". Applications that support both IP versions, such as browsers and curl, then fall back to IPv4, which spoofdpi proxies. spoofdpi logs a warning at startup when it starts routing IPv6 into the TUN interface.

With `ipv6` on:

- Destinations reachable only over IPv6 are unreachable in TUN mode.
- A DNS server at a global IPv6 address is refused too; the system then uses its other DNS servers, if it has any.
- Link-local, unique local (`fc00::/7`) and multicast IPv6 addresses keep their normal routes.
- Pings to global IPv6 addresses get replies, but spoofdpi sends them itself; a reply does not mean IPv6 works.
- When the system has no IPv6 route to the internet, spoofdpi adds no IPv6 route. On Linux it also adds none when IPv6 is disabled on the TUN interface.
- If the system refuses the IPv6 route or, on Linux, one of the IPv6 policy rules, or spoofdpi cannot list the IPv6 policy rules or find room for its own, spoofdpi logs a warning and keeps running with IPv4 only; IPv6 traffic then bypasses spoofdpi.

TUN mode needs no gateway when the default route goes through a point-to-point interface such as PPP: spoofdpi then routes its own traffic out of that interface directly. TUN mode does not start while a full-tunnel VPN carries the traffic (see [Full-Tunnel VPNs](#full-tunnel-vpns)).

In TUN mode, the operating system and the applications resolve names and choose the IP version, so the [`ipv6`](rules.md#rule-fields) of rules and all [DNS settings](dns.md), global and in rules, are ignored. spoofdpi logs this at startup when a rule sets `ipv6` or the DNS settings differ from the defaults.

### TUN Mode Routing on Linux

On Linux, TUN mode leaves the main routing table untouched. It adds its routes to a table of its own, which leads into the TUN interface, and policy rules that send only unmarked traffic into the TUN. spoofdpi sets them up through netlink and runs no `ip` command.

- Traffic that another program marks, such as the tunnel packets of a VPN like `wg-quick`, is not captured and follows the system's rules, so spoofdpi does not circumvent it; this includes any traffic that a firewall or container runtime, such as Docker, marks.
- spoofdpi binds its own sockets to the interface of the route it found at startup and marks them for the same reason, so its traffic follows the main table's routes.
- Traffic from that interface's address also follows the main table's routes, so strict reverse-path filtering, such as NixOS's firewall, keeps accepting the replies to spoofdpi's own connections.
- This relies on the main table keeping its route through that interface: if a VPN or a network manager replaces it while spoofdpi runs, traffic through the TUN stops.
- Routes in the main table more specific than the default route, such as those of the local network, keep working.

- Policy rules that other programs installed before spoofdpi started take precedence. spoofdpi places its rules after the existing ones; when there is no room, it places them before or among them and logs a warning naming those rules.
- A VPN started after spoofdpi takes precedence when it adds policy rules, or routes in the main table more specific than the default route, such as `0.0.0.0/1` and `128.0.0.0/1`. A VPN that only replaces the main table's default route does not: its traffic is still routed into the TUN, where it stops, as described above.
- It needs Linux 4.17 or later and policy routing (`CONFIG_IP_MULTIPLE_TABLES`). It does not need iproute2. On an older kernel, or one without policy routing, spoofdpi fails to start in TUN mode.
- Its rules carry `protocol 213` and its routes `proto 213`, and its table ID is in the range `0x53504400` to `0x535044ff` (1397769216 to 1397769471), which spoofdpi alone uses. The capture rule is `fwmark 0/0xffffffff lookup <table>`: it matches only unmarked traffic.

### IPv6 Link-Local Destinations

A link-local IPv6 address (`fe80::/10`) is reachable only through the interface its zone names, as in `fe80::1%en0`.

- In HTTP mode, write the zone in the request target with `%25` for `%` (RFC 6874), for example `CONNECT [fe80::1%25en0]:443`.
- In SOCKS5 mode, an IPv6 address has no zone. Send a zoned address as a domain name instead, for example `fe80::1%en0`. A `CONNECT` to a link-local address without a zone gets the reply "address type not supported" (`0x08`).
- SOCKS5 `UDP ASSOCIATE` drops datagrams to a link-local address, and to any address sent with a zone.

### Full-Tunnel VPNs

When fake packets or TUN mode is enabled, spoofdpi looks up at startup the interface that the system routes the internet through, and logs it in an `egress` line with its class. spoofdpi always uses the system's route; to send its traffic out of another interface, change the system's routes. The route needs no gateway: a default route through a point-to-point interface, such as PPP, works. If the system has no IPv4 route to the internet, for example on an IPv6-only network, spoofdpi fails to start with an error that says so and whether the system has an IPv6 route. IPv6-only networks are not supported yet.

The classes are:

- `direct`: a physical interface, such as Ethernet or Wi-Fi.
- `uplink`: a point-to-point interface, such as PPP or a 6in4 tunnel, that has the only default route.
- `vpn`: a full-tunnel VPN, such as WireGuard, OpenVPN or IPsec, or a point-to-point interface while a physical interface also has a default route. On Linux, a TAP interface counts as a VPN.
- `unknown`: an interface spoofdpi cannot tell apart.

A full-tunnel VPN carries the traffic to its server, where the censor does not see fake packets, so:

- TUN mode does not start while a full-tunnel VPN carries the IPv4 traffic: spoofdpi fails with an error. Disconnect the VPN, or use the HTTP or SOCKS5 mode.
- In the HTTP and SOCKS5 modes, fake packets are off for the whole run, and spoofdpi logs a warning at startup. The other desync methods, such as splitting, still apply.
- With [`ipv6`](#ipv6) on, a full-tunnel VPN that carries IPv6 makes TUN mode run with IPv6 disabled, with a warning; the HTTP and SOCKS5 modes only log it.

When the class is `unknown`, spoofdpi logs a warning and proceeds as if the interface were not a VPN.

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

When IPv6 is enabled, by this option or, outside TUN mode, by a rule that sets `ipv6 = true`, spoofdpi looks up the IPv6 route to the internet at startup, in every mode, and logs its interface. The route needs no gateway.

When spoofdpi finds no usable IPv6 route (the system has none, or the routing table cannot be read), or in TUN mode a full-tunnel VPN carries IPv6 (see [Full-Tunnel VPNs](#full-tunnel-vpns)), it logs a warning and runs with IPv6 disabled, as if this option and every rule's `ipv6` were off: DNS lookups ask for A records only, TUN mode routes no IPv6 into the TUN interface, and `ipv6 = true` in a rule has no effect. A rule with `ipv6 = false` still keeps its site on IPv4.

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

In `tun` mode, spoofdpi exits with an error when it fails to set up the network config, since no traffic reaches the TUN interface without it. In `http` and `socks5` modes, it logs the error and keeps running.

spoofdpi undoes what it set up when it shuts down. It keeps no state file for this: the old `/tmp/spoofdpi.*.state` files are never read. If one is still there, spoofdpi warns at startup that it is no longer used; delete it and do not run the commands in it. If spoofdpi does not exit cleanly, the next start removes what it left (see [Leftovers After a Crash](#leftovers-after-a-crash)).

!!! important
    In `http` and `socks5` modes, setting the system proxy is currently only supported on **macOS**. In `tun` mode, this option sets up the routing into the TUN interface on Linux, macOS and FreeBSD.

On macOS, the system proxy is a proxy auto-configuration (PAC) URL that spoofdpi serves at `/spoofdpi.pac` on `127.0.0.1`. spoofdpi does not turn on automatic proxy discovery (WPAD).

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

The `gateway` option (`--gateway`, and `gateway` in `[app]`) is deprecated. It is ignored with a warning: spoofdpi uses the system's route to the internet (see [Full-Tunnel VPNs](#full-tunnel-vpns)). To send spoofdpi's traffic out of another interface, change the system's routes instead.

---

## `freebsd-fib`

`type: integer`

### Description

Specifies the FIB (Forwarding Information Base) that spoofdpi's own traffic uses. `(default: none)`

This option is only applicable on **FreeBSD** systems when using TUN mode, and it is **required** there: spoofdpi does not start without it. Valid range is 1 to `net.fibs` minus 1, and at most 15.

Use a FIB that only spoofdpi uses, not one that jails or services started with `setfib` use. spoofdpi fails to start when the FIB has a default route, or a static route to the subnet of the physical interface.

It has no effect in other modes or on other operating systems; there it is only checked to be in the range 1 to 15. A config that omitted it on FreeBSD now fails at startup with `'freebsd-fib' is required in tun mode on FreeBSD`: add the option.

A system with one FIB (`net.fibs=1`) has none to give. Add FIBs with `sysctl net.fibs=2`, or set `net.fibs="2"` in `/boot/loader.conf` to keep them across reboots.

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

## Leftovers After a Crash

spoofdpi undoes its network configuration from memory when it shuts down. When a run does not exit cleanly, for example after a crash or `kill -9`, it can leave routes, rules or a system proxy behind. At every start, in every mode, spoofdpi removes what such a run left, and only the items that it tagged and that have the exact shape it adds. Anything else that looks like its own, it reports with a warning. The command to remove it by hand is in the `manual_command` field of the warning. Cleanup never stops spoofdpi from starting.

spoofdpi does not remove what a running spoofdpi uses: in TUN mode it checks for the running instance's TUN interface or routes, and on macOS it probes the PAC server of the system proxy.

The commands below need root.

**Linux**

- spoofdpi removes the tagged capture rule, the rules of its block, and the tagged routes of its table. It removes nothing while `tun-spoofdpi` exists.
- It warns about a persistent `tun-spoofdpi` interface, which outlives the process that made it.
- It only reports rules without a tag that older builds added, and the source routing rules (`from <IP> lookup N`, N within 200-250) that v1.6.0 and earlier added, as they can be your own. Remove them by hand.

spoofdpi's own items are removed with commands of this form:

```console
$ ip rule del pref <N> fwmark 0/0xffffffff lookup <T> protocol 213
$ ip route del default table <T> proto 213
$ ip -6 route del 2000::/3 table <T> proto 213
```

For v1.6.0 and earlier, the commands are plain, for example the following, where the last one removes the host route to the gateway in the main table:

```console
$ ip rule del pref <pref> from <IP> lookup <table>
$ ip route del default via <gateway> table <table> proto 3
$ ip route del <gateway>/32 table main proto 3
```

**FreeBSD**

- spoofdpi removes the tagged routes of the FIB set by [`freebsd-fib`](#freebsd-fib), and a closed `tun-spoofdpi` interface with its tagged routes in the main FIB.
- Tagged routes in other FIBs are only reported, with the hint to start spoofdpi once with that FIB in `freebsd-fib`.
- FIBs above 15 cannot be set in `freebsd-fib`, so clean them by hand.
- Remove what it reports by hand, for example:

```console
$ route -n delete default <gateway> -fib <N>
$ ifconfig tun-spoofdpi destroy
```

**macOS**

- spoofdpi removes a tagged scoped default route that an earlier run left, only when it is the only scoped default route of its interface. At shutdown, it removes its own scoped default route only while it is still spoofdpi's. It adds none when the physical interface already has one.
- After a crash in `http` or `socks5` mode, it turns off an enabled spoofdpi PAC URL (also the older `/proxy.pac`) only when the server at that URL refuses connections. A live spoofdpi PAC server is left alone and logged at INFO. It warns only when the state is unclear: another server answers on the port, the server does not answer in time, or the answer has no spoofdpi marker. Remove what it reports by hand, for example:

```console
$ route -n delete -ifscope <interface> default <gateway>
$ networksetup -setautoproxystate "<service>" off
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
