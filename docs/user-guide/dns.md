# DNS Configuration

Settings controlling how domain names are resolved.

## `mode`

`type: string`

### Description

Specifies the default resolution mode for domains that do not match any specific rule. `(default: "udp")`

### Allowed Values

- `udp`: Standard DNS over UDP.
- `https`: DNS over HTTPS (DoH).
- `system`: Use the operating system's resolver.

What `system` uses depends on the OS:

- **macOS**: the system resolver (`getaddrinfo`), so mDNSResponder's cache, split DNS, VPN resolvers and `/etc/resolver/*` apply.
- **Linux and FreeBSD, builds without cgo** (such as the official Linux release binaries): Go's built-in resolver, which reads `/etc/hosts` and `/etc/resolv.conf` and sends the queries itself. NSS modules, such as mDNS (`.local` names), are not used.
- **Linux and FreeBSD, builds with cgo** (such as a build from source as the [installation guide](../getting-started/install.md) describes): Go may use the system's `getaddrinfo` instead, depending on `/etc/nsswitch.conf`, and NSS modules then apply.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --dns-mode "https"
```

**TOML Config**
```toml
[dns]
mode = "https"
```

---

## `addr`

`type: <ip:port>`

### Description

Upstream DNS server address for standard UDP queries. `(default: 8.8.8.8:53)`

This is used when `dns-mode` is set to `udp`.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --dns-addr "1.1.1.1:53"
```

**TOML Config**
```toml
[dns]
addr = "1.1.1.1:53"
```

---

## `https-url`

`type: string`

### Description

Endpoint URL for DNS over HTTPS (DoH) queries. `(default: "https://dns.google/dns-query")`

This is used when `dns-mode` is set to `https`.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --dns-https-url "https://1.1.1.1/dns-query"
```

**TOML Config**
```toml
[dns]
https-url = "https://1.1.1.1/dns-query"
```

---

## `qtype`

`type: string`

### Description

Filters DNS queries by record type (A for IPv4, AAAA for IPv6). `(default: "ipv4")`

Available values are `"ipv4"`, `"ipv6"`, and `"all"`.

When a name resolves to several addresses, spoofdpi connects with Happy Eyeballs (RFC 8305). It tries the addresses in the order of RFC 6724, alternating between IPv6 and IPv4 when both are present, and starts each attempt 250 ms after the previous one, or as soon as an attempt fails. It uses the first connection that succeeds.

If your *Internet Service Provider (ISP)* doesn't support IPv6, it is recommended to set this option to `"ipv4"` for stability.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --dns-qtype "all"
```

**TOML Config**
```toml
[dns]
qtype = "all"
```

---

## Caching

DNS answers are always cached:

- In the `udp` and `https` modes, for the TTL of the records, but at most one day. An answer with a TTL of 0 is not cached. When `qtype` is `"all"` and one of the two queries fails, the addresses of the other are cached for at most 30 seconds.
- In the `system` mode, for 30 seconds, since the system resolver does not report TTLs.

An answer is cached for the options it was looked up with: `mode`, `addr` or `https-url`, and `qtype`. A [rule](rules.md#dns-override-dns) with other DNS settings looks the name up again rather than using that answer. Failed lookups are not cached.

The `cache` option (`--dns-cache`, and `cache` in `[dns]` and in rules) is deprecated. It is ignored with a warning.

---

## `timeout`

`type: uint16`

### Description

Specifies the timeout (in milliseconds) for each DNS lookup. `(default: 5000, min: 1, max: 65535)`

A value of `0` is rejected, because a lookup without a timeout can hang forever.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --dns-timeout 3000
```

**TOML Config**
```toml
[dns]
timeout = 3000
```
