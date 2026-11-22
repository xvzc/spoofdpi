# DNS Configuration

Settings controlling how domain names are resolved.

## `mode`

`type: string`

### Description

Specifies the default resolution mode for domains that do not match any specific rule. `(default: "udp")`

### Allowed Values

- `udp`: Standard DNS over UDP.
- `https`: DNS over HTTPS (DoH).
- `system`: Use the system's default resolver.

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

## `cache`

`type: boolean`

### Description

If set, DNS records will be cached to improve performance and reduce latency. `(default: false)`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --dns-cache
```

**TOML Config**
```toml
[dns]
cache = true
```

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
