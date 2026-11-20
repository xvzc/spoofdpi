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

`type: <ip>`

### Description

Specifies the IPv4 address of the default gateway instead of discovering it automatically. `(default: auto-detect)`

The gateway is only used for fake packets ([`tls.fake-preflight`](tls.md#fake-preflight) or [`udp.fake-preflight`](udp.md#fake-preflight) above 0) and for TUN mode. When this option is set, spoofdpi skips automatic discovery and uses the network interface whose subnet contains the gateway. This helps when automatic discovery fails or picks the wrong route, for example on machines with multiple interfaces or a VPN.

Only IPv4 addresses are supported. If no interface is on the same subnet as the gateway, spoofdpi fails to start. If neither fake packets nor TUN mode is enabled, this option is ignored with a warning.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --gateway 192.168.1.1
```

**TOML Config**
```toml
[app]
gateway = "192.168.1.1"
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
