# Overview

There are two methods to configure spoofdpi, and both can be used together.

- TOML Config File
- Command-Line Flags

## Configuration Priority
spoofdpi applies settings in the following order:

1. Values defined in the TOML config file
2. Values passed via command-line (CLI) flags

Command-line flags will always override values set in the TOML config file.
For example, if `config.toml` contains `listen-addr = "127.0.0.1:8080"`, but the user runs `$ spoofdpi --listen-addr :9090`, the `:9090` port will be used.

## Config File Path

If a specific path is not provided via a `--config` flag, spoofdpi will search for `spoofdpi.toml` in the following locations in order, applying only the first file found:

- `$SPOOFDPI_CONFIG` environment variable
- `/etc/spoofdpi.toml`
- `$XDG_CONFIG_HOME/spoofdpi/spoofdpi.toml`
- `$HOME/.config/spoofdpi/spoofdpi.toml`

## Options

The configuration is organized into six main categories. Click on each category to view detailed options.

| Category | Description |
| :--- | :--- |
| **[App](app.md)** | Application-level options (mode, address, logging, etc.). |
| **[Connection](connection.md)** | Connection timeout and packet TTL settings. |
| **[DNS](dns.md)** | DNS resolution options. |
| **[HTTPS](https.md)** | HTTPS/TLS packet manipulation options. |
| **[UDP](udp.md)** | UDP packet manipulation options. |
| **[Rules](rules.md)** | Rule-based routing and automatic bypass policies. |

## Example

The following two methods will achieve the exact same configuration.

### Method 1: Using Command-Line Flags

All settings are passed directly via flags.

```console
$ spoofdpi --app-mode socks5 --dns-mode https --https-disorder
```

### Method 2: Using a TOML Config File

Place the settings in your `spoofdpi.toml` file:

```toml
[app]
mode = "socks5"

[dns]
mode = "https"

[https]
disorder = true
```

Then, run spoofdpi without those flags (it will automatically load the file if placed in a standard path):

```console
$ spoofdpi
```
