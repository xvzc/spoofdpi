# Live Test

Whether a DPI bypass option works depends on the network it runs on. `spoofdpi livetest` runs spoofdpi with different options on your network and reports how many requests through each succeed:

```console
$ sudo spoofdpi livetest --tries 10 \
    --url https://example.com/ \
    --add "label:preflight, --tls-fake-preflight 2" \
    --add "label:stutter, --tls-fake-stutter 1 --tls-split-mode chunk:10"
baseline config: /home/user/.config/spoofdpi/spoofdpi.toml

CASE       URL                   OK     OUTCOMES  WARN  ERR
config     https://example.com/  10/10  200x10    0     0
preflight  https://example.com/  10/10  200x10    0     0
stutter    https://example.com/  10/10  200x10    0     0
```

!!! warning
    Stop any other running spoofdpi before you start a live test. A starting spoofdpi resets the system network settings left by an earlier run, such as the system proxy, so each case of the test changes the network state of a spoofdpi that is already running.

## How It Works

Each case starts spoofdpi as a separate process with its own options, sends `--tries` requests to every `--url` through it, then stops it. Cases run one after another, in the order they are given.

- Every request uses a new connection, so each one goes through a new TLS handshake.
- Requests send the `User-Agent` of a desktop Chrome, since some sites answer other clients with an error page. `--user-agent` changes it.
- Redirects are not followed: any HTTP response counts as a success, and the `OUTCOMES` column shows the status codes. A request that gets no response counts as `timeout`, `reset` or `error`.
- The `WARN` and `ERR` columns count the warnings and errors spoofdpi logged after its server started, while the requests ran. Messages logged while it starts, such as a missing config file or a deprecated option, are not counted.
- Progress, and cases that fail to start, are reported on the standard error.

Run it as root, for example with `sudo`, so that spoofdpi can send fake packets. One `sudo` covers every case. Without root, livetest prints a warning and runs anyway.

## Cases

### Baseline

The baseline case, labeled `config`, runs first. It runs spoofdpi with no extra options and loads your config file the same way `spoofdpi run` does: the file given with `--config`, or otherwise the first file found in the [default locations](overview.md#config-file-path). The line above the table shows the file it loaded, or `none (defaults)` when spoofdpi found none.

`--no-baseline` skips the baseline case. At least one `--add` is then required.

### Adding Cases

Each `--add` adds a case, in the form `"label:NAME, ARGS"` or `"ARGS"`:

```console
$ sudo spoofdpi livetest --url https://example.com/ \
    --add "label:hello-world, --tls-fake-stutter 1 --tls-split-mode chunk:10" \
    --add "--tls-fake-packet 0x16,0x03,0x01 --tls-fake-preflight 1"
```

- `ARGS` are spoofdpi options, split on white space. Quotes are not interpreted.
- With `label:`, the label ends at the first comma, and everything after that comma is `ARGS`. Commas inside `ARGS`, such as in `0x16,0x03,0x01`, are kept.
- Without `label:`, the case is labeled `add-N`, where `N` is the position of the `--add` among all `--add` options. In the example above, the second case is labeled `add-2`.
- A label may contain letters, digits, `.`, `_` and `-`. Labels must be unique, and `config` is reserved for the baseline case.

Cases added with `--add` run with `--clean`, so no config file is loaded, unless `--config` is given. With `--config FILE`, every case loads `FILE` and its own options override it.

### Ignored Arguments

A case may set any spoofdpi server option except the ones livetest sets itself. livetest drops other flags, and arguments that are not options or their values, from a case's arguments. It prints a warning for each on the standard error and runs the case without them:

```console
$ sudo spoofdpi livetest --url https://example.com/ \
    --add "label:t, --config /tmp/a.toml --tsl-fake-stutter 1 --tls-fake-stutter 1"
livetest: case "t": ignored --config /tmp/a.toml (set by livetest)
livetest: case "t": ignored unknown flag --tsl-fake-stutter
livetest: case "t": ignored argument 1
...
```

| spoofdpi option | Why it is ignored |
| :--- | :--- |
| `--app-mode` | Set by livetest; use `--mode`. |
| `--listen-addr` | Set by livetest; use `--listen`. |
| `--config`, `-c`, `--clean` | Set by livetest; use `--config`. |
| `--log-level` | Always `debug`, so that livetest can read spoofdpi's log. |
| `--no-tui` | Always set by livetest. |
| `--auto-configure-network` | Always `false`, so that a config file cannot change the system proxy during a test. |
| `--help`, `-h`, `--version`, `-v` | A case runs the server. |
| Any flag spoofdpi does not have | Unknown; it may be a typo. |
| An argument that is not an option or its value, such as `help`, `-` or `-5` | spoofdpi ignores it, and one that starts with `-` would end spoofdpi's option parsing. |

Every spelling of a flag is recognized: `--name`, `-name`, `--name=value` and `-name=value`. When an ignored option takes a value, such as `--config FILE`, the value is dropped with it. An unknown flag is dropped alone, so a value after it is dropped as an argument, as `1` is in the example above. The value of an option a case may set is the next argument even if it starts with `-`, as in `--tls-fake-seq-offset -10`.

## Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `--url` | | `http` or `https` URL with a host, to request through spoofdpi. Repeatable; at least one is required. |
| `--add` | | Case to test. Repeatable. |
| `--tries` | `10` | Number of requests per URL and case. |
| `--timeout` | `10s` | Timeout of each request. |
| `--start-timeout` | `1m` | Time to wait for spoofdpi to start. |
| `--mode` | `http` | Proxy mode spoofdpi runs in: `http` or `socks5`. `tun` is not supported. |
| `--listen` | `127.0.0.1:18080` | `ip:port` address spoofdpi listens on. |
| `--config` | | spoofdpi config file for every case. It must be an existing file. |
| `--user-agent` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36` | `User-Agent` header of each request. It must not be empty. |
| `--out` | | Directory to write each case's log to, as `<label>.log`. Without it, no logs are written. |
| `--no-baseline` | `false` | Skips the baseline case. |

Options of the server, such as `--tls-fake-stutter`, are not livetest options; give them to a case with `--add`.

## Logs

With `--out DIR`, each case's spoofdpi log is written to `DIR/<label>.log`, and a line below the table shows where:

```console
$ sudo spoofdpi livetest --url https://example.com/ --out ./livetest-logs
...
logs: ./livetest-logs/<case>.log
```

## Exit Status

livetest exits with a non-zero status only when the test cannot run, or when it is interrupted:

- An invalid option, such as a `--url` without `http://` or `https://`, or a `--out` directory that cannot be created, exits with `1` before any case runs.
- Once the test runs, it exits with `0` whatever the results, including when a case has ignored arguments or fails to start.
- Ctrl+C (`SIGINT`), `SIGTERM` or `SIGHUP` stops the running case and prints the report of the results so far. A URL that has no results yet has no row. livetest then exits with 128 plus the signal number: `130` for `SIGINT`, `143` for `SIGTERM` and `129` for `SIGHUP`.
