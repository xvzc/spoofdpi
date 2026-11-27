# Running Tests

This document describes how to run the tests in spoofdpi, from the unit tests to the root-privileged and end-to-end tests. For how to write tests, see [Writing Test Code](writing-tests.md).

## Make Targets

| Target | Runs | Needs root |
| --- | --- | --- |
| `make test` | Unit and network tests, as in CI (same as `make test-network`) | no |
| `make test-unit` | Tests without a build tag | no |
| `make test-network` | Unit tests and the tests tagged `network` | no |
| `make test-root` | [Root-privileged tests](#root-privileged-tests) | yes |
| `make test-e2e` | Builds spoofdpi, then runs the [end-to-end tests](#end-to-end-tests) | yes |
| `make test-all` | `test`, `test-root`, and `test-e2e`, in that order | yes |

Pass extra `go test` flags with `ARGS`, such as `make test ARGS="-run TestFoo"`, and end-to-end flags with `E2E_ARGS`, such as `make test-e2e E2E_ARGS="-url https://example.org/"`. The sections below show the commands each target runs.

## Common Commands

To run the tests without a build tag, use the standard `go test` command from the root directory:

```console
$ go test ./...
```

To run all tests, including tests that require network access, pass the `network` build tag:

```console
$ go test -tags network ./...
```

To run all tests with verbose output (showing all test names):

```console
$ go test -v -tags network ./...
```

To run a specific test function (e.g., `TestCreateCommand_Flags`):

```console
$ go test -v -run TestCreateCommand_Flags ./internal/config/
```

## Test Kinds

| Kind | Where | Runs in CI |
| --- | --- | --- |
| Unit tests | `_test.go` files without a build tag | yes |
| Network tests | files tagged `network`; they read the host's routing table | yes |
| Root-privileged tests | `network` tests whose name ends in `RequireRoot` | no (they skip) |
| End-to-end tests | `test/e2e/`, tagged `e2e`; they run the built binary | no |

Root-privileged and end-to-end tests cover what the others cannot: fake packets sent from raw sockets, the interface they leave through, TUN routes, and the reset after shutdown. They need root and real network access, so they run by hand. Run them after a change to fake packet sending, capture, route lookup, or TUN setup, on every OS the change touches (macOS, Linux, and FreeBSD).

A test that needs root calls `testutil.RequireRoot(t)` and ends its name in `RequireRoot`. Without root it skips; `-run RequireRoot` selects it.

## Root-Privileged Tests

Run them with `make test-root`. It runs the command below: Go builds the tests as your user and runs only the test binaries through `sudo`.

```console
$ sudo -v
$ go test -exec sudo -tags network -count=1 -v -run RequireRoot ./internal/...
```

Running `sudo -v` first caches your credentials, so the test binaries don't each ask for the password. Without a terminal, such as over a non-interactive SSH session, sudo may not cache them; then set `SUDO_ASKPASS` to a program that prints the password and use `-exec "sudo -A"` instead of `-exec sudo`, or pass `SUDO="sudo -A"` to the make targets, such as `make test-root SUDO="sudo -A"`. Keep `-run RequireRoot`: without it, every test in `./internal/...` runs as root.

## End-to-End Tests

The end-to-end tests run a spoofdpi binary in HTTP proxy mode and in TUN mode with `--tls-fake-preflight 1`. They capture the low-TTL fake packets with libpcap on the physical interface and on the TUN, fetch a few sites through spoofdpi, stop it with SIGINT, and compare the routes, rules, and interfaces with a snapshot taken before the start.

Run them with `make test-e2e`, which builds spoofdpi first and then runs the commands below. The tests never build spoofdpi themselves, because the Go toolchain is usually not on root's `PATH` under `sudo`. When you run the commands by hand, build it first, and again after every source change:

```console
$ mkdir -p out/e2e
$ go build -o out/e2e/spoofdpi ./cmd/spoofdpi
```

Startup without root must fail with a message that names the remedy:

```console
$ go test -tags e2e -count=1 -v -run NonRoot ./test/e2e/ -args -bin="$PWD/out/e2e/spoofdpi"
```

Proxy mode and TUN mode, as root:

```console
$ sudo -v
$ go test -exec sudo -tags e2e -count=1 -v -run RequireRoot ./test/e2e/ -args -bin="$PWD/out/e2e/spoofdpi"
```

TUN mode routes the host's traffic into the TUN for a few seconds. On a remote host, make sure the session survives that, or run it from the console.

Options, passed after `-args`:

| Option | Default | Meaning |
| --- | --- | --- |
| `-bin` | `out/e2e/spoofdpi` | The spoofdpi binary to run. |
| `-url` | `https://www.youtube.com/`, `https://example.com/` | Sites to fetch; repeatable or comma-separated. |
| `-port` | `18089` | The proxy port in HTTP proxy mode. |
| `-start-timeout` | `20s` | How long to wait for spoofdpi to start. |
| `-out` | `out/e2e/fake-egress-<time>` | Where the artifacts go. |

Each check is a subtest, such as `TestFakeEgress_TUN_RequireRoot/fakes-on-tun`, and logs its evidence (counts, interfaces, TTLs). spoofdpi runs with `--log-level trace`. Each mode keeps `spoofdpi.log`, `before.txt`, `after.txt`, and on a failed reset `reset.diff` in its artifacts directory.

| Check | Passes when |
| --- | --- |
| `no-state-file`, `no-state-file-after-exit` | spoofdpi wrote no `/tmp/spoofdpi*.state` file since the snapshot, while running and after exit. |
| `fetch/<host>` | The site answers 2xx or 3xx through spoofdpi. |
| `fakes-on-physical` | Low-TTL fakes leave through the physical interface. |
| `fakes-ttl-above-1` | No captured fake has a TTL of 1 or less, which expires at the first hop. |
| `fake-log` | The log shows `sent fake packets`. |
| `bad-checksums` | No captured fake has a wrong TCP checksum. |
| `fakes-on-tun` | TUN mode only: no fake loops into the TUN. |
| `graceful-exit` | TUN mode only: spoofdpi exits 0 within 15 s of SIGINT. |
| `reset-diff` | TUN mode only: routes, rules, and interfaces match the snapshot. |
| `tun-removed` | TUN mode only: the TUN interface is gone. |

`TestFakeEgress_NonRoot` passes when startup without root exits non-zero and names the root requirement and the remedy.

Some failures come from the network, not from spoofdpi:

- `reset-diff` fails when a VPN, DHCP, or another tool changes routes during the run. Read `reset.diff`, and rerun once if the change is unrelated.
- `fetch/<host>` can fail when a fake reaches the server, for example when the learned hop count is off by one. Check the TTLs in the log, and rerun once. To find the connection that taught a hop count, search `spoofdpi.log` for the SYN/ACK's `dst=<ip>:<port>` in a `ttl(tcp)` line, then for `local=<ip>:<port>` in a `new remote conn` line.

## Rules for Root-Privileged and End-to-End Runs

- Do not change routes, rules, FIBs, or interfaces by hand, and do not edit a test to make a check pass. If a check fails, stop and keep the evidence; rerun once only for the network-caused failures above, and keep both results.
- Never drop `-run RequireRoot` from a command that uses `-exec sudo`.
- When a TUN run does not reset, keep `reset.diff`, and report it before anyone touches the routes.
- Leave nothing running: check with `pgrep -lx spoofdpi` at the end.
