# AGENTS.md

## Project

spoofdpi is a proxy tool that bypasses Deep Packet Inspection (DPI) — the technique used by many internet censorship systems to inspect and block traffic. It works by fragmenting and desynchronizing TLS handshakes so that DPI middleboxes misparse the connection while the destination server handles it normally.

## Testing

```console
$ go test -tags network ./...
```

Use `go test ./...` to exclude network-dependent tests (e.g. sandboxed Nix builds).

## Formatting

```console
$ golangci-lint fmt   # format
$ golangci-lint run   # lint (config: .golangci.yml)
```

Or use `make fmt` / `make lint`.

## Documentation

Docs live in `docs/` and are served with `mkdocs serve`.

- `docs/user-guide/` — config options and runtime behavior
- `docs/getting-started/` — install, quick-start, introduction
- `docs/developer-guide/` — build/test/lint workflow, commit conventions

Update docs when a change adds, removes, or renames a config option, or changes user-observable runtime behavior. Pure refactors and internal changes don't require doc updates.
