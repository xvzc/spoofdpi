# AGENTS.md

## Project

spoofdpi is a proxy that bypasses Deep Packet Inspection (DPI), the technique many
censorship systems use to inspect and block traffic. It fragments and desynchronizes
TLS handshakes, and can send low-TTL fake packets, so DPI middleboxes misparse the
connection while the server handles it normally. It runs as an HTTP proxy, a SOCKS5
proxy, or a TUN device, on macOS, Linux, and FreeBSD.

## Developer Guide

How to build, test, lint, commit, and update the docs is in
`docs/developer-guide/`. Read it before you change code, and follow it.
