![Image title](../static/banner.jpg)

# Introduction

**spoofdpi** is a lightweight, flexible tool designed to circumvent *[Deep Packet Inspection (DPI)](https://en.wikipedia.org/wiki/Deep_packet_inspection)* through advanced packet manipulation. It is written in [Go](https://go.dev), supports cross-platform execution, and operates with minimal overhead.

## Features

- **High Performance**: Low latency achieved through the Go runtime and cache
- **Built-in DNS Resolver**: Use built-in DNS resolvers without a need to change system settings
- **Flexible Rules**: Per-domain and per-CIDR rules to block, skip, or tune the bypass
- **Easy Configuration**: Simple setup via a [TOML](https://toml.io/en/) file
- **Cross-Platform**: Runs on macOS, Linux and FreeBSD

