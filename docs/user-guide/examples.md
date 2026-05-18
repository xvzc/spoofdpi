# Configuration Examples

This page provides various configuration examples to help you set up spoofdpi for different scenarios.

## Basic Setup

A minimal configuration to get started with DNS over HTTPS (DoH) and basic DPI bypass.

```toml
[dns]
mode = "https"
https-url = "https://dns.google/dns-query"
```

## Aggressive Bypass

If the default settings are not enough, you can try more aggressive settings. This configuration uses multiple fake packets and disorders the Client Hello.

```toml
[https]
fake-count = 5
fake-packet = [0x16, 0x03, 0x01] # Simple fake Client Hello prefix
disorder = true
split-mode = "chunk"
chunk-size = 1
```

## Rule-Based Routing

Route traffic differently based on the domain or IP address.

```toml
# Block ads
[[rules]]
name = "block ads"
match = { domains = ["ads.example.com"] }
block = true

# Bypass DPI for specific blocked site
[[rules]]
name = "unblock site"
match = { domains = ["blocked-site.com"] }
https = { fake-count = 2, disorder = true }

# Use local network directly (no processing)
[[rules]]
name = "local bypass"
match = { cidrs = ["192.168.0.0/16"] }
https = { skip = true }
```
