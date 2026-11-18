# HTTPS Configuration

Settings for manipulating HTTPS/TLS packets to bypass DPI.

## `split-mode`

`type: string`

### Description

Specifies the default packet fragmentation strategy to use for the Client Hello packet. `(default: "sni")`

### Allowed Values

- `sni`: Splits the packet right after the SNI extension.
- `random`: Splits the packet at a random position.
- `chunk`: Splits the packet into fixed-size chunks (controlled by `https-chunk-size`).
- `first-byte`: Splits only the first byte of the packet.
- `custom`: Uses custom segment plans (TOML only).
- `none`: Disables fragmentation.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --https-split-mode sni
```

**TOML Config**
```toml
[https]
split-mode = "sni"
```

---

## `chunk-size`

`type: uint8`

### Description

Specifies the chunk size in bytes for packet fragmentation. `(default: 35, max: 255)`

This value is only applied when `https-split-mode` is set to `chunk`.
Try lower values if the default fails to bypass the DPI.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --https-chunk-size 1
```

**TOML Config**
```toml
[https]
chunk-size = 1
```

---

## `disorder`

`type: boolean`

### Description

Specifies whether to disorder fragmented Client Hello packets. `(default: false)`

When enabled, this option varies the TTL of fragmented Client Hello packets, potentially causing them to arrive out of order. This complicates the packet reassembly process for DPI systems.

!!! note
    If split mode is `none`, disordering does not occur.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --https-disorder
```

**TOML Config**
```toml
[https]
disorder = true
```

---

## `fake-count`

`type: uint8`

### Description

Specifies the number of fake packets to be sent before the actual Client Hello. `(default: 0)`

Sending fake packets can trick DPI systems into inspecting invalid traffic, allowing the real Client Hello to pass through.
If `https-chunk-size` is greater than 0, each fake packet will also be fragmented.

Fake packets carry the connection's real TCP sequence numbers, learned from the server's SYN/ACK, so they overlap the real Client Hello. This applies to IPv4 servers with public addresses. For IPv6 or private addresses, or if the sequence numbers cannot be learned in time (100ms), random ones are used instead.

!!! note
    spoofdpi must be run with root privileges to use this option effectively on some systems or configurations requiring raw socket access (though usually not required for standard usage, verify if this note from old docs is still accurate - kept for safety).

### Usage

**Command-Line Flag**
```console
$ spoofdpi --https-fake-count 7
```

**TOML Config**
```toml
[https]
fake-count = 7
```

---

## `fake-packet`

`type: byte array`

### Description

Customizes the content of the fake packets used by `https-fake-count`. `(default: built-in fake packet)`

The value should be a sequence of bytes representing a valid (or semi-valid) TLS Client Hello or other protocol data.

### Usage

**Command-Line Flag**
Provide a comma-separated string of hexadecimal bytes (e.g., `0x16, 0x03, 0x01, ...`).

```console
$ spoofdpi --https-fake-packet "0x16, 0x03, 0x01, 0x00, 0xa1, ..."
```

**TOML Config**
Provide an array of integers (bytes).

```toml
[https]
fake-packet = [0x16, 0x03, 0x01, 0x00]
```

---

## `skip`

`type: boolean`

### Description

If set to `true`, HTTPS traffic will be processed without any DPI bypass techniques (fragmentation, disordering, etc.). It effectively treats the connection as a standard HTTPS proxy connection.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --https-skip
```

**TOML Config**
```toml
[https]
skip = true
```

---

## `custom-segments`

`type: array of segment plans`

### Description

Defines custom segmentation plans for fine-grained control over how the Client Hello packet is split. This option is only used when `split-mode` is set to `"custom"`.

Each segment plan specifies where to split the packet relative to a reference point (`from`) with an offset (`at`).

!!! note
    This option is only available via the TOML config file.

!!! important
    When using `custom` split-mode, the global `disorder` option is **ignored**. Use the `lazy` field in each segment plan to control packet ordering instead.

### Segment Plan Fields

| Field   | Type    | Required | Description |
| :------ | :------ | :------- | :---------- |
| `from`  | String  | Yes      | Reference point: `"head"` (start of packet) or `"sni"` (start of SNI extension). |
| `at`    | Int     | Yes      | Byte offset from the reference point. Negative values count backwards. |
| `lazy`  | Boolean | No       | If `true`, delays sending this segment (equivalent to disorder). `(default: false)` |
| `noise` | Int     | No       | Adds random noise (in bytes) to the split position. `(default: 0)` |

### Usage

**TOML Config**

```toml
[https]
split-mode = "custom"
custom-segments = [
    { from = "head", at = 2 },                    # Split 2 bytes from start
    { from = "sni", at = 0 },                     # Split at SNI start
    { from = "sni", at = -5, lazy = true },       # Split 5 bytes before SNI, delayed
    { from = "head", at = 100, noise = 10 },      # Split at ~100 bytes with ±10 noise
]
```
