# UDP Configuration

Settings for UDP packet manipulation and bypass techniques.

## `skip`

`type: boolean`

### Description

If set to `true`, UDP traffic will be processed without any DPI bypass techniques (fake packets, etc.). It effectively treats the connection as a standard UDP proxy connection. `(default: false)`

### Usage

**Command-Line Flag**
```console
$ spoofdpi --udp-skip
```

**TOML Config**
```toml
[udp]
skip = true
```

---

## `fake-count`

`type: int`

### Description

Specifies the number of fake packets to be sent before actual UDP packets. `(default: 0)`

Sending fake packets can trick DPI systems into inspecting invalid traffic, allowing real packets to pass through.

!!! note
    This feature requires root privileges and packet capture capabilities.

### Usage

**Command-Line Flag**
```console
$ spoofdpi --udp-fake-count 5
```

**TOML Config**
```toml
[udp]
fake-count = 5
```

---

## `fake-packet`

`type: byte array`

### Description

Customizes the content of the fake packets used by `udp-fake-count`. `(default: 64 bytes of zeros)`

The value should be a sequence of bytes representing the fake packet data.

### Usage

**Command-Line Flag**
Provide a comma-separated string of hexadecimal bytes (e.g., `0x00, 0x01, 0x02, ...`).

```console
$ spoofdpi --udp-fake-packet "0x00, 0x01, 0x02, 0x03, 0x04"
```

**TOML Config**
Provide an array of integers (bytes).

```toml
[udp]
fake-packet = [0x00, 0x01, 0x02, 0x03, 0x04]
```
