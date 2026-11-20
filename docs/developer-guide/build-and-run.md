# Build and Run

This project utilizes `CGO` for low-level networking capabilities, requiring specific dependencies and build flags.

## Prerequisites

* **Go Version:** Go **1.26 or higher** is required.
* **C Compiler:** A C compiler (GCC or Clang) must be available on your system.
* **Network Dependency:** The project relies on the **libpcap** library for packet capture functionality. You must install the development headers for this library before building.

### Dependency Installation Examples

| Distribution | Command |
| :--- | :--- |
| **Debian/Ubuntu** | `sudo apt update && sudo apt install libpcap-dev` |
| **Fedora/RHEL** | `sudo dnf install libpcap-devel` |
| **macOS (Homebrew)** | `brew install libpcap` |


## Running from Source Code

To run the application without building an executable, use the standard `Go` command. Command-line arguments can be passed directly after the package path.

```console
$ go run ./cmd/spoofdpi --tls-split-mode chunk:1
```

## Building an Executable

To build the executable, ensure **CGO is enabled** and run the standard Go build command targeting the `/cmd` directory:

```console
$ CGO_ENABLED=1 go build -ldflags="-w -s" ./cmd/...
```
