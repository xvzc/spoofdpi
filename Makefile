.PHONY: build test test-unit test-network test-root test-e2e test-all lint fmt fmt-check pre-commit

# The e2e binary, relative to the repository root. The recipes make it
# absolute with the shell, so the Makefile works with GNU and BSD make.
E2E_BIN = out/e2e/spoofdpi

# The command that runs root steps. Without a terminal, use
# SUDO="sudo -A" with SUDO_ASKPASS set.
SUDO ?= sudo

build:
	go build ./cmd/...

# The default test run, as in CI: unit and network tests.
test: test-network

# Tests without a build tag.
test-unit:
	go test $(ARGS) -race ./... -v

# Unit tests plus the tests tagged network, which read the host's routes.
test-network:
	go test $(ARGS) -race -tags network ./... -v

# Tests named ...RequireRoot. Go builds them as the current user and runs
# only the test binaries through sudo. -p 1 runs one package at a time:
# the TUN tests of several packages share /dev/tun.
test-root:
	$(SUDO) -v
	go test $(ARGS) -exec "$(SUDO)" -tags network -count=1 -p 1 -v -run RequireRoot ./internal/...

# End-to-end tests: build spoofdpi, check that it refuses to send fakes
# without root, then run proxy and TUN mode as root. Pass test flags such as
# -url with E2E_ARGS.
test-e2e:
	mkdir -p out/e2e
	go build -o $(E2E_BIN) ./cmd/spoofdpi
	go test -tags e2e -count=1 -v -run NonRoot ./test/e2e/ -args -bin="$$(pwd)/$(E2E_BIN)" $(E2E_ARGS)
	$(SUDO) -v
	go test -exec "$(SUDO)" -tags e2e -count=1 -v -run RequireRoot ./test/e2e/ -args -bin="$$(pwd)/$(E2E_BIN)" $(E2E_ARGS)

# Everything a change to fake packets, capture, routes, or TUN setup needs.
test-all: test test-root test-e2e

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

fmt-check:
	golangci-lint fmt --diff

pre-commit:
	$(MAKE) test
	$(MAKE) fmt-check
	$(MAKE) lint

