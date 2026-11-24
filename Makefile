.PHONY: build test test-unit test-network test-root test-e2e test-all lint fmt fmt-check pre-commit

E2E_BIN := $(CURDIR)/out/e2e/spoofdpi

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
# only the test binaries through sudo.
test-root:
	sudo -v
	go test $(ARGS) -exec sudo -tags network -count=1 -v -run RequireRoot ./internal/...

# End-to-end tests: build spoofdpi, check that it refuses to send fakes
# without root, then run proxy and TUN mode as root. Pass test flags such as
# -url with E2E_ARGS.
test-e2e:
	mkdir -p $(dir $(E2E_BIN))
	go build -o $(E2E_BIN) ./cmd/spoofdpi
	go test -tags e2e -count=1 -v -run NonRoot ./test/e2e/ -args -bin=$(E2E_BIN) $(E2E_ARGS)
	sudo -v
	go test -exec sudo -tags e2e -count=1 -v -run RequireRoot ./test/e2e/ -args -bin=$(E2E_BIN) $(E2E_ARGS)

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

