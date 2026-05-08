.PHONY: build test lint fmt fmt-check pre-commit docs

build:
	go build ./cmd/...

test:
	go test $(ARGS) -race -tags network ./...

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

docs:
	mkdocs serve
