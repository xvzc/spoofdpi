.PHONY: build test lint fmt fmt-check pre-commit claude

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

claude:
	mkdir -p .claude
	ln -sf ../.agents/rules .claude/rules
	ln -sf ../.agents/AGENTS.md .claude/CLAUDE.md
