.DEFAULT_GOAL := help
.PHONY: help check lint vuln tidy-check fmt test

# GOWORK=off: never pick up a go.work from a parent directory.
GO := GOWORK=off go

## help: list targets
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST)

## check: lint, tests, govulncheck and tidy check
check: lint test vuln tidy-check

## lint: golangci-lint
lint:
	GOWORK=off golangci-lint run ./...

## vuln: report known vulnerabilities in the Go dependency graph
vuln:
	$(GO) tool govulncheck ./...

## tidy-check: fail if go.mod or go.sum would change under go mod tidy
tidy-check:
	$(GO) mod tidy -diff
	$(GO) mod verify

## fmt: format Go sources
fmt:
	GOWORK=off golangci-lint fmt ./...

## test: Go tests (set BANOOR_TEST_CLICKHOUSE_DSN to include ClickHouse)
test:
	$(GO) test -race ./...