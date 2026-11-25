.DEFAULT_GOAL := help
.PHONY: help build image run check lint generate generate-check vuln tidy-check fmt test clean

BIN_DIR ?= build/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# GOWORK=off: never pick up a go.work from a parent directory.
GO := GOWORK=off go
GO_BUILD := GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)"
LISTEN ?= 127.0.0.1:8080
CONFIG ?=

## help: list targets
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST)

## build: compile banoord and banoorctl into build/bin
build:
	$(GO_BUILD) -o $(BIN_DIR)/banoord ./cmd/banoord
	$(GO_BUILD) -o $(BIN_DIR)/banoorctl ./cmd/banoorctl

## image: build the banoor:local container image
image:
	docker build -t banoor:local --build-arg VERSION=$(VERSION) .

## run: build and start banoord on LISTEN with CONFIG (see the README's quick start)
run: build
	@test -n "$(CONFIG)" || { echo "set CONFIG to a configuration whose files exist, such as etc/config.json"; exit 1; }
	$(BIN_DIR)/banoord -listen $(LISTEN) -config $(CONFIG)

## check: lint, generated-code check, tests, govulncheck and tidy check
check: lint generate-check test vuln tidy-check

## lint: golangci-lint
lint:
	GOWORK=off golangci-lint run ./...

## generate: regenerate api/rest (ogen) from api/openapi.yaml
generate:
	$(GO) generate ./api/...

## generate-check: fail if committed generated code differs from the spec's output
generate-check: generate
	@test -z "$$(git status --porcelain -- api/rest)" || \
		{ git status --short -- api/rest; echo "generated code is stale: run make generate and commit it"; exit 1; }

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

## clean: remove build output
clean:
	rm -rf build
