# banoor

`banoord` scores network sources from configurable queries and serves a
signed ban list; `banoorctl` checks the operator's lists. [README.md](README.md)
maps each part to its files.

## Commands

`make help` lists every target.

```bash
make lint test      # golangci-lint; go test -race
make generate       # regenerate api/rest from api/openapi.yaml
make check          # lint, generate-check, test, govulncheck, tidy-check
make fmt            # gofumpt, goimports
make build          # build/bin/banoord and build/bin/banoorctl
```

- Before finishing, run `make lint test`. Set
  `BANOOR_TEST_CLICKHOUSE_DSN` (for example
  `clickhouse://default@127.0.0.1:9000`) to include the ClickHouse
  integration test, as CI does.
- `make generate-check` compares generated code with git, so it fails until
  regenerated code is committed.
- Run Go through `make`; run directly, Go needs `GOWORK=off`.

## Layout

- One package under `internal/` per concern. It owns its goroutines, takes an
  injected `*slog.Logger` and returns concrete types; each consumer declares
  the small interface it needs (the scorer's `Source`, the server's `Lists`).
- A decision that should be a pure function of its inputs goes under `pkg/`
  (the engine, address units, list parsing, the sshd parser, signing). Lint
  and the boundary test keep `pkg/` free of `internal/`, `api/`, `net/http`,
  database clients, the process clock and `rand`: pass time in.
- Files are read in `internal/`; `pkg/` parses bytes.
- To restrict who may import a package, add an entry to `boundaries` in
  `internal/testutil/importguard/boundary_test.go`, and a `depguard` rule in
  `.golangci.yml` when lint-time feedback helps.

## API

- `api/openapi.yaml` is the source of truth. `api/rest/` (ogen server) is
  generated from it: never edit it; commit it.
- To add or change an operation: edit the spec, run `make generate`, then
  implement the method on `operations` in `internal/server` (the build fails
  until it exists), with a Go test. `TestEveryOperationIsServed` checks every
  operation answers with its declared content type.
- Paths live under `/api/v1/`; JSON fields are camelCase, except the signed
  payload, whose v1 field names are a published contract
  ([docs/list-format.md](docs/list-format.md)): never rename them.
- Every operation's `default` response is the RFC 9457 `Problem`.
- `/metrics` is hand-routed beside the spec.
- The spec has no linter in CI: ogen rejects what it cannot generate.
  `Envelope.payload` names `Payload` as its `contentSchema`, and
  `TestPayloadMatchesTheSpec` fails when the signed payload's fields and the
  spec's `Payload` and `Entry` differ.

## Go

- Use the injected logger and its `…Context` methods when a context is in
  scope (sloglint). A request's context adds its ID to every line.
- Where a test needs to control time, inject the clock (`scorer.New`'s `now`),
  never `time.Now` in `pkg/`.

## Rules

- Fix lint findings rather than suppressing them. A suppression covers one
  line, names the rule and says why: `//nolint:<linter> // why`. Unused ones
  fail lint.
- Examples, tests and docs use documentation addresses only (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and generic names.
