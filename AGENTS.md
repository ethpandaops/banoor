# banoor

banoor scores network sources from configurable queries and serves a signed
ban list.

## Commands

`make help` lists every target.

```bash
make lint test      # golangci-lint; go test -race
make check          # lint, test, govulncheck, tidy-check
make fmt            # gofumpt, goimports
```

- Before finishing, run `make lint test`.
- Run Go through `make`; run directly, Go needs `GOWORK=off`.

## Layout

- One package under `internal/` per concern. It owns its goroutines, takes an
  injected `*slog.Logger` and returns concrete types; each consumer declares
  the small interface it needs.
- A decision that should be a pure function of its inputs goes under `pkg/`
  (the engine, address units, list parsing, the sshd parser, signing). Lint
  and the boundary test keep `pkg/` free of `internal/`, `api/`, `net/http`,
  database clients, the process clock and `rand`: pass time in.
- Files are read in `internal/`; `pkg/` parses bytes.
- To restrict who may import a package, add an entry to `boundaries` in
  `internal/testutil/importguard/boundary_test.go`, and a `depguard` rule in
  `.golangci.yml` when lint-time feedback helps.

## Go

- Use the injected logger and its `…Context` methods when a context is in
  scope (sloglint). A request's context adds its ID to every line.
- Where a test needs to control time, inject the clock; never `time.Now` in
  `pkg/`.

## Rules

- Fix lint findings rather than suppressing them. A suppression covers one
  line, names the rule and says why: `//nolint:<linter> // why`. Unused ones
  fail lint.
- Examples, tests and docs use documentation addresses only (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and generic names.
