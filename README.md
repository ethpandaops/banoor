# banoor

A Go daemon (`banoord`) that scores network sources from evidence you already
collect and serves a signed list of the ones to block. It runs your queries on
a schedule, adds up weighted points per source over a window, bans sources
that reach a threshold, and publishes a signed, versioned list that hosts or
firewalls pull. Caps keep a bad input from producing a bad list, and a kill
switch empties or defuses the list within one run.

Rules and layout: [AGENTS.md](AGENTS.md). Reference:
[docs/configuration.md](docs/configuration.md),
[docs/list-format.md](docs/list-format.md).

## Quick start

Go 1.27 and golangci-lint 2.15 (`.tool-versions`).

```bash
make check                                  # what CI runs
make build && build/bin/banoord -h          # flags
```

To run it against ClickHouse:

1. Create the state tables, and a signal table if you need one:
   [`examples/schema.sql`](examples/schema.sql).
2. Lay out the files [`examples/config.json`](examples/config.json) names,
   create a signing key and print the line consumers pin:

   ```bash
   mkdir -p etc/allowlist secrets
   cp examples/config.json etc/config.json
   echo '{"entries": []}' > etc/manual.json
   ssh-keygen -t ed25519 -N "" -C banoor -f secrets/signing-key
   build/bin/banoorctl pubkey -key secrets/signing-key -principal list-signer -namespace example-banlist
   ```

3. Put the ClickHouse password in `secrets/clickhouse-password`, and point
   `source.dsn` in `etc/config.json` at your server, by a name the container
   can reach (`--network` for a server in another container).
   `allow.fetchers` believes the `X-Forwarded-User` and `X-Real-Ip` headers
   from `trustedProxies` alone: set that to the proxy in front, which must
   set or strip both, or remove `allow.fetchers`.
4. Run the image, as your own user so it can read the key, on loopback only:

   ```bash
   docker run --rm -p 127.0.0.1:8080:8080 --user "$(id -u):$(id -g)" \
     -v "$PWD/etc:/etc/banoor:ro" -v "$PWD/secrets:/run/secrets:ro" \
     ghcr.io/ethpandaops/banoor:0.2.0
   ```

   On Kubernetes the image runs as user 65532: set the pod's `fsGroup` so it
   can read a secret mounted group-readable. The image holds `banoorctl` too
   (`--entrypoint banoorctl`).

`GET /api/v1/list` answers 503 until the first run succeeds;
`/api/v1/health`, `/metrics` and `/openapi.yaml` answer at once.

## Parts

What each does, and where it lives.

- **Signals as configuration.** Each signal is a query, a weight per attempt,
  a cap per source and a mode (`count`, or `shadow` to measure it first).
  Sources are an IPv4 address or an IPv6 network (/64 by default); ranges only
  come from a person. `internal/config/`, `internal/scorer/inputs.go`.
- **Scoring engine.** Points, the threshold, ban lengths that double for
  repeat offenders, and the caps: new bans per hour and per feeder, entries,
  coverage, additions per generation. Past a cap the highest-priority entries
  win and the rest wait. A pure decision package. `pkg/engine/`.
- **Allowlists.** Files, queries filtered by pinned keys (such as SSH logins
  with a known key), the addresses consumers fetch the list from, and the
  special-purpose ranges. `internal/lists/`, `internal/scorer/fetchers.go`,
  `pkg/netaddr/`.
- **Manual list.** Bans and lifts with an expiry and a reason, checked by
  `banoorctl validate` before they merge. `pkg/manual/`, `cmd/banoorctl/`.
- **Safe SSH extraction.** Takes the client address from the parts of sshd's
  lines a client cannot control; the patterns work in ClickHouse unchanged.
  `pkg/sshlog/`.
- **Signed, fresh lists.** OpenSSH signatures (`ssh-keygen -Y verify`), a
  generation that only goes up, and a new signature every refresh. A new
  generation is recorded before it is served. `pkg/sshsig/`,
  `internal/publish/`.
- **Kill switch and state.** The newest row of a control table sets
  `enforce`, `shadow` or `empty`; bans, publishes and fetchers are recorded,
  so a restart loses nothing. `internal/scorer/state.go`.
- **ClickHouse source.** The official Go client, native or HTTP protocol.
  `internal/clickhouse/`.
- **Spec-first API.** `api/openapi.yaml` generates the ogen server in
  `api/rest/`; `make generate-check` fails on stale output.
  `internal/server/`.
- **Import boundaries.** Who may import what, as a Go test, with lint twins.
  `internal/testutil/importguard/`, `.golangci.yml`.
- **Image and CI.** Static binaries on distroless, nonroot; CI runs the api,
  go and image jobs, the go job's tests against a real ClickHouse; releases publish
  `ghcr.io/ethpandaops/banoor` for amd64 and arm64 with provenance.
  `Dockerfile`, `.github/workflows/`.

Not included: authentication (put an authenticating proxy in front), TLS,
sources other than ClickHouse, alerting.

## License

[MIT](LICENSE)
