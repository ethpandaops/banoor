# banoor

banoor scores network sources from evidence you already collect, and serves a
signed list of the ones to block.

It runs your queries on a schedule, adds up weighted points per source over a
window, bans sources that reach a threshold, and publishes the result as a
signed, versioned list that hosts or firewalls can pull. Caps keep a bad input
from producing a bad list, and a kill switch stops enforcement within one run.

- **Signals are configuration.** Each signal is a query, a weight per attempt,
  a cap per source and a mode (`count`, or `shadow` to measure it before it
  counts). ClickHouse is the supported source.
- **Single sources only.** An IPv4 address, or an IPv6 network (a /64 by
  default) counted as one source. Ranges come only from a person, through the
  manual list.
- **Repeat offenders stay out longer.** A first ban lasts `ban.base`; each ban
  within `ban.repeatWindow` doubles it, up to `ban.max`.
- **Never ban these.** Allowlist files, allowlist queries (for example, every
  address that logged in with a known key in the last 30 days) and the
  special-purpose ranges always win.
- **Safe by default.** Past a cap, the highest-scoring sources are published
  and the rest wait. A run that cannot read an input publishes nothing, so
  consumers keep the last list they verified.
- **Signed and fresh.** Lists are signed in OpenSSH's signature format, carry
  a generation that only goes up, and are re-signed every minute, so
  consumers can reject stale or replayed lists with `ssh-keygen` alone.

## Quick start

1. Create the state tables, and a signal table if you need one:
   [`examples/schema.sql`](examples/schema.sql).
2. Create a signing key:

   ```sh
   ssh-keygen -t ed25519 -N '' -C banoor -f signing-key
   banoor pubkey -key signing-key -principal list-signer -namespace example-banlist
   ```

   The second command prints the `allowed_signers` line consumers pin.
3. Write a configuration, starting from [`examples/config.json`](examples/config.json).
4. Run it:

   ```sh
   docker run --rm -p 8080:8080 \
     -v "$PWD/config.json:/etc/banoor/config.json:ro" \
     -v "$PWD/signing-key:/run/secrets/signing-key:ro" \
     ghcr.io/ethpandaops/banoor:latest
   ```

banoor answers `503` until its first run succeeds, then serves the list at
`server.path` (default `/v1`), metrics at `/metrics` and a liveness check at
`/healthz`.

## How a run works

Every `interval` (default 30 s), banoor:

1. reads the kill switch (the newest row of `tables.control`, or
   `defaultMode` when it is empty);
2. runs every signal query and every allowlist query that is due;
3. rereads the allowlist files and the manual list;
4. scores each source: the sum over counting signals of
   `min(weight × attempts, cap)`;
5. bans sources at or over `threshold` that are not allowlisted, lifted or
   already banned, highest score first, within the caps;
6. records new bans and newly seen manual entries in `tables.decisions`;
7. publishes the list. A change of entries or mode is a new generation,
   recorded in `tables.publishes`. Otherwise the same generation is signed
   again once `refresh` (default 60 s) has passed.

On start, banoor rebuilds its bans and the last generation from those tables,
so a restart neither forgets a ban nor makes the generation go down.

### Caps

| Cap | Default | Past it |
| --- | --- | --- |
| `maxNewPerHour` | 200 | new bans wait for the next hour |
| `maxNewPerFeederPerHour` | 50 | new bans attributed to one feeder (the one that contributed most points) wait |
| `maxEntries` | 5000 | the lowest-priority entries are left off |
| `maxIPv4Addresses`, `maxIPv6Networks` | 2^20 | entries that would pass the coverage are left off |
| `maxAddedPerGeneration` | 500 | the rest are added in later generations |

Priority is manual bans first, then scored bans by points. Deferred sources
are considered again every run and show up in `banoor_deferred`.

### The kill switch

```sql
INSERT INTO banoor.control (Mode, Reason) VALUES ('empty', 'why')
```

| Mode | Published list |
| --- | --- |
| `enforce` | the list; consumers apply it in their own mode |
| `shadow` | the list, marked so consumers drop nothing |
| `empty` | no entries |

It takes effect at the next run, bypasses no allowlist, and needs no deploy.
After `empty`, entries come back at most `maxAddedPerGeneration` at a time.

## Signals

A signal's query returns one row per source and feeder over the window:

| Column | Type | Meaning |
| --- | --- | --- |
| `address` | string | the source address |
| `feeder` | string | who reported it, such as a host; caps are kept per feeder |
| `attempts` | number | how many times in the window |

`{window:UInt32}` in the query is the window in seconds, passed as a
ClickHouse query parameter.

```json
{
  "name": "invalid_user",
  "mode": "count",
  "weight": 1,
  "cap": 0,
  "query": "SELECT Address AS address, Feeder AS feeder, sum(Attempts) AS attempts FROM banoor.ssh_failures WHERE Kind = 'invalid_user' AND Minute >= now() - toIntervalSecond({window:UInt32}) GROUP BY address, feeder"
}
```

A signal with `"parser": "openssh"` returns a `line` column instead of
`address`, and only lines of the listed `kinds` count: `invalid_user`,
`not_allowed`, `penalty_drop`, `maxstartups_drop`, `auth_closed`. This is
convenient for small volumes; for large ones, aggregate in the database.

### Extracting SSH failures safely

sshd logs the user name a client sends verbatim, so a client can make a line
name an address it does not own:

```text
Invalid user x from 192.0.2.7 port 1 from 198.51.100.10 port 36465
```

Take the address from the fixed end of the line, never from its first
` from `. The patterns in [`internal/sshlog`](internal/sshlog/sshlog.go) do,
use RE2 syntax, and work unchanged in ClickHouse. For example, a materialized
view over a raw log table:

```sql
CREATE MATERIALIZED VIEW banoor.ssh_failures_mv TO banoor.ssh_failures AS
WITH
    multiIf(startsWith(Body, 'Invalid user '), 'invalid_user',
            startsWith(Body, 'User ') AND position(Body, ' not allowed because ') > 0, 'not_allowed',
            '') AS kind,
    multiIf(kind = 'invalid_user', extract(Body, '^Invalid user .* from (\\S+) port \\d+$'),
            kind = 'not_allowed', extract(Body, '^User \\S+ from (\\S+) not allowed because '),
            '') AS address
SELECT toStartOfMinute(Timestamp) AS Minute, Host AS Feeder, kind AS Kind, address AS Address, count() AS Attempts
FROM logs.sshd
WHERE kind != '' AND (isIPv4String(address) OR isIPv6String(address))
GROUP BY Minute, Feeder, Kind, Address
```

Only count lines written by the sshd process itself (for example, by user ID
0): any local user can write a log line that claims to come from sshd.

## Allowlists

- `allow.dir`: every `*.txt` file, one address or prefix per line, `#`
  comments. Reread every run; a broken file keeps the last good allowlist.
- `allow.queries`: each query returns `address` and optionally `key`. With
  `keysFile`, only rows whose key is listed there count, such as the SHA256
  fingerprints of the SSH keys you trust:

  ```json
  {"name": "logins", "window": "720h", "refresh": "1h", "keysFile": "/etc/banoor/fingerprints.txt",
   "query": "SELECT Address AS address, Fingerprint AS key FROM banoor.ssh_logins WHERE Hour >= now() - toIntervalSecond({window:UInt32}) GROUP BY address, key"}
  ```
- The special-purpose ranges (private, loopback, link-local, shared,
  multicast and reserved) are always allowed.

An allowed address inside a candidate (an allowed /128 in a /64) keeps the
whole candidate off the list.

## The manual list

`manualFile` is JSON, reread every run:

```json
{"entries": [
  {"action": "ban", "cidr": "203.0.113.0/24", "expires": "2030-01-08T00:00:00Z", "reason": "scanner range", "by": "alice"},
  {"action": "lift", "cidr": "198.51.100.7/32", "expires": "2030-01-02T00:00:00Z", "reason": "customer behind NAT"}
]}
```

A `ban` adds a prefix (no wider than `limits`, /24 and /48 by default); a
`lift` keeps a prefix off the list, overriding scored bans. Both need an
expiry and a reason. Check a list before merging it:

```sh
banoor validate -manual manual.json -allow-dir allowlist/
```

It fails on invalid or too-wide entries, bans that overlap the allowlist or a
lift, and expiries more than a year ahead, and warns about expired entries.

## The list format, version 1

The body is an envelope, so the payload and its signature always match:

```json
{"payload": "<base64 of the payload JSON>", "signature": "-----BEGIN SSH SIGNATURE-----\n..."}
```

The payload:

```json
{
  "version": 1,
  "generation": 1893499200,
  "previous_generation": 1893499140,
  "generated_at": 1893499230,
  "mode": "enforce",
  "entries": [
    {"cidr": "198.51.100.10/32", "expires": 1893585600, "source": "scorer", "reason": "invalid_user=57 in 24h, ban 1"},
    {"cidr": "203.0.113.0/24", "expires": 1894060800, "source": "manual", "reason": "scanner range"}
  ]
}
```

- `generation` only goes up, and changes only when `entries` or `mode` do.
  It is the Unix time of the change, or the previous generation plus one if
  that is higher. `previous_generation` is the one it replaces, 0 for the
  first.
- `generated_at` and `expires` are Unix seconds. An unchanged list is signed
  again every `refresh` with a new `generated_at` and the same generation.
- `cidr` is canonical; scored entries are single sources, wider ones come
  from the manual list. Entries are sorted by `cidr`.
- No allow entries are ever published. Unknown fields may be added within
  version 1; consumers should ignore them.

A consumer should:

1. verify the signature over the decoded payload bytes:

   ```sh
   ssh-keygen -Y verify -f allowed_signers -I list-signer -n example-banlist -s payload.sig < payload.json
   ```
2. reject a payload older than a few times `refresh`, or from the future;
3. reject a generation lower than the last one it loaded; treat an equal one
   as a freshness refresh;
4. apply its own limits (widest prefix, total coverage, size of a change
   from `previous_generation`), and its own allowlist, before loading;
5. drop nothing when `mode` is `shadow`, and everything when it is `empty`.

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `server.listen` | `:8080` | listen address |
| `server.path` | `/v1` | where the list is served |
| `server.fetchUserHeader` | | request header naming the client, for `banoor_fetches_total` |
| `interval` | `30s` | how often to score |
| `refresh` | `60s` | how often to re-sign an unchanged list |
| `source.type` | `clickhouse` | the source |
| `source.url`, `source.user`, `source.passwordFile` | | ClickHouse HTTP endpoint and credentials |
| `source.timeout` | `20s` | per request |
| `source.settings` | | settings sent with every query, such as `max_execution_time` |
| `source.insertSettings` | | settings sent with every insert |
| `tables.decisions`, `tables.publishes`, `tables.control` | | state tables ([schema](examples/schema.sql)) |
| `signing.keyFile` | | unencrypted OpenSSH Ed25519 private key |
| `signing.namespace` | | signature namespace consumers verify with `-n` |
| `defaultMode` | `shadow` | mode while the control table is empty |
| `threshold` | `50` | points that ban a source |
| `window` | `24h` | how far back signals count |
| `ipv6Prefix` | `64` | IPv6 network scored as one source |
| `ban.base`, `ban.max`, `ban.repeatWindow` | `24h`, `504h`, `720h` | ban lengths |
| `signals` | | see [Signals](#signals) |
| `allow.dir`, `allow.queries` | | see [Allowlists](#allowlists) |
| `manualFile` | | see [The manual list](#the-manual-list) |
| `limits.ipv4MinPrefix`, `limits.ipv6MinPrefix` | `24`, `48` | widest prefixes a list may carry |
| `caps.*` | | see [Caps](#caps) |

## Metrics

| Metric | Meaning |
| --- | --- |
| `banoor_mode{mode}` | 1 for the current mode |
| `banoor_generation`, `banoor_list_generated_timestamp_seconds` | the served list |
| `banoor_entries{kind,source}` | entries by kind (`ipv4`, `ipv6`, `range`) and source |
| `banoor_new_bans_total{kind}` | bans issued |
| `banoor_suppressed`, `banoor_suppressed_total` | sources over the threshold kept off by the allowlist or a lift; a rising total is the first sign the allowlist misses someone |
| `banoor_deferred{reason}`, `banoor_deferred_total{reason}` | sources held back by a cap |
| `banoor_signal_would_ban_total{signal}` | sources a shadow signal would have banned |
| `banoor_scored_sources` | sources with points in the window |
| `banoor_manual_entries{action}`, `banoor_manual_invalid` | the manual list |
| `banoor_allowlist_prefixes{list}` | allowlist sizes |
| `banoor_run_blocked_total{reason}` | runs that published nothing |
| `banoor_source_errors_total{query}` | failed queries and inserts |
| `banoor_last_success_timestamp_seconds`, `banoor_run_duration_seconds` | run health |
| `banoor_fetches_total{user,result}` | list requests |

Totals count each source once per episode: a source that stays deferred for
an hour counts once.

## Development

```sh
go test -race ./...
golangci-lint run
```

The ClickHouse integration test runs when `BANOOR_TEST_CLICKHOUSE_URL` (and
optionally `BANOOR_TEST_CLICKHOUSE_USER` and `BANOOR_TEST_CLICKHOUSE_PASSWORD`)
points at a server; it creates and drops its own database.

## License

[GPL-3.0](LICENSE)
