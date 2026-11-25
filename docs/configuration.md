# Configuration

`banoord -config FILE` reads JSON; flags set the listen address
(`-listen`, default `127.0.0.1:8080`) and logging (`-log-format text|json`,
`-log-level`). [`examples/config.json`](../examples/config.json) is a complete
example and [`examples/schema.sql`](../examples/schema.sql) the tables it
needs.

## How a run works

Every `interval`, banoord:

1. reads the kill switch: the newest row of `tables.control`, or
   `defaultMode` while it is empty;
2. runs every signal query, and every allow query that is due;
3. rereads the allowlist files, the key lists and the manual list;
4. scores each source: the sum over counting signals of
   `min(weight × attempts, cap)`, where a `cap` of 0 (the default) means no
   cap;
5. bans the sources at or over `threshold` that are not allowlisted, lifted,
   covered by a manual ban or banned already, highest score first, within the
   caps;
6. records new bans and newly seen manual entries in `tables.decisions`;
7. publishes: a change of entries or mode is a new generation, recorded with
   its prefixes in `tables.publishes` before it is served. Otherwise the same
   generation is signed again once `refresh` has passed.

A run that cannot read an input, or record what it decided, publishes
nothing: the served list ages and consumers keep what they hold. A broken
allowlist file or manual list keeps the last good one. On start, banoord
rebuilds its bans, manual entries, fetchers and generation from the tables.

A first ban lasts `ban.base`; each earlier ban of the same source within
`ban.repeatWindow` doubles it, up to `ban.max`.

## Keys

| Key | Default | Meaning |
| --- | --- | --- |
| `fetchUserHeader` | | request header naming who fetched the list (set by the proxy in front), for `banoor_fetches_total` and `allow.fetchers` |
| `interval` | `30s` | how often to score, and each run's timeout; at least 1 s |
| `refresh` | `60s` | how often to sign an unchanged list again; at least 1 s. A list is served at the end of a run and re-signed by the first run after `refresh`, so it gets up to `refresh` plus two intervals old, which may be at most 5 minutes |
| `source.type` | `clickhouse` | the source |
| `source.dsn` | | `clickhouse://user@host:9000/db` (native) or `http(s)://user@host:8123/db` |
| `source.passwordFile` | | overrides the DSN's password |
| `source.timeout` | `20s` | dial and read timeout |
| `source.settings` | | sent with every query, such as `max_execution_time` |
| `source.insertSettings` | | sent with every insert, such as `distributed_foreground_insert` for Distributed tables |
| `tables.decisions`, `tables.publishes`, `tables.control` | | state tables |
| `tables.fetchers` | | with `allow.fetchers` |
| `signing.keyFile` | | unencrypted OpenSSH Ed25519 private key |
| `signing.namespace` | | the namespace consumers verify with `-n` |
| `defaultMode` | `shadow` | mode while the control table is empty |
| `threshold` | `50` | points that ban a source |
| `window` | `24h` | how far back signals count; `{window:UInt32}` in signal queries |
| `ipv6Prefix` | `64` | the IPv6 network scored as one source |
| `ban.base`, `ban.max`, `ban.repeatWindow` | `24h`, `504h`, `720h` | ban lengths; `max` and `repeatWindow` at most a year |
| `signals` | | see below |
| `allow.dir`, `allow.queries`, `allow.fetchers` | | see below |
| `manualFile` | | see below |
| `limits.ipv4MinPrefix`, `limits.ipv6MinPrefix` | `24`, `48` | the widest prefixes a list may carry |
| `caps.maxEntries` | `5000` | past it, the lowest-priority entries are left off |
| `caps.maxAddedPerGeneration` | `500` | past it, additions wait for the next generation |
| `caps.maxNewPerHour` | `200` | new bans in any hour |
| `caps.maxNewPerFeederPerHour` | `50` | new bans attributed to one feeder (the one that gave most points) in any hour |
| `caps.maxIPv4Addresses`, `caps.maxIPv6Networks` | `1048576` | total coverage |

Priority is manual bans first, then scored bans by points. A source a cap
holds back is considered again every run; a ban is only issued if it is
published.

## Signals

A signal's query returns one row per source and feeder over the window:

| Column | Type | Meaning |
| --- | --- | --- |
| `address` | string | the source address |
| `feeder` | string | who reported it, such as a host |
| `attempts` | number | how many times in the window |

```json
{
  "name": "invalid_user",
  "mode": "count",
  "weight": 1,
  "query": "SELECT Address AS address, Feeder AS feeder, sum(Attempts) AS attempts FROM banoor.ssh_failures WHERE Kind = 'invalid_user' AND Minute >= now() - toIntervalSecond({window:UInt32}) GROUP BY address, feeder"
}
```

A `shadow` signal never counts; `banoor_signal_would_ban_total` shows what it
would have banned. A row whose `attempts` is NULL, NaN, infinite or negative
counts as invalid, like an address that does not parse. With `"parser": "openssh"` the query returns a `line`
column instead of `address`, and only lines of the listed `kinds` count
(`invalid_user`, `not_allowed`, `penalty_drop`, `maxstartups_drop`,
`auth_closed`). That suits small volumes; for large ones, aggregate in the
database.

### Extracting SSH failures safely

sshd logs the user name a client sends verbatim, so a client can make a line
name an address it does not own:

```text
Invalid user x from 192.0.2.7 port 1 from 198.51.100.10 port 36465
```

Take the address from the fixed end of the line, never from the first
` from `. The patterns in [`pkg/sshlog`](../pkg/sshlog/sshlog.go) do, and work
unchanged in ClickHouse:

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

Count only lines sshd itself sent to syslog (for example, written by user ID
0): any local user can write a line claiming to come from sshd, and with `-e`
sshd writes to standard error without escaping newlines.

## Allowlists

The allowlist always wins: an allowed address inside a candidate (an allowed
/128 in a /64) keeps the whole candidate off the list.

Each source the allowlist or a lift newly keeps off the list is logged
(`suppressed`, with its points and what kept it off) and recorded in
`tables.decisions` with the action `suppressed`. In shadow mode, these show
where the allowlist misses someone, or allows too much.

- **Files** (`allow.dir`): every `*.txt` file, one address or prefix per line,
  `#` comments, reread every run. A missing directory is an error.
- **Queries** (`allow.queries`): each returns `address` and optionally `key`.
  With `keysFile` (reread every run), only rows whose key is listed count,
  such as the SHA256 fingerprints of the SSH keys you trust:

  ```json
  {"name": "logins", "window": "720h", "refresh": "1h", "keysFile": "/etc/banoor/fingerprints.txt",
   "query": "SELECT Address AS address, Fingerprint AS key FROM banoor.ssh_logins WHERE Hour >= now() - toIntervalSecond({window:UInt32}) GROUP BY address, key"}
  ```

- **Fetchers** (`allow.fetchers`): every address a consumer fetched the list
  from within `window`, when its user (`fetchUserHeader`) matches the `users`
  regular expression, which must not match an empty user. The address comes
  from `addressHeader`, which the proxy in front must set and clients must
  not be able to; the hosts that pull the list are then never banned, with
  nothing to maintain. Each user keeps its 16 most recent addresses. A host
  fetches over one address family at a time, so have consumers alternate IPv4
  and IPv6.

  ```json
  {"addressHeader": "X-Real-Ip", "users": "^host-", "window": "720h"}
  ```

- **Special-purpose ranges** (private, loopback, link-local, shared, IETF
  protocol assignments, benchmarking, multicast, reserved, NAT64 and Teredo)
  are always allowed.

## The manual list

`manualFile` is JSON, reread every run:

```json
{"entries": [
  {"action": "ban", "cidr": "203.0.113.0/24", "expires": "2030-01-08T00:00:00Z", "reason": "scanner range", "by": "alice", "commit": "3f2a9c1"},
  {"action": "lift", "cidr": "198.51.100.7/32", "expires": "2030-01-02T00:00:00Z", "reason": "customer behind NAT"}
]}
```

A `ban` adds a prefix; a `lift` keeps a prefix off the list, over scored and
manual bans. `by` and `commit` are optional and for people; `commit` is
published with the entry. A file that is not one object with an `entries`
array keeps the last good list. Both must fit within `limits` and need an expiry and a reason.
Check a list before merging it:

```bash
banoorctl validate -manual manual.json -allow-dir allowlist/ [-config config.json] [-max-ahead 8760h]
```

It fails on invalid or too-wide entries, bans that overlap the allowlist or a
lift, and expiries more than `-max-ahead` away (a year by default), and warns
about expired entries.

## The kill switch

```sql
INSERT INTO banoor.control (Mode, Reason) VALUES ('empty', 'why')
```

`enforce` publishes the list for consumers to apply; `shadow` marks it so
they drop nothing; `empty` publishes no entries. It takes effect at the next
run. After `empty`, entries return at most `caps.maxAddedPerGeneration` at a
time.

## Metrics

| Metric | Meaning |
| --- | --- |
| `banoor_mode{mode}` | 1 for the current mode |
| `banoor_generation`, `banoor_list_generated_timestamp_seconds` | the served list |
| `banoor_entries{kind,source}` | entries by kind (`ipv4`, `ipv6`, `range`) and source |
| `banoor_new_bans_total{kind}` | bans issued |
| `banoor_suppressed`, `banoor_suppressed_total` | sources and manual bans the allowlist or a lift keeps off; a rising total is the first sign the allowlist misses someone |
| `banoor_deferred{reason}`, `banoor_deferred_total{reason}` | entries a cap holds back |
| `banoor_signal_would_ban_total{signal}` | sources a shadow signal would have banned |
| `banoor_scored_sources` | sources with points in the window |
| `banoor_invalid_addresses_total` | signal rows whose address did not parse |
| `banoor_manual_entries{action}`, `banoor_manual_invalid` | the manual list |
| `banoor_allowlist_prefixes{list}` | allowlist sizes: `files`, each query, `fetchers` |
| `banoor_run_blocked_total{reason}` | runs that published nothing |
| `banoor_source_errors_total{query}` | failed queries and inserts |
| `banoor_last_success_timestamp_seconds`, `banoor_run_duration_seconds` | run health |
| `banoor_fetches_total{user,result}` | list requests, by `result` (`ok`, `not_modified`, `unavailable`); `user` is `unknown` without a user header, `invalid` for a malformed one, and `other` past 256 users |

The deferred, would-ban and suppressed totals count each source once per
episode: one that stays deferred for an hour counts once.
