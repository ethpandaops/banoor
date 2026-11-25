# Configuration

`banoord -config FILE` reads JSON; flags set the listen address
(`-listen`, default `127.0.0.1:8080`) and logging (`-log-format text|json`,
`-log-level`). [`examples/config.json`](../examples/config.json) is a complete
example and [`examples/schema.sql`](../examples/schema.sql) the tables it
needs.

## How a run works

Every `interval`, banoord:

1. reads the kill switch: the newest row of `tables.control` not dated in
   the future, or `defaultMode` while there is none;
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

A missing input may only keep sources off the list, so lifts, expiries and
the kill switch still take effect:

- In `empty` mode a run reads nothing but the kill switch.
- A signal whose query fails, or returns no `address` (or `line`), `feeder`
  or `attempts` column, is left out of the run, and counted in
  `banoor_source_errors_total`.
- When new decisions cannot be recorded, the run publishes without them: no
  new bans, and manual entries are recorded later.
- A broken allowlist file, key list or manual list keeps the last good one,
  and an allow query that fails keeps its last result.

A run that cannot read the kill switch, or the allowlists or the manual list
when it has no good copy yet, or record a new generation, publishes nothing:
the served list ages and consumers keep what they hold.

On start, banoord rebuilds its bans, manual entries, fetchers and generation
from the tables, skipping any ban it could not have issued: wider than one
source, issued in the future, or longer than `ban.max`. Run one banoord per
set of state tables: two would each serve their own list. Its ClickHouse
user needs to read the signal and allow tables and write the state tables;
give operators insert on the control table alone, and log shippers insert on
the signal tables alone, since banoord publishes what the state tables hold.

A first ban lasts `ban.base`; each earlier ban of the same source within
`ban.repeatWindow` doubles it, up to `ban.max`. `ban.base` is at least
`window`, so the evidence behind a ban has left the window when the ban
ends; attempts made during a ban count toward the next.

## Keys

| Key | Default | Meaning |
| --- | --- | --- |
| `fetchUserHeader` | | request header naming who fetched the list (set by the proxy in front), for `banoor_fetches_total` and `allow.fetchers` |
| `trustedProxies` | | prefixes, such as `"192.0.2.10/32"`, of the peers whose `fetchUserHeader` and `allow.fetchers.addressHeader` are believed; required with `allow.fetchers`. Without it, every peer's are |
| `interval` | `30s` | how often to score, and each run's timeout; at least 1 s |
| `refresh` | `60s` | how often to sign an unchanged list again; at least 1 s. A list is served at the end of a run and re-signed by the first run after `refresh`, so it gets up to `refresh` plus two intervals old, which may be at most 5 minutes |
| `source.type` | `clickhouse` | the source |
| `source.dsn` | | `clickhouse://user@host:9000/db` (native) or `http(s)://user@host:8123/db` |
| `source.passwordFile` | | overrides the DSN's password |
| `source.timeout` | `20s` | dial and read timeout |
| `source.settings` | | sent with every query, such as `max_memory_usage`. The client sets `max_execution_time` itself, to the run's remaining time plus 5 s (up to `interval` + 5 s), so a settings profile constraint must allow that |
| `source.insertSettings` | | sent with every insert, such as `distributed_foreground_insert` for Distributed tables |
| `tables.decisions`, `tables.publishes`, `tables.control` | | state tables |
| `tables.fetchers` | | with `allow.fetchers` |
| `signing.keyFile` | | unencrypted OpenSSH Ed25519 private key |
| `signing.namespace` | | the namespace consumers verify with `-n` |
| `defaultMode` | `shadow` | mode while the control table is empty |
| `threshold` | `50` | points that ban a source |
| `window` | `24h` | how far back signals count; `{window:UInt32}` in signal queries |
| `ipv6Prefix` | `64` | the IPv6 network scored as one source |
| `ban.base`, `ban.max`, `ban.repeatWindow` | `24h`, `504h`, `720h` | ban lengths; `base` at least `window`, `max` and `repeatWindow` at most a year |
| `signals` | | see below |
| `allow.dir`, `allow.queries`, `allow.fetchers` | | see below |
| `manualFile` | | see below |
| `limits.ipv4MinPrefix`, `limits.ipv6MinPrefix` | `24`, `48` | the widest prefixes a list may carry |
| `caps.maxEntries` | `5000` | past it, the lowest-priority entries are left off |
| `caps.maxAddedPerGeneration` | `500` | past it, additions wait for the next generation |
| `caps.maxNewPerHour` | `200` | new bans in any hour |
| `caps.maxNewPerFeederPerHour` | `50` | new bans attributed to one feeder (the one that gave most points) in any hour. Rows without a feeder share one |
| `caps.maxIPv4Addresses`, `caps.maxIPv6Networks` | `1048576` | total coverage |

Priority is manual bans first, then scored bans by points. A source a cap
holds back is considered again every run; a ban is only issued if it is
published. A ban records the 10 feeders that gave it most points.

## Signals

A signal's query returns one row per address and feeder over the window:

| Column | Type | Meaning |
| --- | --- | --- |
| `address` | string | the source address |
| `feeder` | string | who reported it, such as a host |
| `attempts` | integer or float | how many times in the window |

```json
{
  "name": "invalid_user",
  "mode": "count",
  "weight": 1,
  "query": "SELECT cutIPv6(toIPv6(Address), 8, 0) AS address, Feeder AS feeder, sum(Attempts) AS attempts FROM banoor.ssh_failures WHERE Kind = 'invalid_user' AND Minute >= now() - toIntervalSecond({window:UInt32}) GROUP BY address, feeder"
}
```

banoord sums rows per source as it reads them, but a client that rotates
through its IPv6 /64 still makes one row per address. `cutIPv6(toIPv6(x), 8,
0)` groups them into their /64 (the default `ipv6Prefix`) in the database
and leaves IPv4 addresses whole.

`weight` must be positive. A `shadow` signal never counts;
`banoor_signal_would_ban_total` shows what it would have banned. A row whose
`attempts` is NULL, NaN, infinite or negative counts as invalid, like an
address that does not parse (`banoor_invalid_rows`). With
`"parser": "openssh"` the query returns a `line` column instead of
`address`, and only lines of the listed `kinds` count (`invalid_user`,
`not_allowed`, `penalty_drop`, `maxstartups_drop`, `auth_closed`). That suits
small volumes; for large ones, aggregate in the database.

`maxstartups_drop` hits whichever client sshd drops at random while it is
over MaxStartups, not only the cause, and `penalty_drop` hits everyone in a
penalised `PerSourceNetBlockSize` block: keep them in `shadow` unless that
is what you want to count.

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

Logins for an allow query come from `AcceptedPattern`, whose groups are the
user, the address and the key's fingerprint. Keep only rows whose address is
an address:

```sql
CREATE MATERIALIZED VIEW banoor.ssh_logins_mv TO banoor.ssh_logins AS
WITH extractGroups(Body, '^Accepted publickey for (\\S+) from (\\S+) port \\d+ ssh2: \\S+ (SHA256:\\S+)(?: ID .*)?$') AS g
SELECT toStartOfHour(Timestamp) AS Hour, g[2] AS Address, g[3] AS Fingerprint
FROM logs.sshd
WHERE length(g) = 3 AND (isIPv4String(g[2]) OR isIPv6String(g[2]))
```

## Allowlists

The allowlist always wins: an allowed address inside a candidate (an allowed
/128 in a /64) keeps the whole candidate off the list.

Each source over the threshold, ban in force and manual ban the allowlist or
a lift newly keeps off the list is logged (`suppressed`, with its points and
what kept it off) and recorded in `tables.decisions` with the action
`suppressed`. In shadow mode, these show what the allowlist keeps off, so you
can check it allows only who it should; a source it misses shows up as a ban.

- **Files** (`allow.dir`): every `*.txt` file, one address or prefix (not
  `/0`) per line, `#` comments, reread every run. A missing directory is an
  error.
- **Queries** (`allow.queries`): each returns `address` and optionally `key`.
  Each row allows one address; a row naming a prefix allows nothing. With
  `keysFile` (reread every run), only rows whose key is listed count, such as
  the SHA256 fingerprints of the SSH keys you trust. A key list that cannot be
  read, or lists no key, keeps the last good one:

  ```json
  {"name": "logins", "window": "720h", "refresh": "1h", "keysFile": "/etc/banoor/fingerprints.txt",
   "query": "SELECT Address AS address, Fingerprint AS key FROM banoor.ssh_logins WHERE Hour >= now() - toIntervalSecond({window:UInt32}) GROUP BY address, key"}
  ```

- **Fetchers** (`allow.fetchers`): every address a consumer fetched the list
  from within `window`, when its user (`fetchUserHeader`) matches the `users`
  regular expression, which must not match an empty user. The address comes
  from `addressHeader`, which the proxy in front must set and clients must
  not be able to; the hosts that pull the list are then never banned, with
  nothing to maintain. Both headers are believed only from `trustedProxies`,
  and an address header sent twice is ignored. Anyone who can fetch as a
  matching user can allow addresses, so keep `users` to your consumers and
  the proxy's credentials to them. Each user keeps its 16 most recent
  addresses, and at most 4,096 users are kept. A host fetches over one
  address family at a time, so have consumers alternate IPv4 and IPv6.

  ```json
  {"addressHeader": "X-Real-Ip", "users": "^host-", "window": "720h"}
  ```

- **Special-purpose ranges** (private, loopback, link-local, shared, IETF
  protocol assignments, benchmarking, multicast, reserved, IPv4-mapped, NAT64
  and Teredo) are always allowed.

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
run that can read the control table and record the generation; `empty` needs
nothing else. A row dated in the future is ignored until its time.

Nothing is banned while the list is empty, and bans in force stay in force.
After `empty`, entries return at most `caps.maxAddedPerGeneration` at a
time. A switch from `shadow` to `enforce` keeps the entries, so the whole
list applies at once.

## Metrics

| Metric | Meaning |
| --- | --- |
| `banoor_mode{mode}` | 1 for the mode last read from the kill switch |
| `banoor_generation`, `banoor_list_generated_timestamp_seconds` | the served list |
| `banoor_entries{kind,source}` | entries by kind (`ipv4`, `ipv6`, `range`) and source |
| `banoor_new_bans_total{kind}` | bans issued |
| `banoor_suppressed`, `banoor_suppressed_total` | sources, bans in force and manual bans the allowlist or a lift keeps off |
| `banoor_deferred{reason}`, `banoor_deferred_total{reason}` | entries a cap holds back |
| `banoor_signal_would_ban_total{signal}` | sources a shadow signal would have banned |
| `banoor_scored_sources` | sources with points in the window |
| `banoor_invalid_rows` | signal rows in the window that could not be scored: an address that does not parse, or `attempts` NULL, NaN, infinite or negative |
| `banoor_manual_entries{action}`, `banoor_manual_invalid` | the manual list |
| `banoor_allowlist_prefixes{list}` | allowlist sizes: `files`, each query, `fetchers` |
| `banoor_run_blocked_total{reason}` | runs that published nothing |
| `banoor_source_errors_total{query}` | failed queries, inserts and reads, such as `signal:<name>` and `keys:<allow query>` |
| `banoor_last_success_timestamp_seconds`, `banoor_run_duration_seconds` | run health |
| `banoor_fetches_total{user,result}` | list requests, by `result` (`ok`, `not_modified`, `unavailable`); `user` is `unknown` without a user header, `invalid` for a malformed one, and `other` past 256 users |

The deferred, would-ban and suppressed totals count each source once per
episode: one that stays deferred for an hour counts once.
