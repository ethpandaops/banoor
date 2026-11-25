# The list format, version 1

`GET /api/v1/list` returns an envelope, so the payload and its signature
always match:

```json
{"payload": "<base64 of the payload JSON>", "signature": "-----BEGIN SSH SIGNATURE-----\n..."}
```

- The response carries an `ETag`; a request whose `If-None-Match` names it
  gets `304 Not Modified`.
- `503` (an RFC 9457 problem) means no list has been published yet. Any
  answer other than `200` or `304` means: keep what you hold.

## The payload

```json
{
  "version": 1,
  "generation": 1893499200,
  "previous_generation": 1893499140,
  "generated_at": 1893499230,
  "mode": "enforce",
  "entries": [
    {"cidr": "198.51.100.10/32", "expires": 1893585600, "source": "scorer", "reason": "invalid_user=57 in 24h, ban 1", "commit": ""},
    {"cidr": "203.0.113.0/24", "expires": 1894060800, "source": "manual", "reason": "scanner range", "commit": "3f2a9c1"}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `version` | 1. Fields may be added within version 1; ignore ones you do not know. |
| `generation` | Only goes up. It changes when `entries` or `mode` change, and when banoord restarts. It is the Unix time of the change, or the previous generation plus one if that is higher, so it keeps going up even if banoord loses its state. |
| `previous_generation` | The generation this one replaces; 0 for the first. |
| `generated_at` | When this payload was signed, in Unix seconds. An unchanged list is signed again every `refresh` (60 s by default) with the same generation. |
| `mode` | `enforce`: apply the list in your own mode. `shadow`: load it, drop nothing. `empty`: `entries` is `[]`. |
| `entries[].cidr` | A canonical prefix (host bits zero, IPv4 written as IPv4), no wider than the configured limits (/24 and /48 by default). Scored entries are single sources; wider ones come from the manual list. Sorted ascending. |
| `entries[].expires` | Unix seconds. |
| `entries[].source` | `scorer` or `manual`. |
| `entries[].reason`, `entries[].commit` | For people, and possibly empty. Never parse them. |

No allow entries are ever published.

## Verifying a list

The signature is OpenSSH's (`PROTOCOL.sshsig`, Ed25519, SHA-512) over the
decoded payload bytes, in the namespace the server is configured with. Pin
the key in an `allowed_signers` file
(`banoorctl pubkey -key FILE -principal list-signer -namespace example-banlist`
prints the line), then:

```bash
curl -s http://127.0.0.1:8080/api/v1/list > envelope.json
jq -r .payload envelope.json | base64 -d > payload.json
jq -r .signature envelope.json > payload.sig
ssh-keygen -Y verify -f allowed_signers -I list-signer -n example-banlist -s payload.sig < payload.json
```

## What a consumer should check

1. The signature, against the pinned key or keys (several, to rotate).
2. `generated_at`: reject a payload older than a few refresh intervals (10
   minutes, say), or from the future.
3. `generation`: reject one lower than the last you loaded, and remember it
   across restarts. An equal one is a freshness refresh: reset your age and
   change nothing.
4. Your own limits before loading: the widest prefix, the number of entries,
   total coverage, and how many entries a list adds when your loaded
   generation equals `previous_generation`. Skip the last check on your first
   load, and in `shadow` and `empty` mode.
5. Your own allowlist, which always wins.
6. `mode`: drop nothing in `shadow`; flush in `empty`.

banoord's caps keep its lists inside defaults of /24 and /48, 5,000 entries,
2^20 IPv4 addresses or IPv6 /64 networks, and 500 additions per generation;
configure the same limits on both sides.
