# UwUSpamNet protocol v1

HTTPS and JSON. Production: `https://spamnet.minifyx.de`. Every request and response body is
UTF-8 JSON (`content-type: application/json`), except `GET /`, which is an HTML page.

## Authentication

`POST /v1/register` needs none. Everything else under `/v1/` except `/v1/health` needs

    Authorization: Bearer usn_<64 hex>

A missing, malformed or unknown key is `401 unauthorized`; a banned server gets `403 banned`.

## Endpoints

### `POST /v1/register`

```json
{ "name": "mail.example.com", "software": "UwUMail 0.38.0", "contact": "postmaster@example.com" }
```

- `name`: required, 1–253 characters. `software`: required, 1–100. `contact`: optional,
  at most 254; `""` counts as absent. No control characters in any of them.
- `201 { "serverId": "s_<24 hex>", "key": "usn_<64 hex>" }`.
- The key is shown this once. The service keeps only its SHA-256.
- The service also stores the registration network, the client address cut to /24 (IPv4) or /48
  (IPv6), never the address itself. Servers in the same registration network count as one
  (see listing rules).
- At most 5 registrations per client IP and UTC day, otherwise `429`. This counter lives only in
  memory: it starts afresh when the service restarts.

### `POST /v1/reports`

```json
{
  "reports": [
    {
      "verdict": "spam",
      "reason": "user",
      "digests": ["d1:…", "p1:…"],
      "domains": ["spam.example.com"],
      "ip": "203.0.113.7",
      "from": "example.net"
    }
  ]
}
```

- `verdict`: `spam` or `ham`. `reason`: `user` (a person decided) or `filter`. Both required;
  any other value is `400 invalid_json`. Unknown fields are ignored.
- `digests` (≤ 8, Digest v1, see `digest-v1.md`), `domains` (≤ 20), `ip`, `from`: all optional.
- At most 100 reports per request, and per report at most 8 digests and 20 domains: more is
  `413 too_large` for the whole request. The body may be at most 1 MiB.
- `202 { "accepted": n }`.

Values are checked and normalized one by one. A value that is not valid for its kind is
**skipped silently**, not refused; a report with no valid value left is not counted in
`accepted` and not counted against the daily budget.

| kind | accepted | stored as |
|---|---|---|
| `digest` | `d1:` or `p1:` + 32 lowercase hex | as sent |
| `domain`, `from` | a DNS name of ≥ 2 labels, `[A-Za-z0-9-]`, 1–63 per label, no leading/trailing `-`, ≤ 253, TLD not all digits; a trailing dot is allowed | lowercase, without trailing dot |
| `ip` | IPv4 or IPv6 address (IPv6 also with `/64`); IPv4-mapped IPv6 is IPv4 | IPv4 as the address (`203.0.113.7`), IPv6 as its /64 network (`2001:db8:aa:bb::/64`) |

Private, loopback, link-local, unspecified, multicast and broadcast addresses (and `0.0.0.0/8`,
`fc00::/7`) are skipped. The service does not cut domains down to the registrable domain: the
client sends what the plan says (registrable domains from links, the registrable RFC5322.From
domain).

Daily budget: 5000 counted reports per server and UTC day. A request that would go over it is
refused as a whole with `429` (nothing of it is stored); `Retry-After` says how many seconds
remain until the next UTC day.

Several reports of one server about one value count once: the service counts servers, not
reports. Per (kind, value, server) it keeps four counters (spam/ham × user/filter) and the time
of the last spam and the last ham report.

### `GET /v1/list?since=<cursor>`

```json
{
  "cursor": "1234",
  "full": false,
  "entries": [
    { "kind": "domain", "value": "spam.example.com", "score": 2.29, "expires": "2026-11-30T12:00:00Z" }
  ],
  "removed": [ { "kind": "digest", "value": "d1:…" } ]
}
```

- Without `since`, or with a cursor the service no longer knows (garbage, from the future, or
  older than 30 days), the answer is the full list: `full: true`, every listed entry, `removed`
  empty. The client replaces what it had.
- With a known cursor: `full: false`, the entries that are new or changed since then (new score
  or expiry), and in `removed` those that left the list since then. The client merges.
- Always keep the returned `cursor` for the next call. It is opaque: compare it for equality
  only. Nothing changed → the same cursor and two empty arrays.
- `score`: 1.0–4.0, two decimals. `expires`: RFC 3339 UTC. A client should drop an entry when
  `expires` has passed even without a `removed` for it.
- Requires the key. Suggested interval: every 15 minutes.

An entry's expiry can move later when new spam reports come in; the service only reports such a
change again when it moves by a day or more, so the `expires` a client holds can be up to a day
early.

### `GET /v1/health`

`200 { "status": "ok", "version": "0.1.0", "checks": { "database": "ok" } }`, or `503` with
`"error"` in place of `"ok"`.

### `GET /`

Information and privacy page (German and English).

## Errors

```json
{ "error": "rate_limited", "detail": "…" }
```

`error` is a stable code; `detail` is an optional human-readable note and may change.

| status | `error` | when |
|---|---|---|
| 400 | `invalid_json` | body is not JSON of the expected shape |
| 400 | `invalid_request` | a field breaks its rules (register) |
| 401 | `unauthorized` | key missing, malformed or unknown |
| 403 | `banned` | the server was banned |
| 404 | `not_found` | unknown path |
| 413 | `too_large` | more than 100 reports, 8 digests or 20 domains, or a body over 1 MiB |
| 429 | `rate_limited` | registrations per IP, or reports per server, for today used up; with `Retry-After` |
| 500 | `internal` | |

## Listing rules

Evaluated per (kind, value) whenever a report about it arrives, a server is banned or unbanned,
the allowlist changes, and on every `GET /v1/list` for entries whose expiry has come.

- Only reports from the last 14 days count; older report rows are deleted.
- Banned servers do not count.
- Allowlisted values are never listed. `domain` and `from` entries also match subdomains
  (`gmail.com` covers `mail.gmail.com`); `ip` entries may be CIDR networks.
- A server's spam vote is worth 2 if any of its spam reports in the window had `reason=user`,
  otherwise 1. Ham votes alike.
- Servers are grouped by registration network. A network's spam weight is 2 if one of its
  servers voted spam as `user`, otherwise 1.
- **Listed** when at least 3 registration networks voted spam, and the spam votes are at least
  3 × the ham votes (both summed over servers, with the weights above).
- **score** = 1 + 3 · (min(W, 10) − 3) / 7, rounded to two decimals, where W is the summed
  network weight. 3 filter-only networks → 1.0; 10 or more weight → 4.0.
- **expires** = (last spam report of the 3rd most recent network) + 14 days − 1 day per point of
  ham votes (weighted as above), at most 10 days less. That is the moment the entry would stop having 3 networks in the
  window, brought forward by ham. An entry whose expiry is already past is not listed.
- Removed entries are kept as tombstones for 30 days so that incremental clients learn about
  them.

## Limits, in one place

| what | limit | configurable |
|---|---|---|
| registrations per client IP and UTC day | 5 | `SPAMNET_REGISTRATIONS_PER_IP` |
| reports per server and UTC day | 5000 | `SPAMNET_REPORTS_PER_DAY` |
| reports per request | 100 | no |
| digests / domains per report | 8 / 20 | no |
| request body | 1 MiB | no |
| report window, entry lifetime | 14 days | no |
| incremental cursor valid for | 30 days | no |
