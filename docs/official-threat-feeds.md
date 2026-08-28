# Official threat-feed refresh API

Wardnet keeps operator-supplied `POST /api/threat-feeds/import` separate from a
closed registry of official upstreams. The registry is persisted with source identity,
URL template, parser, supported indicator types, attribution and terms link, HTTP
validators, refresh interval, TTL, last attempt/success/error, and the upstream copyright
notice when supplied. Each successful `200` also records a SHA-256 digest of the exact
validated response body; this is local provenance evidence, not an upstream signature.

| Source id | Upstream contract | Default refresh / TTL | Credential |
| --- | --- | --- | --- |
| `spamhaus-drop-v4` | Spamhaus DROP IPv4 JSON Lines | 24h / 48h | None |
| `spamhaus-drop-v6` | Spamhaus DROP IPv6 JSON Lines | 24h / 48h | None |
| `urlhaus-online` | URLhaus authenticated recent CSV export | 1h / 2h | KV key `urlhaus_auth_key` |
| `threatfox-recent` | ThreatFox `get_iocs`, one-day window | 1h / 2h | KV key `threatfox_auth_key` |

Spamhaus asks automated users not to fetch more often than hourly and documents daily
refresh as sufficient; Wardnet therefore defaults DROP to daily. abuse.ch exports update
more often, but Wardnet deliberately uses a one-hour floor. A request before the interval
expires returns `429` with `Retry-After`. An upstream request that fails also consumes the
interval, preventing operator retries from exceeding the source's fetch policy; credential
preflight failures do not.

The data is governed by source-specific terms, not by Wardnet's MIT license. Preserve
attribution and review the [Spamhaus DROP fair-use policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)
and [abuse.ch terms of use](https://abuse.ch/terms-of-use/) before commercial use or
redistribution. The canonical formats are documented by
[Spamhaus](https://www.spamhaus.org/blocklists/do-not-route-or-peer/),
[URLhaus](https://urlhaus.abuse.ch/api/), and
[ThreatFox](https://threatfox.abuse.ch/api/).

The current contracts were rechecked against those official pages on 2026-08-28:
Spamhaus publishes the two JSON URLs, requires attribution and preservation of its date/©
notice, re-evaluates DROP daily, and says daily fetching is sufficient. URLhaus documents
the authenticated `recent.csv` export URL. ThreatFox requires `Auth-Key` and documents
`get_iocs` with a one-day minimum window. Neither abuse.ch API documents a detached
checksum for these responses, so Wardnet records its own digest after TLS retrieval and
full-response validation while retaining ETag/Last-Modified when provided.

The built-in GET endpoints were also rechecked live on 2026-08-28. Spamhaus `drop_v4.json`,
Spamhaus `drop_v6.json`, and URLhaus `csv_recent` each returned direct `HTTP 200` without an
intermediate redirect. ThreatFox uses a POST-only API contract at `/api/v1/`, so a GET/HEAD
probe is not the authoritative success path for that source.

## Credentials

Place abuse.ch keys in the JSON credential registry selected by
`WAF_IDS_CREDENTIALS_PATH`; handlers read only `CredentialRegistry::get_credential`.
Keys are never returned by status, written into persisted feed metadata, included in audit
logs, or exposed in request errors.

```json
{
  "admin_tokens": "operator-token:soc:write,reader-token:auditor:readonly",
  "urlhaus_auth_key": "...",
  "threatfox_auth_key": "..."
}
```

## Endpoints

`GET /api/official-threat-feeds` requires any authenticated admin principal and returns
registry/status metadata without secrets.

`POST /api/official-threat-feeds/{source_id}/refresh` requires a write-capable principal.
Unknown/non-canonical sources are rejected. Wardnet sends `If-None-Match` and
`If-Modified-Since` when validators exist. A `304` refreshes freshness evidence without
rewriting indicator content.

On a successful `200`, Wardnet parses and validates the entire response before one
persistent mutation replaces only rows owned by that source, updates the existing
`ThreatFeedStatus` freshness record, stores validators/status, and writes an audit entry.
Network, HTTP, body, parsing, or validation failure records `last_error` but retains the
last-known-good threat/DNSBL rows unchanged. Requests have a 15-second total timeout and
responses are streamed with an 8 MiB hard limit. Credential preflight failures do not consume
the source refresh interval, so adding a missing key permits an immediate corrective retry.

These are threat-intelligence feeds consumed by gateway scoring. The authoritative DNSBL
zone exports exact IPv4 host entries only; CIDR ranges and IPv6 entries remain available to
inline gateway scoring rather than being expanded into an unbounded zone. That host-only
publication rule applies to both official-feed imports and operator-created `DnsblEntry`
records with `prefix_len`; subnet entries remain visible through `GET /api/dnsbl` and active
for inline scoring, but they are intentionally omitted from `/dnsbl/zone`. Wardnet is not a
recursive DNS resolver and does not configure an upstream DNS resolver.

## Scrubbed runtime evidence (2026-08-27)

A bounded local run of this PR's production refresh endpoint fetched and parsed the official
Spamhaus TLS sources without publishing indicator rows. `spamhaus-drop-v4` returned HTTP 200
and atomically installed 1,703 DNSBL ranges; `spamhaus-drop-v6` returned HTTP 200 and installed
92 ranges. Both status records captured a successful attempt timestamp, a response digest,
`Last-Modified`, and the upstream copyright notice. Neither response supplied an ETag.

The same run exercised URLhaus and ThreatFox through the official registry, but no matching KV
credentials were available. Both failed closed with HTTP 502 before an upstream request;
`last_attempt_unix` and `last_success_unix` remained unset, no digest or indicator counts were
fabricated, and an operator can retry immediately after adding a credential. The source
registry continued to expose attribution, terms links, parser identity, indicator types, and
the one-hour refresh/two-hour TTL policy without exposing credential values.

Last-known-good behavior is covered by the bounded official refresh integration test: timeout,
oversized body, parse, and validation failures retain the prior source-owned rows while recording
the failure status. The live successful snapshot above establishes the parser and persistence
path against current official content; it does not redistribute or enumerate any IOC row.
