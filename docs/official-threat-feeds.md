# Official threat-feed refresh API

Wardnet keeps operator-supplied `POST /api/threat-feeds/import` separate from a
closed registry of official upstreams. The registry is persisted with source identity,
URL template, parser, supported indicator types, attribution and terms link, HTTP
validators, refresh interval, TTL, last attempt/success/error, and the upstream copyright
notice when supplied.

| Source id | Upstream contract | Default refresh / TTL | Credential |
| --- | --- | --- | --- |
| `spamhaus-drop-v4` | Spamhaus DROP IPv4 JSON Lines | 24h / 48h | None |
| `spamhaus-drop-v6` | Spamhaus DROP IPv6 JSON Lines | 24h / 48h | None |
| `urlhaus-online` | URLhaus authenticated recent CSV export | 1h / 2h | KV key `urlhaus_auth_key` |
| `threatfox-recent` | ThreatFox `get_iocs`, one-day window | 1h / 2h | KV key `threatfox_auth_key` |

Spamhaus asks automated users not to fetch more often than hourly and documents daily
refresh as sufficient; Wardnet therefore defaults DROP to daily. abuse.ch exports update
more often, but Wardnet deliberately uses a one-hour floor. A request before the interval
expires returns `429` with `Retry-After`.

The data is governed by source-specific terms, not by Wardnet's MIT license. Preserve
attribution and review the [Spamhaus DROP fair-use policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)
and [abuse.ch terms of use](https://abuse.ch/terms-of-use/) before commercial use or
redistribution. The canonical formats are documented by
[Spamhaus](https://www.spamhaus.org/blocklists/do-not-route-or-peer/),
[URLhaus](https://urlhaus.abuse.ch/api/), and
[ThreatFox](https://threatfox.abuse.ch/api/).

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

These are threat-intelligence feeds consumed by gateway scoring and the authoritative
DNSBL zone export. They are not recursive DNS resolvers and do not configure an upstream
DNS resolver.
