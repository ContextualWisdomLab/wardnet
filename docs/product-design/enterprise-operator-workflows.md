# Enterprise Operator Workflows

## 1. Buyer Lab Validation

Entry: buyer engineer opens `/admin` on a lab deployment.

Expected surface:

- health and persistence mode
- configured route count
- blocked and monitored event counts
- commercial readiness status
- DNSBL zone availability
- support bundle link

Success state: buyer can reproduce readiness through `GET /api/commercial/readiness`, `GET /api/support-bundle`, `GET /api/kpis`, and `GET /dnsbl/zone`.

## 2. Threat Feed Update Operation

Entry: SOC operator imports an approved feed through `POST /api/threat-feeds/import`.

Expected states:

- unauthorized writes return a clear 401 without mutating state
- invalid feed payloads return specific 400 blockers
- accepted feeds update threat indicators, DNSBL entries, and feed status atomically
- readiness reflects feed evidence immediately

Success state: the feed appears in `/api/threat-feeds`, and the support bundle includes updated feed and evidence counts.

## 3. Enforcement Route Change

Entry: operator creates or updates a route through `POST /api/routes`.

Expected states:

- new route defaults should be reviewed in monitor mode before block mode in production procedures
- invalid route prefixes or upstream schemes return specific blockers
- route-scoped block mode prevents accidental global enforcement
- events record route id, action, score, reason, and path

Success state: the gateway returns monitor/block decisions and records evidence without leaking admin tokens.

## 4. Support and Due-Diligence Handoff

Entry: support engineer exports `GET /api/support-bundle`.

Expected contents:

- generated timestamp
- health status
- SOC KPI snapshot
- license profile
- readiness checks and blockers
- route, threat, DNSBL, feed, and event counts

Success state: the bundle can be attached to buyer due diligence or support intake without source-code access and without raw secrets.

## UI Direction

Use a compact operations layout with small headings, stable metric cells, direct status labels, and dense tables. Avoid a landing page, oversized hero, marketing copy, decorative cards, and unclear one-color status systems.
