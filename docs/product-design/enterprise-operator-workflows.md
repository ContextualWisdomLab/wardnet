# Enterprise Operator Workflows

## 1. Buyer Lab Validation

Entry: buyer engineer opens `/admin` on a lab deployment.

Expected surface:

- health and persistence mode
- configured route count
- blocked and monitored event counts
- commercial readiness status
- feed freshness status
- DNSBL zone availability
- SOC event export availability
- support bundle link
- buyer evidence manifest link

Success state: buyer can reproduce readiness through `GET /api/commercial/readiness`, `GET /api/commercial/evidence-manifest`, `GET /api/support-bundle`, `GET /api/kpis`, `GET /api/threat-feeds/freshness`, `GET /api/events.ndjson`, and `GET /dnsbl/zone`.

## 2. Threat Feed Update Operation

Entry: SOC operator imports an approved feed through `POST /api/threat-feeds/import`.

Expected states:

- unauthorized writes return a clear 401 without mutating state
- invalid feed payloads return specific 400 blockers
- accepted feeds update threat indicators, DNSBL entries, and feed status atomically
- readiness reflects feed freshness immediately
- stale feeds become explicit blockers instead of silently passing readiness

Success state: the feed appears in `/api/threat-feeds`, freshness appears in `/api/threat-feeds/freshness`, and the support bundle includes updated feed and evidence counts.

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
- buyer evidence manifest with endpoint, document, and deployment evidence paths
- route, threat, DNSBL, feed, and event counts
- threat feed freshness records
- SOC event export path

Success state: the bundle can be attached to buyer due diligence or support intake without source-code access and without raw secrets.

## 5. Buyer Evidence Manifest

Entry: buyer engineer requests `GET /api/commercial/evidence-manifest`.

Expected states:

- readiness status, blockers, and 2B KRW target are visible without scraping multiple screens
- required endpoints include method, path, content type, and what each proves
- document paths include commercial, analytics, Product Design, Figma/FigJam, and complexity-audit artifacts
- deployment assets are listed for lab validation

Success state: a buyer can turn the manifest into a procurement checklist and verify each runtime surface independently.

## 6. SOC/SIEM Evidence Export

Entry: SOC engineer requests `GET /api/events.ndjson`.

Expected states:

- no events returns an empty NDJSON body with the same content type
- each event is one JSON object per line
- blocked and monitored actions remain visible for ingestion rules
- export does not include admin tokens or mutable configuration secrets

Success state: buyer can ingest the export into a lab parser without scraping the admin console.

## UI Direction

Use a compact operations layout with small headings, stable metric cells, direct status labels, and dense tables. Avoid a landing page, oversized hero, marketing copy, decorative cards, and unclear one-color status systems.
