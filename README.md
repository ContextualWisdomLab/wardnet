# WAF IDS AI SOC

Rust-first gateway and SOC control-plane baseline for ContextualWisdomLab.

The project starts small on purpose:

- web-managed API gateway routes
- reusable `waf-ids-core` domain crate inside the same Cargo workspace
- request scoring from threat indicators and DNSBL entries
- monitor/block enforcement modes
- RFC 5782-style DNSBL zone export
- SOC event and KPI APIs
- tenant/license-aware commercial readiness APIs
- threat feed import status for real-time update operations
- support bundle API for buyer due diligence and support handoff
- threat-feed freshness evidence and SOC event NDJSON export
- optional JSON state persistence for standalone operation
- embedded admin console

It does not pretend to be a full WAF, IDS, SIEM, or SOAR yet. Production WAF and IDS coverage should come from adapters to proven engines such as OWASP CRS/Coraza and Suricata.

## Completion Baseline

The program-complete baseline means the binary can run by itself, keep operator-managed routes/threats/DNSBL entries/events across restart when `WAF_IDS_STATE_PATH` is configured, enforce monitor/block decisions, export DNSBL records, and prove that loop through `scripts/smoke.sh`.

It is still not a hardened internet-facing deployment. Use TLS, identity-aware access, upstream allowlists, and route rollback procedures before production traffic.

## Commercial Readiness Baseline

The 2B KRW sale readiness baseline means the runtime can prove a buyer-facing pilot state through API evidence:

- `GET /api/commercial/license` returns tenant, edition, license, support, and annual contract metadata.
- `POST /api/commercial/license` updates that metadata with `X-Admin-Token`.
- `POST /api/threat-feeds/import` imports operator-reviewed threat indicators and DNSBL entries.
- `POST /api/threat-feeds/import/phishing-database` pulls active domains/IPs from `Phishing-Database/Phishing.Database` and converts them into local block signals.
- `GET /api/commercial/readiness` returns pass/fail checks and blockers against the 2B KRW target.
- `GET /api/threat-feeds/freshness` returns fresh/stale feed evidence from TTL and last update time.
- `GET /api/events.ndjson` exports events as newline-delimited JSON for SOC/SIEM ingestion tests.
- `GET /api/commercial/evidence-manifest` returns the buyer-verifiable runtime, document, and deployment evidence map.
- `GET /api/support-bundle` returns health, KPIs, license, readiness, and evidence counts without admin secrets.

The formal acceptance criteria are in `docs/commercial/20b-krw-sale-readiness.md`.

The enterprise product package evidence is tracked in:

- `docs/superpowers/specs/2026-07-02-enterprise-product-package-design.md`
- `docs/superpowers/plans/2026-07-02-enterprise-product-package.md`
- `docs/superpowers/specs/2026-07-02-feed-freshness-siem-evidence-design.md`
- `docs/superpowers/plans/2026-07-02-feed-freshness-siem-evidence.md`
- `docs/superpowers/specs/2026-07-03-buyer-evidence-manifest-design.md`
- `docs/superpowers/plans/2026-07-03-buyer-evidence-manifest.md`
- `docs/figma/enterprise-product-architecture.md`
- `docs/product-design/enterprise-operator-workflows.md`
- `docs/analytics/enterprise-value-scorecard.md`
- `docs/ponytail/2026-07-02-complexity-audit.md`

## Run

```bash
cargo run
```

Open `http://127.0.0.1:8080/admin`.

Useful environment variables:

- `BIND_ADDR`: listen address, default `127.0.0.1:8080`
- `ADMIN_TOKEN`: optional write token for management writes via `X-Admin-Token`
- `WAF_IDS_STATE_PATH`: optional JSON state path. When omitted, the service runs with seeded in-memory state.
- `DNSBL_ORIGIN`: DNSBL zone origin, default `dnsbl.local`
- `EVENT_LIMIT`: retained event count, default `1000`; must be greater than zero

Example with persistent local state:

```bash
ADMIN_TOKEN=dev-secret \
WAF_IDS_STATE_PATH=./waf-ids-state.local.json \
DNSBL_ORIGIN=dnsbl.example \
cargo run
```

## API

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/api/routes
curl http://127.0.0.1:8080/api/threats
curl http://127.0.0.1:8080/api/dnsbl
curl http://127.0.0.1:8080/api/commercial/license
curl http://127.0.0.1:8080/api/commercial/readiness
curl http://127.0.0.1:8080/api/commercial/evidence-manifest
curl http://127.0.0.1:8080/api/threat-feeds
curl http://127.0.0.1:8080/api/threat-feeds/freshness
curl -X POST http://127.0.0.1:8080/api/threat-feeds/import/phishing-database \
  -H 'content-type: application/json' \
  -H 'x-admin-token: dev-secret' \
  -d '{}'
curl http://127.0.0.1:8080/api/events.ndjson
curl http://127.0.0.1:8080/api/support-bundle
curl http://127.0.0.1:8080/dnsbl/zone
curl http://127.0.0.1:8080/gateway/demo?q=union%20select
```

Add a blocking route:

```bash
curl -X POST http://127.0.0.1:8080/api/routes \
  -H 'content-type: application/json' \
  -H 'x-admin-token: dev-secret' \
  -d '{
    "id": "api",
    "path_prefix": "/api",
    "upstream": "https://example.com",
    "mode": "block",
    "enabled": true
  }'
```

Management writes are upserts:

- routes are keyed by `id`
- threat indicators are keyed by `indicator_type`, `value`, and `source`
- DNSBL entries are keyed by `address`

DNSBL response codes must be IPv4 loopback-style values in `127.0.0.0/8`.

Import a reviewed threat feed:

```bash
curl -X POST http://127.0.0.1:8080/api/threat-feeds/import \
  -H 'content-type: application/json' \
  -H 'x-admin-token: dev-secret' \
  -d '{
    "feed_id": "misp-seoul",
    "source": "misp://soc.example",
    "ttl_seconds": 600,
    "threats": [{
      "value": "credential_dump",
      "indicator_type": "malware",
      "severity": "critical",
      "source": "misp-seoul",
      "ttl_seconds": 600
    }],
    "dnsbl": [{
      "address": "198.51.100.23",
      "code": "127.0.0.4",
      "reason": "feed scanner",
      "source": "misp-seoul",
      "ttl_seconds": 600
    }]
  }'
```

Import active phishing domains/IPs directly from the public Phishing.Database project:

```bash
curl -X POST http://127.0.0.1:8080/api/threat-feeds/import/phishing-database \
  -H 'content-type: application/json' \
  -H 'x-admin-token: dev-secret' \
  -d '{
    "feed_id": "phishing-db-seoul",
    "domain_limit": 5000,
    "ip_limit": 5000,
    "severity": "high",
    "ttl_seconds": 3600
  }'
```

Deployment assets:

- `Dockerfile`
- `deploy/docker-compose.yml`
- `deploy/kubernetes/waf-ids-ai-soc.yaml`

## Workspace

- `crates/waf-ids-core`: pure domain models, validation, upserts, scoring, DNSBL zone formatting, event retention, threat-feed freshness classification, KPI snapshots, commercial readiness snapshots, and buyer evidence manifests.
- `src/lib.rs`: Axum management API, admin console, optional state persistence, upstream proxying, NDJSON event export, evidence manifest/support bundle assembly, and in-crate HTTP tests.
- `src/main.rs`: process configuration and server startup.

The core is a local workspace crate rather than a git submodule because it does not yet have a separate release cadence or external consumers.

## Roadmap

1. Coraza/OWASP CRS adapter for HTTP transaction scoring.
2. Suricata EVE JSON ingest and correlation with gateway events.
3. STIX/TAXII and MISP/OpenCTI feed import jobs.
4. Authoritative DNSBL service mode using Hickory DNS.
5. AI SOC analyst assist with human approval gates for blocking changes.
6. Full SIEM adapters after the NDJSON export contract is proven in buyer labs.

## Verification

```bash
cargo fmt --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
scripts/smoke.sh
```

Untrusted-input surfaces (request scorer, state deserializer, admin-token and
DNSBL parsers) are covered by coverage-guided fuzzing plus stable property
tests. See [`docs/fuzzing.md`](docs/fuzzing.md).
