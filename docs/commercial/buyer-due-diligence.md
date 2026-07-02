# Buyer Due Diligence Evidence

## Product Evidence

- Runtime health: `GET /healthz`
- Web control plane: `GET /admin`
- Gateway routes: `GET /api/routes`
- Threat indicators: `GET /api/threats`
- DNSBL entries: `GET /api/dnsbl`
- DNSBL zone: `GET /dnsbl/zone`
- Security events: `GET /api/events`
- SOC event export: `GET /api/events.ndjson`
- SOC KPIs: `GET /api/kpis`
- License profile: `GET /api/commercial/license`
- Sale readiness: `GET /api/commercial/readiness`
- Buyer evidence manifest: `GET /api/commercial/evidence-manifest`
- Threat feed status: `GET /api/threat-feeds`
- Threat feed freshness: `GET /api/threat-feeds/freshness`
- Support bundle: `GET /api/support-bundle`

## Engineering Evidence

- Memory-safe Rust implementation with Axum and Tokio.
- JSON state persistence with temporary file write and atomic rename.
- In-memory rollback when persistence fails.
- Route-scoped monitor/block mode to reduce accidental global enforcement.
- Authenticated management writes through `X-Admin-Token`.
- Automated tests for management APIs, gateway scoring, DNSBL export, event NDJSON export, feed freshness, persistence failures, commercial readiness, and legacy state compatibility.
- Buyer evidence manifest that lists required runtime endpoints, committed document paths, deployment assets, blockers, and runtime evidence counts from one API.
- `scripts/smoke.sh` verifies a full local lifecycle including restart persistence.

## Security Review Packet

- [Security policy](../../SECURITY.md)
- [Threat model](../security/threat-model.md)
- [Compliance mapping](../security/compliance-mapping.md)
- [Operations runbook](../runbooks/operations.md)
- [Architecture](../architecture.md)
- [SOC KPI model](../analytics/soc-kpis.md)

## Deployment Review Packet

- [Dockerfile](../../Dockerfile)
- [Compose stack](../../deploy/docker-compose.yml)
- [Kubernetes manifest](../../deploy/kubernetes/waf-ids-ai-soc.yaml)

## Buyer Lab Script

Run:

```bash
cargo test --locked
scripts/smoke.sh
```

Then inspect:

```bash
curl -fsS http://127.0.0.1:8080/api/commercial/readiness
curl -fsS http://127.0.0.1:8080/api/commercial/evidence-manifest
curl -fsS http://127.0.0.1:8080/api/threat-feeds/freshness
curl -fsS http://127.0.0.1:8080/api/events.ndjson
curl -fsS http://127.0.0.1:8080/api/support-bundle
```
