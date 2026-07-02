# 2B KRW Commercial Sale Readiness Standard

This project treats a 2B KRW sale as an enterprise due-diligence threshold, not a marketing claim. The runtime must expose evidence that an operator can verify without reading source code.

## Acceptance Criteria

1. The product exposes a tenant-aware license profile through `GET /api/commercial/license`.
2. Authorized operators can register license metadata through `POST /api/commercial/license`.
3. The license profile must support edition, status, licensee, node count, support contact, and annual contract value.
4. The annual contract value must be at least `2_000_000_000` KRW for the readiness API to report sale readiness.
5. Threat feed updates must be importable through `POST /api/threat-feeds/import`.
6. The product must expose fresh/stale threat feed evidence through `GET /api/threat-feeds/freshness`.
7. The product must expose SOC event export through `GET /api/events.ndjson`.
8. The product must retain threat feed status, imported HTTP indicators, DNSBL entries, gateway routes, and security events across restart when `WAF_IDS_STATE_PATH` is configured.
9. The readiness API must report blockers instead of returning a vague success state.
10. The support bundle API must return health, KPIs, license metadata, readiness checks, feed freshness, and evidence counts without secrets.
11. Docker, Compose, and Kubernetes deployment assets must exist for buyer lab validation.
12. Security, compliance, architecture, operations, and KPI evidence must be committed with the product.
13. Reusable domain logic must be separated from HTTP/persistence code when that improves maintainability without adding release overhead.
14. Product design, Figma/FigJam, analytics, complexity-audit, and implementation-plan evidence must be committed for buyer due diligence.

## Runtime Readiness API

`GET /api/commercial/readiness` returns:

- `target_sale_value_krw`: always `2000000000`
- `ready_for_enterprise_sale`: true only when all checks pass
- `readiness_level`: `sale_ready` or `implementation_required`
- `blockers`: failed check identifiers
- `deployment_assets`: expected production packaging files
- `buyer_evidence`: due-diligence document paths

## Required Passing Checks

- `license`: active or evaluation license metadata is present.
- `contract_value`: annual contract value is at least 2B KRW.
- `threat_feed_updates`: at least one imported threat feed is fresh within its TTL.
- `gateway_enforcement`: at least one enabled gateway route exists.
- `dnsbl_publication`: DNSBL entries are available for zone export.
- `support_evidence`: at least one security event exists for a support bundle.

## Current Boundary

The project is still a commercial baseline, not a complete enterprise WAF/IDS suite. Production buyers should require follow-on integration of Coraza/OWASP CRS, Suricata EVE ingest, durable database storage, SSO/RBAC, audit logs, signed release artifacts, and production SIEM mapping before internet-edge deployment.

The current library boundary is `crates/waf-ids-core`, a local workspace crate. A submodule is not justified until an independently versioned adapter or SDK exists.
