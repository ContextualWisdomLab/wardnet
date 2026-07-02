# Ponytail Complexity Audit

## Decision

Split reusable WAF/IDS/SOC domain logic into `crates/waf-ids-core` inside the same Cargo workspace. Do not use a git submodule at this stage.

## Findings

- Shrink: `src/lib.rs` mixed Axum handlers, persistence, proxying, domain models, scoring, readiness, and DNSBL formatting. Moving deterministic domain logic to `waf-ids-core` reduces the app crate surface without changing runtime behavior.
- YAGNI: a submodule would add versioning, CI, review, and release overhead before there is an independent library consumer.
- Delete: do not create a mock "enterprise WAF engine" to justify the sale package. Keep WAF and IDS engines as explicit future adapters to Coraza/OWASP CRS and Suricata.
- Keep: the single binary, JSON state option, admin console, smoke test, and deployment assets remain important for buyer lab time-to-value.

## Resulting Boundaries

- `crates/waf-ids-core`: pure models, validation, upserts, scoring, event retention, KPI snapshots, readiness snapshots, and DNSBL zone formatting.
- `src/lib.rs`: Axum app, admin console, management endpoints, optional persistence, upstream proxying, support bundle assembly, and integration tests.
- `src/main.rs`: process configuration and server startup.

## Follow-On Refactors

1. Move HTTP integration tests to `tests/` after a public test fixture becomes useful.
2. Add adapter crates only when Coraza, Suricata, TAXII, MISP, or Hickory DNS integrations are implemented.
3. Keep AI SOC recommendation code separate from enforcement writes until approval and audit workflows exist.
