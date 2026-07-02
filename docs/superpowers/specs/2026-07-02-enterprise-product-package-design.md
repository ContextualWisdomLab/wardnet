# Enterprise Product Package Design

## Goal

Move the current WAF/IDS/AI SOC runtime from a commercial baseline into a buyer-verifiable enterprise product package suitable for a 2B KRW due-diligence conversation.

## Plugin Inputs Used

- Superpowers: structured the spec, implementation plan, execution loop, and verification contract.
- Figma: generated a FigJam architecture artifact without Figma Code Connect.
- Product Design: shaped operator and buyer workflows for the admin console, readiness, support bundle, and feed operations.
- Ponytail: audited complexity and selected a small workspace crate split instead of broader decomposition.
- Data Analytics: defined KPIs and buyer-value metrics that can be used in enterprise evaluation.

## Figma Artifact

- FigJam architecture: https://www.figma.com/board/JExziD87eUWKLERECUGhWQ?utm_source=codex&utm_content=edit_in_figjam&oai_id=&request_id=a97d2861-82f8-4d43-9d16-27e07b13b10c&architecture=true
- Constraint: Figma Code Connect is explicitly out of scope and was not used.

## Product Requirements

1. Keep the first screen as an operations console, not a landing page.
2. Show route, threat feed, DNSBL, event, KPI, license, readiness, and support-bundle states in a scan-friendly web surface.
3. Make readiness blockers concrete enough for a buyer engineer or support engineer to reproduce through APIs.
4. Preserve the current standalone path: one Rust binary, optional JSON state, Docker, Compose, Kubernetes, and smoke test.
5. Separate reusable domain logic only where it reduces future adapter complexity.
6. Avoid a git submodule until there is an independently versioned engine or SDK with a separate release cadence.

## Architecture Decision

Create `crates/waf-ids-core` inside the same Cargo workspace. It owns pure domain models and deterministic logic:

- route, threat, DNSBL, feed, event, license, KPI, and readiness models
- route/threat/DNSBL/feed validation and upsert semantics
- request scoring and DNSBL zone export
- event retention, KPI snapshot, and readiness snapshot

The root `waf-ids-ai-soc` crate keeps process startup, Axum routes, persistence, upstream proxying, admin console, and integration tests. This boundary gives a future SDK/adapters a stable domain surface without adding submodule governance overhead.

## Product Design Scope

- Admin console: compact operational overview with no marketing hero.
- Readiness: pass/fail state with blocker identifiers and evidence paths.
- Threat feed operations: imported feed status, source, TTL, threat count, DNSBL count, and latest update.
- Support bundle: generated health, KPI, license, readiness, and evidence counts with no secrets.

## Analytics Scope

Primary buyer metrics:

- sale readiness pass rate
- buyer lab time-to-value
- threat feed freshness SLA
- gateway decision latency
- false-positive rollback rate
- support bundle completeness

Driver metrics:

- enabled route count
- imported feed count and freshness
- threat indicator count by severity/source
- DNSBL entry count by response code/source
- blocked and monitored event counts
- CI, smoke, and coverage status

Guardrails:

- unauthorized write attempts
- p95/p99 decision latency
- event persistence failures
- score override or rollback count
- stale feed percentage

## Ponytail Audit Outcome

- Shrink: move pure domain logic out of `src/lib.rs` into `crates/waf-ids-core`.
- YAGNI: do not add a git submodule before an independent release boundary exists.
- Delete: do not build a fake WAF/IDS engine; keep Coraza and Suricata as explicit future adapters.
- Net: reduce app crate complexity while preserving the single-binary sales-demo path.

## Acceptance Criteria

1. Workspace crate boundary exists and the root crate uses it.
2. Product, design, analytics, Ponytail, and Figma artifacts are committed.
3. README and architecture docs explain the reusable core boundary.
4. `cargo fmt --check`, `cargo test --locked --workspace`, coverage, clippy, `actionlint`, `scripts/smoke.sh`, and `git diff --check` pass.
5. Work is published through a PR, real findings are addressed, and default branch CI/Scorecard are verified.
