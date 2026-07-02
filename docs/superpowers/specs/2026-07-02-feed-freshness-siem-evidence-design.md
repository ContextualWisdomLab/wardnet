# Feed Freshness and SIEM Evidence Design

## Goal

Strengthen the 2B KRW buyer-lab package with evidence that threat updates are fresh and security events can be handed to a SOC or SIEM without source-code access.

## Plugin Inputs Used

- Superpowers: keep the work as a concrete spec, plan, execution loop, and verification contract.
- Figma: extend the existing FigJam architecture board without Figma Code Connect.
- Product Design: keep the admin surface operational and expose freshness/export evidence in the first-screen workflow.
- Ponytail: avoid a new crate, submodule, scheduler, or SIEM adapter until a real integration exists.
- Data Analytics: convert threat-feed freshness and SOC export into buyer-verifiable KPIs and guardrails.

## Product Requirements

1. A buyer can distinguish fresh and stale threat feeds from an API response.
2. Sale readiness fails when all imported threat feeds are stale.
3. SOC event export is available as newline-delimited JSON for simple ingestion tests.
4. The support bundle includes feed freshness evidence.
5. The admin console shows feed freshness and event export surfaces without becoming a marketing page.
6. No new dependency, submodule, or adapter crate is added for this tranche.

## Architecture

Keep the existing Rust workspace boundary:

- `crates/waf-ids-core`: pure freshness classification, KPI counts, and readiness checks.
- `src/lib.rs`: Axum routes, NDJSON event export, support bundle assembly, admin console, and HTTP tests.
- `scripts/smoke.sh`: buyer-lab verification of freshness, readiness, support bundle, and event export.

## API Additions

- `GET /api/threat-feeds/freshness`: returns feed id, source, last update, threat count, DNSBL count, TTL, expiry, and stale boolean.
- `GET /api/events.ndjson`: returns one JSON event per line with `application/x-ndjson`.

## KPI Additions

- `fresh_threat_feed_count`
- `stale_threat_feed_count`

## Readiness Change

The `threat_feed_updates` readiness check now means at least one imported feed is fresh within its TTL, not merely that a feed was imported once.

## Acceptance Criteria

1. FigJam board includes a buyer-verifiable feed freshness and SOC export evidence flow.
2. Product, analytics, commercial, architecture, and buyer due-diligence docs describe the new evidence.
3. Unit and HTTP tests cover fresh feed, stale feed, readiness, support bundle, and NDJSON export.
4. `scripts/smoke.sh` verifies the new buyer-lab evidence.
5. `cargo fmt --check`, `cargo test --locked --workspace`, coverage, clippy, `actionlint`, smoke, and diff check pass.
6. Work is published through a PR, real findings are addressed, and default branch CI/Scorecard are verified.
