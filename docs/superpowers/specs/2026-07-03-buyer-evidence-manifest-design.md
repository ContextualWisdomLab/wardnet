# Buyer Evidence Manifest Design

## Problem

The runtime already exposes commercial readiness, feed freshness, SOC NDJSON export, DNSBL zone export, and a support bundle. A buyer still has to assemble the procurement checklist manually from several endpoints and documents.

## Design

Keep the evidence manifest in `waf-ids-core` because it is deterministic domain evidence assembled from existing `AppData`, KPI, and readiness snapshots.

The app crate remains responsible only for:

- binding `GET /api/commercial/evidence-manifest`
- placing the manifest into `SupportBundle`
- rendering it in the embedded admin console

## Manifest Fields

- `generated_at_unix`
- `target_sale_value_krw`
- `ready_for_enterprise_sale`
- `readiness_level`
- `blockers`
- `runtime_counts`
- `required_endpoints`
- `document_paths`
- `deployment_assets`

## Boundary Decision

No new crate or submodule is justified. The manifest is a small pure snapshot over existing domain state, and moving it elsewhere would add release and review overhead without an independent consumer.

## Verification

- Core unit tests assert ready and stale manifest behavior.
- HTTP integration tests assert endpoint and support bundle payloads.
- Smoke test validates buyer-lab lifecycle through the new endpoint.
