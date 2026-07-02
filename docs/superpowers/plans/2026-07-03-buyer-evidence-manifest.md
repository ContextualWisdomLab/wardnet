# Buyer Evidence Manifest Plan

## Goal

Advance the 2B KRW buyer-readiness baseline by giving enterprise evaluators one runtime contract that lists the evidence they must verify.

## Scope

- Add a pure `BuyerEvidenceManifest` model and deterministic snapshot function to `crates/waf-ids-core`.
- Expose `GET /api/commercial/evidence-manifest` from the app crate.
- Include the manifest in `GET /api/support-bundle` so support handoff and buyer due diligence share the same evidence map.
- Add the manifest to the embedded admin console.
- Update README, commercial readiness, buyer due diligence, Product Design workflow, SOC KPI, and FigJam architecture evidence.
- Extend tests and smoke coverage to prove the endpoint and support-bundle contract.

## Non-Goals

- No new git submodule.
- No new dependency.
- No vendor SIEM adapter before a named buyer mapping exists.
- No Figma Code Connect.

## Acceptance

- `GET /api/commercial/evidence-manifest` returns readiness state, blockers, runtime counts, required endpoints, document paths, and deployment assets.
- Required endpoints include readiness, feed freshness, events NDJSON, DNSBL zone, and support bundle.
- Support bundle embeds the same manifest without secrets.
- Local verification passes for format, tests, clippy, smoke, and diff hygiene.
