# 2B KRW Customer Contract Readiness Standard

This document defines Wardnet's existing customer-contract readiness predicate. The `2_000_000_000` KRW threshold is tenant/customer commercial metadata used by the current readiness API. It is not product valuation, software-sale ambition, a billing ledger, or evidence that Wardnet itself is worth or should be sold for that amount.

The separate [USD 20 billion product-quality bar](./usd-20b-product-quality-bar.md) is a software-quality ambition. It must not be represented by `annual_contract_value_krw`, `target_sale_value_krw`, tenant pricing, billing state, or accounting facts.

## Acceptance Criteria

1. The product exposes a tenant-aware license profile through `GET /api/commercial/license`.
2. Authorized operators can register license metadata through `POST /api/commercial/license`.
3. The license profile supports edition, status, licensee, node count, support contact, and annual contract value.
4. The existing readiness predicate treats `annual_contract_value_krw >= 2_000_000_000` as the customer-contract-value check. Changing that value requires an independent accepted product decision; it is never derived from the USD 20 billion quality ambition.
5. Threat feed updates are importable through `POST /api/threat-feeds/import`.
6. The product exposes fresh/stale threat-feed evidence through `GET /api/threat-feeds/freshness`.
7. The product exposes SOC event export through `GET /api/events.ndjson`.
8. The product retains threat-feed status, imported HTTP indicators, DNSBL entries, gateway routes, and security events across restart when the configured standalone state adapter is in use.
9. The readiness API reports concrete blocker identifiers rather than a vague success state.
10. The support-bundle API returns health, KPIs, license metadata, readiness checks, feed freshness, and evidence counts without secrets.
11. The product exposes a buyer evidence manifest through `GET /api/commercial/evidence-manifest` so evaluators can verify required runtime APIs, committed documents, and deployment assets from one contract.
12. The product exposes management write audit logs through `GET /api/audit-logs` without persisting administrator tokens or request bodies.
13. Docker, Compose, and Kubernetes deployment assets exist for buyer lab validation where the protected source advertises them.
14. Security, compliance, architecture, operations, and KPI evidence is committed with the product and must remain explicit about protected-main versus candidate maturity.
15. Reusable domain logic is separated from HTTP/persistence code when that improves maintainability without inventing a second authority.
16. Product-design, analytics, complexity-audit, and implementation-plan evidence used in due diligence remains evidence, not a substitute for executable product gates.

## Runtime Readiness API

`GET /api/commercial/readiness` currently returns:

- `target_sale_value_krw`: `2000000000`;
- `ready_for_enterprise_sale`: true only when all current readiness checks pass;
- `readiness_level`: `sale_ready` or `implementation_required`;
- `blockers`: failed check identifiers;
- `deployment_assets`: expected packaging files;
- `buyer_evidence`: due-diligence document paths.

`GET /api/commercial/evidence-manifest` returns the buyer validation map:

- current readiness state and blockers;
- runtime counts for routes, indicators, DNSBL entries, feeds, fresh/stale feeds, and events;
- required evidence endpoints with method, path, content type, and what each endpoint proves;
- management audit-log count and the `GET /api/audit-logs` endpoint for successful administrator writes;
- committed document paths and deployment assets that should be reviewed during procurement.

These fields are compatibility/runtime evidence. Their names do not make the customer contract threshold a product-valuation authority.

## Required Passing Checks

- `license`: active or evaluation license metadata is present.
- `contract_value`: annual contract value is at least 2B KRW.
- `threat_feed_updates`: at least one imported threat feed is fresh within its TTL.
- `gateway_enforcement`: at least one enabled gateway route exists.
- `dnsbl_publication`: DNSBL entries are available for zone export.
- `support_evidence`: at least one security event exists for a support bundle.

## Current Boundary

The readiness predicate is only one customer/commercial metadata surface. It does not establish production readiness. Protected production truth still requires the independent security, identity, durable-state, release, observability, recovery, integration, and review/control-plane gates tracked by the repository's production-readiness authority and product/technical gap baseline.

The current 2B KRW value remains unchanged in this documentation repair. A future change to customer contract readiness must be justified on its own product authority and versioned API compatibility; it must not be inferred from the USD 20 billion software-quality ambition.
