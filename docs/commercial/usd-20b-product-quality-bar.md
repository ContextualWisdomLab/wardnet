# USD 20 Billion Product Quality Bar

Wardnet uses **USD 20 billion** as a deliberately demanding software-sale quality ambition: the product, evidence, architecture, operability, security posture, and buyer experience should be developed to a standard that could withstand due diligence for a software asset of that scale. It is not a tenant price, contract-value threshold, billing rule, or accounting fact.

This ambition therefore has no direct numeric mapping to `annual_contract_value_krw`, `target_sale_value_krw`, license metadata, revenue, ARR, or another customer field. The existing 2B KRW customer-contract readiness predicate remains a separate compatibility contract documented in [2B KRW Customer Contract Readiness](./2b-krw-customer-contract-readiness.md).

## Authority boundary

The USD 20 billion ambition is an engineering and commercial-quality bar. It is satisfied only through buyer-visible evidence accumulated in the bounded contexts that own the relevant truth. A number in a tenant profile cannot satisfy it.

Wardnet owns gateway and SOC control-plane policy, Agent Artifact Admission, Wardnet security verdicts, local runtime/network enforcement evidence, and Wardnet audit/provenance. Quarantine Sandbox Runtime owns hostile execution isolation. contextual-orchestrator owns Agent/LLM provider and model orchestration. EgressWeave may provide a released outbound-policy contract. Context Graph Contracts and Enterprise Architecture Core retain their respective canonical contract and architecture-decision authority. Wardnet consumes those external capabilities only through released, versioned contracts or anti-corruption layers and does not copy their source or read their application databases.

## Buyer-visible evidence

Progress against this quality bar is demonstrated by concrete evidence such as:

- fail-closed authentication, authorization, admission and outbound-destination policy with hostile-case regressions;
- production-grade durability, tenant isolation, transactionality, replay/idempotency, bounded resource use, recovery and rollback;
- proven WAF/IDS enforcement and measurable detection/false-positive behavior rather than hand-written baseline heuristics alone;
- reproducible exact-head CI, security analysis, fuzz/property coverage, 100% owned production statement/branch/edge-case coverage, rustdoc/docstring completeness, SBOM, provenance, signatures and immutable release identity;
- protected-branch governance that is satisfiable without self-approval, fabricated human review, routine bypass, stale predecessor evidence or false-green infrastructure output;
- versioned integration contracts with canonical CWL owners, provenance, schema/conformance evidence, and fail-closed behavior when an immutable compatible release is absent;
- production-shaped performance, capacity, readiness/liveness/startup, incident-response, observability, backup/restore and game-day evidence;
- code-current PRD/TRD/ADR/architecture/threat-model/test/operability/release documentation whose claims distinguish protected truth from candidate work;
- procurement-facing evidence that a buyer can independently verify without trusting a marketing statement.

The live evidence inventory and remaining gaps belong in `docs/product-technical-gap-baseline.md` and the repository's production-readiness issue. Individual feature PRs may contribute evidence, but neither an open branch nor a readiness endpoint promotes that evidence to protected/released truth.

## Decision rule

A feature does not advance this bar merely because it raises a commercial number. It advances the bar when it removes a buyer-visible product, security, reliability, governance, integration, performance, or operability gap with reproducible evidence and preserves Wardnet's bounded-context ownership.

Conversely, no deployment should be rejected solely because its `annual_contract_value_krw` does not encode the USD 20 billion ambition. Customer contract metadata and software quality/valuation are different ubiquitous-language concepts with different authorities.

## Evidence discipline

Claims against this quality bar must identify the exact protected source or immutable release, applicable tests and security gates, contract/provenance identity where external owners are consumed, known residual risks, and rollback/recovery behavior. Candidate PR evidence is useful for development but must not be presented as shipped capability before protected integration and release.

This document intentionally does not create a product valuation model or forecast. If a future process needs financial valuation, pricing, billing, or accounting truth, that requires its own accepted bounded context and evidence rather than overloading Wardnet's customer readiness fields.
