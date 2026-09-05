# ADR-2026-09-05-OUTBOUND-REPUTATION: Wardnet owns outbound site security reputation

- Date: 2026-09-05
- Status: Proposed for architectural review; not an implemented capability.
- Scope: Wardnet security policy, threat evidence, and SOC accountability for outbound destinations.
- Baseline: `main@5829a0f08d78de464dd24393ce5d0f25fba9d126`.
- Product request: prevent internal users, services, and agents from contacting external services with adverse security reputation.

## Context

Wardnet already owns WAF/IDS/SOC gateway decisions, threat-intelligence ingestion, and DNSBL publishing. Its current `/gateway/{path}` evaluates an incoming request before forwarding to a configured upstream. That is not a company-wide outbound website reputation enforcement system. The current `ThreatIndicator` and `SecurityEvent` models also lack the complete destination, evidence-lifecycle, tenant, and policy-version contract proposed here.

The objection to using Wardnet as a generic website-reputation utility is valid when it means putting crawler rankings, extraction difficulty, or an unrelated HTTP client into the WAF. It does not exclude a distinct security responsibility: deciding whether an identified internal workload may contact an external destination under current threat intelligence and organizational policy. This decision complements ingress WAF and IDS observations rather than reinterpreting them.

Current owner evidence in [Wardnet #136](https://github.com/ContextualWisdomLab/wardnet/pull/136), [#115](https://github.com/ContextualWisdomLab/wardnet/pull/115), and [EgressWeave #237](https://github.com/ContextualWisdomLab/EgressWeave/issues/237) assigns reusable outbound HTTP destination/address, DNS, redirect, proxy, TLS, and resource authorization to EgressWeave. This ADR does not reverse that boundary. The EgressWeave GitHub Releases listing returned no releases during the 2026-09-05 review; an immutable compatible Rust-consumer contract is an integration prerequisite, not a reason to defer Wardnet's domain design or offline implementation.

## Decision

Add **Outbound Site Reputation** as a bounded security capability owned by Wardnet. Implement its future deterministic policy and evidence core in a separate Rust workspace crate, with Wardnet application adapters and a versioned evaluation surface. Keep it independently testable without network access, an LLM, or a sibling repository checkout.

Wardnet owns destination maliciousness assessment, evidence admission and lifecycle, tenant/workload/purpose policy, scoped business exceptions, explanatory decisions, and SOC records. EgressWeave owns safe transport and connection authority. A policy enforcement point composes the two; neither product's allow decision can override the other's denial. Protect-mode forwarding requires authenticated context, an explicit Wardnet allow, a valid EgressWeave authorization bound to the actual connection, current matching evidence, and the required audit reservation.

A reputation verdict is not proof that traffic was intercepted or blocked. Coverage and actual enforcement outcomes must be recorded separately. Company-wide protection requires an enforced network path; a voluntary SDK integration, DNS feed, or the present reverse-proxy endpoint alone is insufficient.

The normative requirements, threat cases, and delivery boundaries are in the [design](../superpowers/specs/2026-09-05-outbound-site-reputation-design.md); the [implementation plan](../superpowers/plans/2026-09-05-outbound-site-reputation.md) divides independently testable slices.

## Alternatives considered

| Alternative | Benefit | Rejection or consequence |
| --- | --- | --- |
| Extend the existing WAF score/DNSBL matcher into a universal site score | Minimal apparent code change | Conflates request payload, source IP, destination identity, and evidence lifetimes. An IP DNSBL is not a domain/URL reputation model. |
| Put maliciousness policy inside EgressWeave, or introduce a new mandatory general reputation service | Central-looking interface | Moves SOC/security authority into the transport owner or adds a premature independent deployment. External intelligence providers remain useful inputs, not owners of Wardnet business policy. |
| Separate Wardnet reputation core with versioned transport integration | Explicit security responsibility, deterministic testing, reusable standalone Rust boundary | Selected. Requires disciplined schemas, interception coverage, and an immutable compatible transport contract before production integration. |

## Safety and non-goals

Unknown is not safe. Expired, deleted, revoked, unverifiable, or out-of-scope evidence cannot silently authorize traffic. Freshness and source health remain distinct from maliciousness. Correlated feeds are not independent votes; provider confidence is not a calibrated probability. Do not inherit `BLOCK_SCORE` or invent a weighted machine-learning score for this feature.

Business exceptions are authenticated, exact-scope, expiring, audited grants for unknown destinations; they do not erase evidence or override hard threat or transport denials. No raw URLs containing credentials, request bodies, or tokens are exported to providers or ordinary logs.

This capability does not own crawling, stealth, CAPTCHA solving, website popularity, content credibility, general HTTP transport, malware detonation, LLM routing, DLP, or a full secure-web-gateway product. CAPTCHA, robots rules, HTTP 403/429, domain novelty, and geography alone are not maliciousness evidence. Optional future analysis must use its canonical owner and cannot automatically widen enforcement authority.

## Consequences and adoption

The design adds a deliberate security bounded context without duplicating EgressWeave. It creates operating costs: feed licensing and freshness, false-positive handling, policy rollout, audit durability, and deployment coverage. Opaque HTTPS supports only the identities actually observed; full URL protection cannot be advertised without URL visibility.

This documentation PR changes no runtime, deployment, dependency, or workflow. Its ADR remains Proposed until reviewed. Offline domain work can proceed independently; live enforcement is gated on the versioned owner contract and the plan's security acceptance. Existing preservation PRs are neither merged nor superseded by this record. PR #130 remains the sole writer of `docs/product-technical-gap-baseline.md`; this change does not create a competing ledger.

## Evidence

See [research and source traceability](../papers/outbound-site-reputation-sources.md). Protective DNS practice supports the security use case; DNS reputation research motivates evidence and temporal evaluation, not a claim that Wardnet already reproduces a published detector. Repository observations above describe the pinned baseline and inspected open work, not shipped future features.
