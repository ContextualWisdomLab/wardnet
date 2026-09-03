# Wardnet Product / Technical Gap Baseline

This document is Wardnet's code-adjacent gap ledger. It distinguishes protected product truth from active candidate work and from external canonical-owner dependencies. Live PR/check/ruleset state still has to be re-read before any merge or release decision; this file does not promote an open branch, predecessor check, or mutable sibling repository to authority.

## Commercial authorities

Wardnet has two deliberately separate commercial concepts.

- **USD 20 billion product-quality ambition** is the standing buyer-quality bar. It is satisfied only through evidence-backed security, operability, release, integration, supportability, performance, governance, and recovery quality. It must not be encoded as tenant pricing, `annual_contract_value_krw`, billing, accounting, ARR, or another customer's commercial fact. The detailed product-quality contract is `docs/commercial/usd-20b-product-quality-bar.md`.
- **2B KRW customer-contract readiness** is the existing Wardnet commercial-readiness predicate represented by `TARGET_SALE_VALUE_KRW = 2_000_000_000` and tenant `annual_contract_value_krw`. It is not product valuation. The canonical document is `docs/commercial/2b-krw-customer-contract-readiness.md`; the historical `docs/commercial/20b-krw-sale-readiness.md` path is compatibility-only and is not numeric authority.

Changing either authority requires its own product rationale and executable/documentation fitness. One may never be mechanically derived from the other.

## Protected baseline

Protected/default `main` currently contains the Rust-first gateway/SOC control-plane baseline and PR #137's external administrator-Secret hardening. Wardnet has no GitHub Release, so protected source remains unreleased product truth rather than an immutable production release identity. Issue #87 is the aggregate production-readiness gate and remains authoritative for closure criteria.

The protected baseline must continue to preserve Wardnet ownership of gateway/admission/security-control decisions, policy versions, audit/provenance evidence, and Wardnet security verdicts without absorbing foreign bounded contexts.

## Highest-priority buyer-visible gaps

| Priority | Gap | Current owner path | Protected completion evidence |
| --- | --- | --- | --- |
| P0 | Fail-closed management authentication | #78 / PR #155 | Non-loopback startup cannot become ready without a write-capable administrator; loopback development remains explicit; exact-current-PR security/coverage/review governance is terminal-valid before protected merge. |
| P0 | Fail-closed outbound destination policy | #79 / PR #136 | Every Wardnet-owned outbound HTTP surface is mediated; DNS and request execution share one bounded deadline; explicit allowlist/deny precedence and decision evidence are tested; SSRF/rebinding/redirect/proxy bypasses fail closed. |
| P0 | Agent Artifact Admission | #128 / PR #129 | Structured artifact intent binds ecosystem/name/version/source/digest/destination/configuration/build variant; hostile package-manager capability bypasses fail closed; downstream retrieved-byte/execution evidence remains quarantine/execution-broker authority. |
| P0 | PostgreSQL production authority and tenant isolation | #80 | Production mode uses a durable PostgreSQL authority with constraints, default-deny RLS, migrations, transaction-scoped identity context, conflict semantics, backup/restore and measured recovery evidence. |
| P0 | Durable external effects | #81 | Domain mutation and outbox intent are atomic; leased workers, retry classification, idempotency and dead-letter/replay are durable, tenant-safe and observable. |
| P0 | Proven WAF/IDS enforcement and detection quality | #86 with attack acceptance #11 | Pinned real WAF/IDS engines participate in production enforcement/evidence; attack-family and route-class false-positive/false-negative evidence is reproducible; AI SOC remains advisory until authorized policy action. |
| P1 | Enterprise identity and authorization | #82 | Released Keyverse identity signals are consumed through a versioned boundary; Wardnet keeps resource authorization, SoD, approval and audit authority. |
| P1 | Bounded distributed admission/overload behavior | #83 | Attacker-controlled cardinality is bounded; trusted-proxy attribution is explicit; multi-replica quotas and backpressure/degradation semantics are measured and tested. |
| P1 | Immutable release/promotion/rollback | #84 | One reviewed source identity maps to signed immutable artifacts, SBOM/provenance, reproducibility evidence, deployment by digest, rollback evidence and a GitHub Release. |
| P1 | Operability/recovery | #85 | OpenTelemetry/SLO/alert/incident/restore evidence is production-shaped, secret-safe, correlated to exact deployment/policy identities and independently recoverable. |

No gap is closed by documentation alone. Protected merge plus the issue-specific behavioral and evidence contract is required.

## Bounded-context and integration constraints

Wardnet owns **Gateway**, **Admission Policy**, **Artifact Identity**, **Security Analysis Integration**, **Network Egress**, **SOC Evidence**, **Runtime Control**, and **Audit / Provenance** only to the extent those concepts are Wardnet security-control truth.

Canonical external owners remain separate:

- `quarantine-sandbox-runtime`: hostile execution, isolation, cleanup and artifact-analysis runtime evidence;
- `EgressWeave`: reusable outbound HTTP-policy contract when a compatible immutable release exists;
- `contextual-orchestrator`: Agent/LLM orchestration, capability/provider/model routing and provider credentials;
- `appguardrail`: its own application guardrail/security-analysis authority;
- `keyverse`: authenticated identity and lifecycle signals;
- `context-graph-contracts`: released provider-neutral Context Assertion/CloudEvent/provenance/admission Shared Kernel;
- `enterprise-architecture-core`: authoritative EA Decision Plane;
- `.github`: organization CI/review/security/ruleset/release control-plane governance.

Wardnet consumes foreign capabilities only through released/versioned contracts and Anti-Corruption Layers. Mutable sibling PR heads, source copies, cross-service SQL, local reimplementation of another owner's truth, and provider-specific authority leakage are not production dependencies.

Security findings, artifact verdicts, incident observations and Wardnet policy decisions remain Wardnet evidence. Architecture-relevant technology/lifecycle/risk/remediation changes may be projected through a released Context Graph contract into the EA owner path, but individual security findings are not promoted into authoritative EA facts.

## Quality and release gates

A release candidate is not commercial-ready merely because source tests pass. One exact protected candidate must simultaneously satisfy:

- realistic hostile/error/replay/race/DoS/network/cleanup tests for changed security boundaries;
- owned production statement/branch/edge-case coverage at repository policy and complete public Rust documentation;
- exact-current-PR and exact-head CI, security, SAST, dependency, package, SBOM, provenance and review/thread evidence required by then-live policy;
- no self-approval, model/bot-as-human approval, force push, routine bypass, predecessor evidence substitution or gate weakening;
- pinned/versioned toolchain and dependencies, immutable package/image identity, signed provenance, release notes and verified rollback;
- product-path performance and operational evidence where the changed surface is latency- or availability-sensitive;
- code-current ADR/architecture/security/threat-model/test/operability documentation for the implemented boundary.

A guarded administrator bypass is limited to a proved control-plane chicken-and-egg where the gate being repaired prevents the minimal repair of that same gate and every organization emergency-policy precondition is satisfied. Ordinary runner/reviewer/provider wait, failed tests, missing evidence or release dependencies do not qualify.

## Current execution order

Issue #87 remains the aggregate readiness authority. The shortest protected path is to finish #78 and #79 without weakening central gates, complete #128 while preserving quarantine ownership, then establish #80 before #81, followed by #82/#83, #86/#11, #84 and #85. Independent low-risk fixes may proceed in parallel when they do not create mutable cross-PR authority or violate stack ancestry.

This baseline should change when protected product truth or an accepted gap contract changes. Transient workflow run IDs and queue snapshots belong in the owning PR/issue or central control-plane owner path rather than becoming durable architecture truth here.
