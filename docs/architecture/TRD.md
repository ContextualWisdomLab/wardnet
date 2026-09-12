# Wardnet Technical Requirements Document

Status: canonical technical requirements for protected-main Wardnet development. This document describes required architecture and acceptance boundaries; it does not promote unmerged branches or foreign-owner mutable heads to released dependencies.

## Technical authority

Wardnet is a Rust-first gateway, WAF/IDS-adjacent SOC control plane, and Agent Artifact Admission authority. The root crate owns HTTP/control-plane application behavior and `crates/waf-ids-core` owns pure domain logic. Proven external security engines and CWL sibling systems remain integration dependencies rather than code to duplicate inside Wardnet.

Source-of-truth order for a conflict is: protected code and executable tests; accepted ADRs; `docs/architecture.md` and security/operations/release documentation; this TRD; product requirements. A requirement that is not yet implemented must stay visibly future/acceptance work rather than being described as protected-main capability.

## Bounded contexts

Wardnet owns the following bounded contexts:

- Gateway Routing and Enforcement: route selection, monitor/block decisions, request limits, and gateway event production.
- SOC Evidence and Operations: security events, KPIs, threat-feed freshness, support evidence, and operator-facing control state.
- Agent Artifact Admission: artifact/evidence binding, policy evaluation, admission decision, reason, and auditable receipt.
- Security Policy and Evidence: Wardnet-owned policy semantics and the evidence needed to justify Wardnet decisions.
- Runtime Configuration: non-secret process-edge configuration captured once as an immutable `RuntimeConfiguration` snapshot when that branch reaches protected main.
- Credential Bootstrap: secret-bearing bootstrap material owned by `CredentialRegistry`.

Persistence, PostgreSQL authority, advanced SIEM/SOAR behavior, optional integrations, and other active-stack work are not considered protected-main truth until their exact changes reach protected main.

## Runtime and implementation requirements

### Language and dependency policy

Gateway, DNSBL, admission, and high-throughput control-plane hot paths are Rust-first. New equivalent security engines must not be invented when a proven engine or standard adapter is available. Dependencies must be pinned/locked according to the repository build contract and security scanned on the exact candidate head.

Cross-repository integration uses **released contracts only**. Wardnet must not copy sibling source, query sibling databases with cross-service SQL, or bind production behavior to a mutable PR/default-branch implementation. Versioned HTTP/event/evidence contracts are preferred at service boundaries.

### Runtime configuration and secrets

Secret-bearing configuration is bootstrapped into `CredentialRegistry`. Environment variables or secret files are bootstrap transport, not handler-time secret authority. Administrator secrets must satisfy the repository's strict admission rules before they can authorize management writes.

Non-secret runtime settings are converging on an immutable `RuntimeConfiguration` snapshot. When that architecture reaches protected main, `run_from_env` must obtain one validated snapshot at the process edge and pass values inward without later direct environment reads. `WAF_IDS_CREDENTIALS_PATH`, `ADMIN_TOKEN`, and `ADMIN_TOKENS` remain outside `RuntimeConfiguration` because they are credential-bootstrap concerns.

A non-loopback bind must fail closed before listener readiness if no write-capable, header-presentable administrator principal exists. Read-only principals, TLS, or an upstream identity layer do not substitute for Wardnet's own write-auth bootstrap prerequisite. Loopback development mode remains explicitly distinguishable in health/readiness evidence.

### API and domain alignment

HTTP/API types, domain invariants, persistence representation, fixtures, and tests must evolve together. Management mutations are authenticated/authorized upserts where the current domain defines upsert identity. DNSBL values must preserve the `127.0.0.0/8` response-code invariant and RFC 5782-compatible export behavior.

Untrusted request bodies must be bounded before expensive parsing or processing. Rate-limit semantics, event retention, persistence failure behavior, shutdown/flush behavior, and authorization distinctions are testable contracts, not incidental implementation details.

No API response may claim stronger release, security, freshness, or provenance status than the underlying evidence proves.

## Agent Artifact Admission requirements

Wardnet's admission input must be capable of representing an immutable artifact identity, normally a cryptographic digest, plus required evidence references. Policy evaluation produces a deterministic Wardnet decision record with at least artifact identity, policy identity/version, evaluated evidence identities, decision, reason, timestamp, and Wardnet runtime/release identity where available.

Missing mandatory evidence fails according to policy and may not be treated as success because an external owner is unavailable. External execution/sandbox, egress, orchestration, and guardrail details stay outside the admission implementation unless represented by a released contract/evidence receipt.

Canonical foreign owners are:

- `quarantine-sandbox-runtime`: hostile workload isolation, ephemeral execution workspace, resource/syscall/filesystem controls, cleanup/recovery, and artifact-analysis execution profiles.
- `EgressWeave`: outbound destination and transport authorization/control semantics.
- `contextual-orchestrator`: LLM/model/tool orchestration and its released API.
- `appguardrail`: application/agent guardrail implementation and its released evidence contracts.

Wardnet validates and evaluates foreign receipts but does not reimplement these owners.

## LLM boundary

All production LLM use goes through a released `contextual-orchestrator` API. Wardnet owns the security question, evidence supplied, deterministic policy surrounding the call, and treatment of the response. `contextual-orchestrator` owns model selection, provider routing, workflow/reasoning/tool policy, and model-runtime execution.

LLM output is advisory unless a Wardnet policy explicitly defines a bounded use that is independently supported by deterministic evidence. Malformed, unsupported, stale, or unavailable orchestration responses fail closed for any security-critical decision path.

GitHub Actions model workflows must use organization-owned exact-SHA reusable workflows and the approved gateway-token path. Wardnet must not add a local clone of central OpenCode, Strix, Noema, CodeQL, SAST, or security-review logic.

## Performance requirements

The realistic asynchronous Wardnet-owned buyer path has a target of **p95 <= 20 ms** for processing attributable to Wardnet. Benchmarks/load tests must identify the endpoint/path, concurrency, payload shape, warmup, sample size, hardware/runner class, and whether external network calls are excluded or separately reported.

External LLM, threat-intelligence, sandbox, egress, or other service latency must not be hidden inside a local-processing claim. A performance regression must be reproduced with a bounded load/E2E case before optimization; throughput work must not weaken authorization, evidence binding, or fail-closed behavior.

## Persistence and transaction requirements

Protected main currently supports in-memory or JSON-file state and uses write-to-temporary-sibling plus atomic rename for file persistence. Documentation must not state that PostgreSQL is shipped until that stack reaches protected main.

For future database-backed work, application code must not hold explicit database locks or long-lived transactions while performing LLM calls, external I/O, sandbox execution, or long-running computation. Read necessary state, end the database transaction, perform external/expensive work, then open a bounded write transaction that revalidates the required optimistic/concurrency predicate before commit. Cross-service SQL remains forbidden.

## Security requirements

Authentication, authorization, evidence integrity, and network/external-owner trust boundaries are independent controls. A stronger control in one layer does not erase a required control in another.

Security-sensitive comparisons and credential parsing must preserve the protected fail-closed semantics and tests. Security findings are repaired at their causal owner. Central `.github` workflow/runner/verdict defects are handed to the central owner with exact repository/base/head/run/job evidence; Wardnet source is not churned merely to obtain another dispatch.

Threat-feed and adapter acquisition must validate destination/transport expectations without absorbing `EgressWeave` policy ownership. Hostile-workload execution is requested through the sandbox owner's released boundary rather than implemented inside Wardnet.

## UI and accessibility requirements

Material operator UI work must have reusable design/token/component evidence and automated buyer-flow acceptance for normal, loading, empty, error, permission, responsive, keyboard, and accessibility states. The console must remain usable at mobile, intermediate, and desktop widths without clipping or undersized critical targets.

Text layout must tolerate KO/EN/JA/ZH/VI/ES/DE/FR content characteristics. A locale robustness test is not a claim that all translations are shipped. Security/performance/readiness copy must be evidence-backed.

## Test and coverage requirements

At minimum, exact-head repository acceptance retains:

- `cargo fmt --check`;
- `cargo test --locked --workspace`;
- `cargo clippy --locked --workspace --all-targets -- -D warnings`;
- fuzz/property mirrors for untrusted-input surfaces;
- hostile tests for security boundaries and failure paths;
- repository-owned production Rust statement/branch/edge coverage and public rustdoc coverage at the live required threshold, with the commercial-development target of 100%;
- realistic async k6/E2E coverage for buyer-critical paths when performance or deployment behavior is material.

A predecessor SHA, synthetic merge ref when source-head proof is required, queued/cancelled/skipped job, or model-only review is not exact-head GREEN evidence.

## Release and supply-chain requirements

A release-ready protected head requires aligned version metadata and CHANGELOG, deterministic package construction, an SBOM, provenance/attestation, reproducibility evidence, rollback procedure/evidence, a protected exact source head, immutable tag, and immutable GitHub release/package publication. No immutable release may be claimed while the release inventory is empty.

`SBOM` and `provenance` are release artifacts, not prose checkboxes. Their identities must bind to the same artifact/source candidate being promoted. Security/CodeQL/review gates required by live protection remain fail-closed; ordinary failed or queued checks are not emergency-bypass conditions.

## Documentation and architecture synchronization

Changes that alter product behavior, bounded-context ownership, API/evidence contracts, security boundaries, persistence, deployment, operator workflows, or release semantics must update the relevant PRD/TRD/UML/ADR/architecture/security/ops/test/release documentation in the same causal lane or an explicitly owned dependent lane.

`docs/product-technical-gap-baseline.md` has a dedicated writer lane and must not be concurrently edited by this documentation-contract PR. Accepted ADR consolidation remains owned by its existing lane. Context Fabric owns writes to `context-graph-contracts` and `enterprise-architecture-core`; Wardnet inventories those repositories read-only and consumes only immutable releases/contracts when available.

## Standards traceability

The following authoritative references apply together with narrower references already recorded in `docs/security/`, `docs/doctoring/`, ADRs, and feature-specific design records.

- Levine, J., & Vixie, P. (2010). *DNS blacklists and whitelists* (RFC 5782). Internet Engineering Task Force. https://doi.org/10.17487/RFC5782
- National Institute of Standards and Technology. (2020). *Zero trust architecture* (NIST SP 800-207). https://doi.org/10.6028/NIST.SP.800-207
- National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- World Wide Web Consortium. (2023). *Web Content Accessibility Guidelines (WCAG) 2.2*. https://www.w3.org/TR/WCAG22/

If implementation evidence conflicts with prose, fix the prose or implementation causally; do not preserve an outdated requirement merely because it is written here.
