# Wardnet Product Requirements Document

Status: canonical product scope for protected-main behavior and bounded commercial development.

This document describes Wardnet as it is intended to be bought, operated, evaluated, and released without promoting unmerged feature branches to shipped truth. Implementation detail remains subordinate to `docs/architecture.md`, accepted ADRs, the threat model, runbooks, tests, and protected code.

## Product authority

Wardnet owns three related product responsibilities:

1. **Gateway and SOC Control Plane** — route management, request security decisions, operational event/KPI visibility, DNSBL publication, management APIs, and the operator-facing control surface around those capabilities.
2. **Agent Artifact Admission** — Wardnet owns the admission decision, security evidence envelope, policy evaluation, decision/audit record, and the buyer-visible reason that an agent artifact is accepted, denied, or held.
3. **Security evidence and policy** — Wardnet owns the evidence and policy required to justify its gateway, SOC, and admission decisions, including provenance of the decision inputs that Wardnet itself is authoritative for.

Wardnet is not the canonical implementation owner for every security mechanism it consumes. Product boundaries below are mandatory so that a buyer receives one coherent control plane without duplicated enforcement engines.

## Buyer problems

A buyer must be able to operate a security gateway and SOC-facing control plane without guessing which repository owns a decision, which evidence justified it, or whether an automated decision silently bypassed a missing dependency. The product therefore prioritizes fail-closed security boundaries, explicit ownership, deterministic evidence, and deployable operational recovery over feature breadth.

The primary buyer outcomes are:

- a gateway request is routed, monitored, or blocked under an inspectable Wardnet policy decision;
- security operators can inspect events, threat-feed freshness, KPIs, readiness, and support evidence without requiring repository knowledge;
- management writes require a usable write-capable administrator credential whenever the service is bound beyond numeric loopback;
- agent artifacts are admitted only through Wardnet's policy/evidence boundary, while execution isolation and other foreign-owner controls remain external dependencies;
- security and commercial evidence is bound to the evaluated artifact, runtime, configuration, and release rather than inferred from stale predecessor results;
- operational failure is diagnosable and recoverable without disabling a security gate.

## Product requirements

### Gateway and SOC operations

The protected product must keep route, indicator, DNSBL, event, KPI, readiness, and support-evidence surfaces coherent with the same underlying security state. Block/monitor behavior remains route-scoped. DNSBL publication follows the repository's RFC 5782-compatible contract. Threat-intelligence freshness is buyer-visible and stale feeds cannot be represented as fresh evidence.

Wardnet integrates proven security engines and formats where they are authoritative rather than inventing substitutes. OWASP CRS/Coraza, Suricata, STIX/TAXII, MISP, and OpenCTI are integration directions or adapters; their existence in documentation does not by itself mean every engine is embedded in protected main.

### Management security

Numeric loopback operation may run in development mode without a write credential. Any other listener must fail closed before readiness unless Wardnet has a write-capable administrator principal whose secret can actually be represented in the HTTP authentication header contract. Read-only credentials do not satisfy this prerequisite.

Authentication and authorization are distinct product states. Missing/invalid authentication and authenticated-but-insufficient authority must remain distinguishable without leaking expected credentials. Secrets are bootstrap inputs to `CredentialRegistry`; runtime handlers do not treat raw process environment as the credential authority.

### Agent Artifact Admission

Wardnet owns admission, not hostile workload execution. An admission record must be able to bind the artifact identity/hash, policy version or identity, relevant evidence references, decision, reason, time, and the Wardnet release/configuration that produced the decision. A missing required evidence class fails closed according to policy; it is not converted into a positive decision merely because an external service is unavailable.

The following implementation authorities remain external:

- `quarantine-sandbox-runtime` owns hostile-workload isolation and execution profiles, including application-service isolation and artifact-analysis runtime controls.
- `EgressWeave` owns outbound destination/transport authorization and egress control semantics.
- `contextual-orchestrator` owns LLM orchestration, model/tool policy, reasoning/workflow selection, and the released API Wardnet may call for LLM-assisted SOC work.
- `appguardrail` owns its guardrail implementation surface. Wardnet consumes released evidence/contracts where a Wardnet policy requires them; it does not copy that logic into the gateway.

Wardnet may display, validate, bind, and evaluate released evidence from those owners. It must not source-copy their implementation, perform cross-service SQL, or depend on mutable sibling PR heads.

### Evidence and explainability

A buyer-visible security decision must identify enough evidence to reproduce why the decision was made. Evidence must distinguish observed fact, policy evaluation, external-owner receipt, and advisory model output. LLM output is never the sole authority for a security decision that requires deterministic evidence.

All LLM use is through a released `contextual-orchestrator` API contract. Repository or GitHub Actions automation must not introduce a second model-routing implementation in Wardnet.

### Operator UI

The `/admin` surface is an operations console, not a marketing landing page. Material UI work must use reusable design/tokens/components and retain Figma/Storybook evidence for the implemented design system and buyer-critical surfaces. Buyer-critical flows must cover normal, loading, empty, error, permission-denied, responsive, and keyboard/accessibility states.

Text-bearing material UI must remain robust for KO/EN/JA/ZH/VI/ES/DE/FR content expansion and wrapping even when a locale is not yet shipped as a complete translation. UI claims about security, performance, readiness, or release state must come from product evidence, not decorative copy.

## Quality and acceptance

A change is not product-complete because its happy path works. Depending on the affected bounded context, acceptance includes hostile-input tests, permission/authentication cases, deterministic failure-path tests, exact-head CI/security evidence, API/schema alignment, operational recovery, and documentation updates.

Rust remains the preferred implementation language for gateway, DNSBL, high-throughput control-plane, and admission hot paths. Owned production Rust must maintain complete rustdoc/test/edge coverage according to the repository's live coverage contract. The realistic asynchronous buyer path has a performance objective of p95 no greater than 20 ms for Wardnet-owned processing; external network/service latency must be measured and reported separately rather than hidden inside that claim.

## Release and commercial truth

Protected `main` is source truth, but it is not by itself an immutable commercial release. A release-ready candidate requires a version and CHANGELOG entry aligned with the source, reproducible package construction, SBOM, provenance/attestation, rollback evidence, a protected exact head, an immutable tag/release, and all then-live required gates terminal-valid. Stale, predecessor, queued, skipped, cancelled, or synthetic evidence is non-passing.

As of the protected baseline used to create this document (`main@f8260f1e03836039ff9463dd99fa982e4e270c4b`), the GitHub Releases inventory is empty. Product documentation must therefore not describe an immutable Wardnet release as already shipped.

## Architecture and contract boundaries

Wardnet consumes foreign capabilities only through released contracts. `context-graph-contracts` and `enterprise-architecture-core` are architecture/context authorities owned by the Context Fabric workstream; Wardnet inventories them read-only while that writer owns them. With no immutable release available from either repository at this baseline, Wardnet does not bind protected product behavior to their mutable default branches.

The technical requirements are canonicalized in `docs/architecture/TRD.md`; the component/dependency view is `docs/architecture/wardnet-control-plane.puml`. Accepted decisions remain in `docs/adr/`, and `docs/product-technical-gap-baseline.md` remains the separate technical-gap ledger when its owner lane lands.

## Standards and research traceability

These references constrain the product requirements together with the repository's more specific doctoring/security citations.

- Levine, J., & Vixie, P. (2010). *DNS blacklists and whitelists* (RFC 5782). Internet Engineering Task Force. https://doi.org/10.17487/RFC5782
- National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- World Wide Web Consortium. (2023). *Web Content Accessibility Guidelines (WCAG) 2.2*. https://www.w3.org/TR/WCAG22/

Where a publication cannot legally be redistributed in this repository, retain citation and stable locator rather than copying the PDF. Standards or papers committed as artifacts must have a redistribution basis recorded in the owning documentation/PR.
