# ADR-0012: Agent Artifact Admission is a separate Wardnet bounded context

- Status: Accepted for PR #129
- Date: 2026-09-01
- Decision owner: Wardnet

## Context

Wardnet already owns network and application admission controls. AI coding agents add a different trust transition: untrusted text can be transformed into a package-install or code-execution request. Treating that concern as another handler inside the existing gateway would mix traffic enforcement, package identity, execution authority, and audit semantics in one module and would make future broker integrations depend on the gateway deployment.

The current implementation has a standalone Rust crate, `wardnet-agent-artifact-admission`, with a deterministic policy evaluator, strict install-intent contract, append-only audit evidence, loopback-only HTTP delivery, and immutable process configuration. This ADR records the domain boundary and the dependency direction that subsequent work must preserve.

## Decision

Agent Artifact Admission is a distinct Wardnet bounded context inside the core Security Admission subdomain. Its ubiquitous language and context relationships are defined in `docs/architecture/agent-artifact-admission-context-map.md`.

The bounded context owns:

- `InstallIntent`, `InstructionSource`, `ApprovedManifest`, `ApprovedArtifact`, `AdmissionPolicy`, `AdmissionDecision`, reason codes, and their invariants;
- deterministic policy evaluation for one install intent;
- the canonical minimized audit fact for an authenticated admission attempt;
- the loopback-only v0.1 admission API and process composition required to expose that decision boundary.

It does not own:

- package execution or sandboxing;
- registry discovery, publisher inference, or dependency resolution;
- Sigstore, TUF, or SLSA provider schemas;
- OpenCode/Codex/Claude/Hermes orchestration policy;
- SIEM/OCSF/OTLP projection formats;
- organization-wide credential or workflow authority.

Those models cross the boundary only through explicit adapters or Anti-Corruption Layers. A provider DTO must not become an admission domain entity.

## Dependency direction

The domain kernel (`admission.rs`, `policy.rs`) must remain free of Axum, Tokio, filesystem, listener, provider SDK, and deployment dependencies. HTTP/process/configuration concerns depend inward on the domain contracts. Concrete audit storage may implement the audit port but must not be imported by the policy evaluator.

The current crate is a modular deployment boundary, not a mandate to create another microservice for every protocol. A split requires an independently evolving responsibility, persistence authority, policy lifecycle, reuse boundary, or deployment cadence. Additional HTTP, SIEM, Sigstore, or registry adapters alone do not justify a new service.

`crates/agent-artifact-admission/tests/ddd_architecture_contract.rs` enforces the initial dependency rules. Architecture changes must update this ADR or supersede it and change the fitness tests in the same PR.

## Consequences

The main Wardnet gateway cannot reach into Agent Artifact Admission internals. Execution brokers use the published admission API or a future package contract. Agent Artifact Admission cannot directly query another CWL service's application tables. Cross-product integration uses versioned API, package, or event contracts.

The bounded context remains independently deployable and can be embedded later without losing its domain boundary. The immutable-policy v0.1 avoids a runtime policy aggregate and reduces the transaction to `evaluate -> build audit fact -> durably append -> return receipt`.

The existing `audit.rs` currently contains both the audit contract and a small file-backed adapter. This is tolerated only while there is one local adapter and the domain evaluator does not depend on its concrete type. A second persistence backend is the trigger to split the port from concrete adapters rather than growing a generic infrastructure module.

## Security and supply-chain basis

The admission service complements, rather than replaces, software-supply-chain provenance. Exact digest and reviewed-manifest binding are local admission facts; registry and build provenance remain external authorities.

Current primary guidance checked for this decision:

- SLSA v1.2 is the latest released SLSA specification and adds the Source Track; its source and provenance controls remain external evidence consumed through adapters. https://slsa.dev/blog/2025/11/announce-slsa-v1.2
- The Update Framework specification currently lists v1.0.33 as latest; future signed policy/artifact metadata integration must translate TUF metadata through an adapter. https://theupdateframework.io/spec/
- NIST SP 800-218, SSDF Version 1.1, remains the current final SSDF publication; SP 800-218 Rev. 1 / SSDF 1.2 is still an Initial Public Draft and is not treated as binding. https://csrc.nist.gov/pubs/sp/800/218/final
- NIST SP 800-218A is the final generative-AI SSDF community profile and supports treating AI-produced software-development instructions as inputs that require secure development controls rather than execution authority. https://csrc.nist.gov/pubs/sp/800/218/a/final

## Alternatives considered

**Add routes to the main gateway module.** Rejected because it couples package-execution admission to traffic-routing deployment and expands the gateway's responsibility.

**Create a generic `security-service` or `common` crate.** Rejected because the name hides responsibility and invites unrelated controls into a shared dumping ground.

**Let execution brokers implement their own checks.** Rejected because policy and evidence would diverge between OpenCode, Codex, Claude, Hermes, CI, and MCP callers.

**Make provenance providers domain dependencies.** Rejected because it imports foreign schemas and lifecycle decisions into the admission model; provider evidence belongs behind explicit translation boundaries.
