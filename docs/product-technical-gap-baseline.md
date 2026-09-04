# Product and technical gap baseline

Snapshot date: 2026-09-05. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger, not an archive of predecessor evidence.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane and the Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress integration, SOC Evidence, Runtime Control, Audit-Provenance and Agent Artifact Admission bounded contexts. `quarantine-sandbox-runtime` owns hostile execution isolation/cleanup; `contextual-orchestrator` owns Agent/LLM/provider orchestration; EgressWeave owns reusable outbound HTTP destination/address policy; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only: no source copy, cross-service SQL or mutable sibling production dependency.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Both remain read-only from this Wardnet writer while their Context Fabric owner is active. Wardnet findings/verdicts remain Wardnet evidence; EA may retain verified evidence references for technology risk/remediation/initiative context but must not copy raw security verdicts into authoritative architecture truth.

Fresh GitHub release inventories are empty for Wardnet, Context Graph Contracts, EA Core, `contextual-orchestrator`, `quarantine-sandbox-runtime`, EgressWeave and `appguardrail`. No mutable sibling head is production/release authority.

## Protected truth and control plane

Protected/default Wardnet truth is now `main@5829a0f08d78de464dd24393ce5d0f25fba9d126`, produced by protected merge #159. #159 is no longer an open prerequisite: its CI/Fuzz/Scorecard pressure repair, explicit hosted-runner contract, `AGENTS.md` ownership guidance and workflow queue/runner regressions are protected truth and must be adopted by consumer lanes rather than copied or bypassed.

Organization ruleset `18156473` remains active on `~DEFAULT_BRANCH`; live policy still requires one generic approving review with no named required reviewer, resolves review threads, requires central OpenCode/review-scheduler/Security/Strix/Semgrep/Noema/CodeQL workflows, and blocks deletion/non-fast-forward while exposing `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval and bot/model-as-human approval are forbidden. `.github#772` and its live owner-plane reconciliation lane own replacement of only the structurally impossible approval count/routine bypass while deterministic security/coverage/SBOM/provenance/thread/branch-integrity controls remain or strengthen.

Runner/event/model-review acquisition/materialization remains `.github#712` owner work. Queued/pre-checkout jobs, `runner_id=0`, `steps=[]`, startup failure, coverage materialization failure or a started model-review request that never produces a current-head verdict are non-passing. They do not justify leaf no-op churn, predecessor evidence reuse, gate weakening or routine bypass.

## Agent Artifact Admission

PR #129 remains Draft/mergeable and is now non-destructively integrated onto protected #159 truth at exact `f6889079ce49b6f08865180dd6a1ffd8145a8192`; fresh ancestry reports `behind_by=0`. Its effective feature delta remains 67 files and does not duplicate the protected workflow-owner paths.

The bounded context is pre-execution structured installer security admission only. It binds reviewed workspace manifest/artifact identity, exact ecosystem/name/version/registry/owner/SHA-256, executable family, declared operands, policy revision and bounded provenance; it does not fetch, decrypt, install, execute, isolate, activate or route workloads. An `allow` receipt is admission authority, not downloaded-byte proof or runtime activation.

Current hostile TDD includes the PyPI hash-mode contradiction: RED `032d74e060e778add00a2cc757ce3582c1135232` proves `--require-hashes` plus hostile `--no-require-hashes` must not remain admissible; classifier `4c0de8a3445d6b062b69440507cd3c81a3323308` isolates pip/pip3 hash-mode authority; causal repair `bba656c1d776da38a7315d9ec8e6cb5bdfd621d1` fails the contradictory request closed. Earlier package-manager, Cargo, npm-family, OCI-cardinality/platform and Podman trust/auth/decryption hostile contracts remain preserved.

Fresh current-head execution is non-passing/queued: CI `33904242427`, Fuzz `33904242501`, Security Scan `33904242429`, SAST Semgrep `33904242491`, CodeQL PR `33904242556`. No predecessor check/review conclusion transfers after the protected-main integration.

`context-graph-contracts#27` owns the future provider-neutral external-capability artifact/evidence/admission/activation grammar. The owner handoff requires security-artifact admission evidence to remain distinct from Noema governed activation/orchestration, with semantic request/artifact/policy/evidence identity and hostile fixtures preventing either authority from substituting for the other. Package-manager argv/parser semantics and Wardnet reason codes remain Wardnet-local. `enterprise-architecture-core#45` owns architecture adoption/risk/provenance projection and must retain evidence references without making Wardnet findings authoritative EA facts.

## Immediate product/security lanes

- **#155 management auth** — exact `f74ff25a321dfb1d7109719e2a1fc77e47dc4898`, Ready/mergeable, non-destructively integrated onto current protected main with `behind_by=0`. Its 13-file delta fails closed before readiness when a non-loopback listener lacks a write-capable administrator credential. Fresh current-head CI `33904633002`, Fuzz `33904632999`, Security Scan `33904633208`, SAST `33904633082`, CodeQL PR `33904632978` are queued. The predecessor OpenCode run that acquired a runner but timed out waiting for a verdict is RCA evidence only.
- **#134 support-bundle regression** — exact `4db75680dcfa03d0592c62f08278fdef09c33694`, Ready/mergeable, `behind_by=0`; effective delta is 38 test lines in `src/lib.rs` binding support-bundle counts and administrator-secret redaction. Predecessor GREEN/cancelled review evidence does not transfer.
- **#140 Runtime Configuration** — canonical supporting-boundary owner for the immutable non-secret bootstrap snapshot. Feature lanes must adopt it rather than create a competing process-environment authority; it still requires fresh integration onto protected #159 truth before merge.
- **#157/#165 trusted client attribution** — #165 is the current production feature owner; #157 remains a preservation lane until all still-valid trusted-proxy fuzz/corpus/invariant evidence is demonstrably transferred after the workflow and Runtime Configuration foundations are protected. Do not close #157 merely because #165 exists.
- **#136 outbound policy** — preservation Draft only. Keep Wardnet-owned purpose/call-site/deadline/evidence hostile tests, but do not integrate the local destination/DNS/redirect/proxy/TLS policy implementation. EgressWeave must first publish an immutable Rust-consumable provider-neutral authorization/evidence boundary; current EgressWeave release inventory is empty.
- **#88 contextual-orchestrator consumer** — architecture-gated. Preserve unique fail-closed credential/header/streaming negative evidence, remove LiteLLM/provider-routing/virtual-key ownership when reconstructing, and consume only a released CO API/client/schema/Agent boundary. Current CO release inventory is empty.
- **#164 release evidence** — Draft stacked on #77. It separates PR build/SBOM evidence from protected-main OIDC attestation authority. Do not publish from a feature branch; after the Rust/toolchain parent is protected truth, restack on fresh main and reacquire exact-head package/SBOM/provenance/reproducibility evidence.
- **#127 material UI/a11y** — source accessibility changes still require current-head real-browser keyboard/focus/accessibility/responsive/normal-loading-empty-error-permission evidence; source-string tests alone are not WCAG 2.2 AA evidence.

## Open PR inventory and single-writer discipline

Fresh search returns 25 open Wardnet PR lanes: `#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #155, #156, #157, #158, #162, #164, #165`. #159 is excluded because it is now protected-main truth.

PR #130 remains the sole writer for this file. It has adopted protected #159 non-destructively; this refresh is the only concurrent edit to `docs/product-technical-gap-baseline.md`. Other lanes hand evidence into #130 rather than editing this path. PR retirement still requires protected merge, explicit user instruction, malicious/no-valid delta, or verified complete successor transfer of every useful code/test/fixture/contract/evidence delta.

## Context Fabric read-only inventory

Context Graph Contracts still reports default/protected `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13`; `main` points to the same tip but is unprotected. Ruleset `18156473` follows `~DEFAULT_BRANCH`, so it currently governs `develop`. GitHub Releases are empty. The open dependency stack remains Draft/unreleased; #27 owns external-capability artifact/evidence/admission/activation semantics. This branch-topology mismatch is Context Fabric/.github owner-plane work, not a Wardnet or user decision.

EA Core still reports default/protected `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`; active product-line `main@ca6889497728e1a3f09d68790a9096576e13a3ff` remains outside default-branch authority. The same organization ruleset follows `develop`; GitHub Releases are empty. #45 owns external-capability portfolio/adoption decisions; #40 is a Draft Context Fabric projection consumer and currently reports missing exact-head workflow materialization. Wardnet does not mutate EA source/PR state.

## Buyer-visible gap order

Current order remains authority/security before breadth: protected management authentication (#78/#155); immutable outbound policy/evidence integration (#79/#136 + EgressWeave owner release); real attack-path CI and deployable public path (#11/#75); Agent Artifact Admission (#128/#129); PostgreSQL authority/tenant isolation (#80) then transactional outbox (#81); Keyverse identity/approval (#82) and distributed admission/trusted attribution (#83); proven Coraza/CRS and Suricata detection (#86); immutable release evidence (#84); telemetry/SLO/incident/restore (#85); final readiness against one immutable protected release identity (#87).

The USD 20 billion ambition is a product-quality bar, not a customer contract value, billing field or runtime pricing authority. #162 owns that documentation separation. Root `src/lib.rs` remains a modularity pressure point, not evidence by itself for a deployable service split; prefer a modular monolith until transaction/isolation/scale/deployment/reusable-owner evidence pays for another boundary.

## Standards and release gate

Security and runtime decisions remain traceable to current authoritative NIST/OWASP/CWE/IETF/OCI/Linux sources and primary/peer-reviewed research where the implementation depends on them. Citation is design evidence, not proof that a control is shipped. Wardnet-owned production targets 100% statement/branch/edge-case coverage and complete public rustdoc/docstrings, with realistic bypass/replay/race/DoS/network/cleanup tests where applicable.

No Wardnet release is authorized at this snapshot. Release requires one exact integrated protected head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence, immutable artifact/source identity and a verified publication path. Feature-branch artifacts or attestations remain candidate evidence only.
