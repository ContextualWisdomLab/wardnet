# Product and technical gap baseline

Snapshot date: 2026-09-05. Re-read live refs, PRs, review threads, exact-head checks, rulesets, security results and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger, not an archive of superseded run state.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane and the Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress integration, SOC Evidence, Runtime Control, Audit-Provenance and Agent Artifact Admission bounded contexts. `quarantine-sandbox-runtime` owns hostile execution isolation and cleanup; `contextual-orchestrator` owns Agent/LLM/provider orchestration; EgressWeave owns reusable outbound HTTP policy; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only: no source copy, cross-service SQL or mutable sibling dependency.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel. `enterprise-architecture-core` is the EA Decision Plane. Both remain read-only from this Wardnet lane while their Context Fabric owner is active. Wardnet findings and artifact verdicts remain Wardnet evidence; architecture may reference validated risk/remediation evidence without copying a raw verdict into authoritative EA truth.

Fresh release inventory remains empty for Wardnet, Context Graph Contracts, EA Core, contextual-orchestrator, quarantine-sandbox-runtime, EgressWeave and appguardrail. Mutable sibling heads are therefore not production/release authority.

## Protected truth and control plane

Protected/default Wardnet truth is `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. Organization ruleset `18156473` remains active on `~DEFAULT_BRANCH`; it retains one generic approving review, review-thread resolution, central required workflows, deletion/non-fast-forward protection and `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval and bot/model-as-human approval are forbidden. `.github#772` owns the narrow governance repair while deterministic workflow/security/coverage/SBOM/provenance/thread/branch-integrity controls remain or strengthen.

Runner/event/model-review materialization remains `.github#712` owner work. Queued/pre-checkout jobs with `runner_id=0`/null and `steps=[]`, startup failures, coverage materialization failures and review requests that never produce a current-head verdict are non-passing. They do not justify no-op source churn, predecessor evidence reuse, gate weakening or routine bypass.

## Agent Artifact Admission — current security lane

PR #129 is Draft/mergeable at exact `3f3da03884527d7ecea18cae9cab38b0bbbb0dbd`, directly ahead of protected `main` (`behind_by=0`). Its current scope is a pre-execution structured package-install admission boundary; it does not fetch, decrypt, install, execute, isolate or activate workloads.

The branch already fail-closes executable/ecosystem confusion, undeclared operands, indirect package sources, alternate registry/index/config/workspace/install roots, lifecycle/trust/integrity bypasses, Cargo source/version/build/overwrite/tracking authority, PyPI target/build variants and dependency expansion, npm-family resolver-selected transitive closure without a reviewed immutable material set, OCI platform/cardinality variants, and Podman TLS/authentication/decryption authority.

Latest hostile TDD closes a pip parser-authority ambiguity:

- RED `032d74e060e778add00a2cc757ce3582c1135232` proves an otherwise approved direct PyPI request carrying both `--require-hashes` and hostile `--no-require-hashes` must not receive `allow`;
- classifier `4c0de8a3445d6b062b69440507cd3c81a3323308` isolates pip/pip3 hash-mode semantics in `pypi_hash_mode.rs`;
- admission repair `bba656c1d776da38a7315d9ec8e6cb5bdfd621d1` blocks the contradictory request with stable `missing_safety_flag` evidence;
- `CHANGELOG.md` and `docs/doctoring/pypi-hash-mode-authority.md` keep the code and current pip primary-source reasoning aligned.

An admission receipt still does not prove downloaded bytes. The downstream execution boundary must independently bind retrieved bytes or equivalent immutable provenance to the reviewed SHA-256 before installation/execution.

Exact-current-head runs are non-passing at runner acquisition: CI `33898982616`, Fuzz `33898982598`, CodeQL PR `33898982736`, SAST Semgrep `33898982757`, Security Scan `33898982652`. CI job `101108311380` is pre-checkout with `steps=[]`, `runner_id=0`, no runner/group identity and exact `head_sha=3f3da038...`. All returned inline review threads are resolved/outdated; no unresolved actionable thread is currently returned. `.github#712` comment `5543903041` owns this exact runner-acquisition specimen. No predecessor check/review conclusion transfers.

No new Shared Kernel schema is required for the pip-local parser repair. `context-graph-contracts#27` owns provider-neutral external capability artifact/evidence/admission/activation grammar; `enterprise-architecture-core#45` owns architecture adoption/risk/provenance projection. Package-manager argv and Wardnet reason codes remain local implementation evidence.

## Other immediate product/security lanes

- **#155 management auth** — exact `e6f05d77858e91c176cff25c4b11e790bc5dcdd1`. Repository CI/Fuzz/Security/SAST are terminal GREEN, but the required OpenCode lane acquired a runner and then failed to materialize a current-head verdict before the central administrative boundary. `.github#712` owns that control-plane defect. Not a bypass case.
- **#77 Rust/deployment hardening** — exact `46fef54c9b5916eb77196fb515a8fabad13a05d1`; current candidate preserves the duplicate-Kubernetes-Deployment hostile regression and exact Rust toolchain pin. Current exact-head evidence must be re-read before any merge claim.
- **#136 outbound policy consumer evidence** — exact `28e5776388b2fc31e1d0567382871a1f599aa3ed`, Draft. Preserve the DNS/deadline/SSRF hostile evidence, but do not integrate its local egress-policy implementation. EgressWeave is the canonical policy owner and must publish an immutable compatible port/ACL before reconstruction.
- **#140 Runtime Configuration** — exact `6b0219dad241cfea9969e7e05c11a9937131b36b`; canonical owner for the immutable non-secret bootstrap snapshot. Feature lanes must adopt this foundation rather than create a competing configuration authority.
- **#159 workflow pressure repair** — exact `8dc374ed597292a9d97a25e7cdea832b5990b6dd`; sole writer for the CI/Fuzz workflow pressure slice, carrying explicit `ubuntu-24.04`, PR-number concurrency and a coalesced fuzz runner. Consumer lanes must not duplicate its workflow paths.
- **#165 trusted client attribution** — exact `3415b748bdf8c6ccd112f215b28cdc116895b861`, Draft/mergeable. It treats forwarding metadata as authority only behind configured trusted proxy CIDRs, keeps malformed chains fail-closed to the direct peer, and depends on #140 plus preservation of #157's still-unique fuzz evidence after workflow ownership settles.
- **#164 release evidence** — exact `1d3f5a4bd618084031f3e722804b7c61303baeb5`, Draft/stacked on #77. It separates PR build/SBOM evidence from protected-main OIDC attestation authority. Do not publish from the feature branch; restack after #77 becomes protected truth and reacquire all exact-head evidence.
- **#127 material UI/a11y** — source-level accessibility changes still require real-browser current-head keyboard/focus/accessibility/responsive/state evidence before merge; source-string tests alone are not WCAG 2.2 AA evidence.
- **#88 contextual-orchestrator boundary** — remains architecture-gated until contextual-orchestrator publishes a compatible immutable API/client/schema contract; retain useful credential grammar/negative tests, discard LiteLLM/provider-routing ownership from the eventual Wardnet consumer.

## Baseline lane integrity

PR #130 remains the sole writer for this file. Fresh ancestry comparison corrects its stale PR-body narrative: branch `codex/main-gap-followup@66b9d1d183dfb733cf9c6283ec307cf9e06aff43` already contains current protected `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128` (`behind_by=0`) and its effective diff against main is this baseline file only. A destructive rebase is neither required nor allowed. This refresh advances that branch linearly and invalidates predecessor checks for the new exact head.

Fresh GitHub search returns 26 open Wardnet PR lanes: `#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #155, #156, #157, #158, #159, #162, #164, #165`. PRs not in this live set are not carried as open merely because an older snapshot listed them.

PR retirement still requires protected merge, explicit user instruction, malicious/no-valid delta, or verified complete successor transfer of every useful code/test/fixture/contract/evidence delta.

## Context Fabric read-only inventory

Context Graph Contracts still reports default/protected `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13`; `main` is the same tip but currently unprotected. Its active inherited ruleset is the same organization ruleset `18156473`; GitHub Release inventory is empty. Open stacked contract/release work remains unreleased, and #27 owns the external-capability artifact/evidence/admission/activation grammar. No mutable CGC head is consumer authority.

EA Core still reports default/protected `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`; `main@ca6889497728e1a3f09d68790a9096576e13a3ff` remains a separate unprotected line. Its active inherited ruleset is `18156473`; GitHub Release inventory is empty. #45 owns portfolio architecture decisions for external capabilities and #20 tracks the protected-main/default transition and integration acceptance. Wardnet does not repair those repositories' source or PR state.

The default/protection mismatch in both owner repositories is an owner-plane operating defect, not a user-choice blocker. Context Fabric/.github owner automation must establish protected-main authority and then rebuild dependent stacks from fresh protected truth without transferring predecessor evidence.

## Buyer-visible gap order

Current product-quality order remains security and authority first: #78 management authentication; #79 released outbound policy/evidence integration; #11 real attack-path CI and #75 deployable public path; #128 Agent Artifact Admission; #80 PostgreSQL authority/tenant isolation then #81 transactional outbox; #82 Keyverse identity/approval and #83 distributed admission; #86 proven Coraza/CRS and Suricata detection; #84 immutable release evidence; #85 telemetry/SLO/incident/restore; #87 final readiness against one immutable protected release identity.

The USD 20 billion quality ambition is a product-quality bar, not a customer contract value or runtime pricing field. PR #162 owns that authority separation; this ledger tracks the resulting buyer-visible quality gaps rather than inventing valuation evidence.

Root `src/lib.rs` remains a modularity pressure point, not evidence by itself for a service split. Prefer a modular monolith until transaction, isolation, scale, deployment or reusable-owner evidence pays for another deployable boundary.

## Standards and release gate

Implementation evidence remains grounded in current authoritative NIST/OWASP/CWE/IETF/OCI/Linux sources and primary/peer-reviewed research where the design depends on them. Citations constrain design but do not prove a control is shipped. Wardnet-owned production code targets 100% statement/branch/edge-case coverage and complete public rustdoc/docstrings with realistic bypass/replay/race/DoS/network/cleanup cases where applicable.

No release is authorized at this snapshot. Release requires one exact integrated protected head with current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence, immutable artifact identity and a verified publication path. Feature-branch artifacts or attestations remain branch evidence only.
