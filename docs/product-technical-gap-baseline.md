# Product and technical gap baseline

Snapshot date: 2026-09-10. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts stay in the owning PR and issue histories. Draft/feature heads below are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. The branch is protected and repository-local `rust` remains a required status context. Wardnet has no GitHub Release, so protected source truth is not yet an immutable release identity.

Organization ruleset `18156473` remains active on `~DEFAULT_BRANCH`. It requires one generic approving review while declaring no required reviewer/team, code-owner review or last-push approval. Required review-thread resolution, centrally required OpenCode/Noema/Strix/security/SAST/CodeQL workflows, deletion protection and non-fast-forward protection remain active. The rule exposes organization-admin bypass, but routine bypass is not an acceptance path. `.github#772` remains the canonical solo-maintainer governance defect: self-approval stays forbidden and model/bot reviews are not human approval.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict ordering/publication remains `.github#1929` or its live successor. OpenCode Ready-state exact-head review materialization remains `.github#2045` owner work. Wardnet does not add leaf provider/model/group fallbacks, duplicate central workflows, synthesize statuses, or source-churn a clean candidate to repair those planes.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed its own current SHA as merge evidence. The PR metadata, current-head workflows, review/thread state and protected-base compatibility must be re-read after each refresh.

## Context Fabric and EA compatibility

Fresh read-only owner inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Wardnet does not write either repository while the Context Fabric owner is active. Their default/integration-branch convergence remains central owner work under `.github#1137`; mutable heads are compatibility evidence only.

No released CGC/EA identity is treated as Wardnet production authority. Shared artifact/activation objects, Context Assertions and architecture projection remain canonical-owner responsibilities. Wardnet package-manager argv, local reason codes, security findings and verdicts are not copied into authoritative EA truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `d113b4c5c1f402b15eae1e672ea6a058ba7289c2`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Protected-main truth was adopted non-destructively earlier and later security children have been integrated by ordinary expected-head merges. No force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact package ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

The latest completed Wardnet-owned security repairs are:

- **#256 / #257 — existing audit-file permissions.** Hosted hostile evidence established that `OpenOptions::mode(0o600)` constrains file creation only and does not tighten an already-existing inode. The causal repair validates the effective Unix permission bits from the same opened descriptor and rejects group/other access (`mode & 0o077 != 0`) without silently `chmod`ing deployment storage or adding a pathname preflight. Exact child `378e24075aa316c9058c8b6df3fcd7d5c5ff4fc5` had terminal CI/Fuzz and zero review threads. Ordinary expected-head integration produced canonical `ffbcd6298c0bfdf45f72130136694cb2be0b420a`; on that exact successor, CI `34458292113`, Fuzz `34458292193`, Security Scan `34458292203`, and SAST Semgrep `34458292146` were terminal SUCCESS. Issue #256 is closed only after verified successor carry-forward.
- **#258 / #259 — hard-linked audit storage.** Test-only exact `b992cdb0e3cc42cd48427072373010fcde798a78`, with production source byte-identical to parent `ffbcd629...`, created an owner-only target file and a configured audit pathname as a hard link to the same inode. Hosted CI `34458676152`, rust job `102811040900`, passed formatting and all preceding workspace/audit controls, then failed only `file_sink_rejects_hard_linked_owner_only_regular_file`: the existing sink accepted the multiply-linked inode. Minimum repair `8ec36c7034f8eff37f025aab9b2e9cb21cde7286` adds same-descriptor `metadata.nlink() == 1` beside the existing regular-file and owner-only-mode checks. It does not unlink, replace, chmod, add pathname preflight, or weaken `O_NOFOLLOW | O_NONBLOCK | O_APPEND`. Doctoring/TRACEABILITY at child exact `fb56c93d52c861ca05e62d7f73aa99176ee9fdf1` relates the invariant to CWE-62, NIST SP 800-53 Rev. 5 AU-9 and Linux inode/link semantics without claiming NIST prescribes the mechanism. Exact repaired child CI `34458968448` and Fuzz `34458968506` were terminal SUCCESS with zero reviews/threads. Ordinary expected-head integration produced current canonical `d113b4c5c1f402b15eae1e672ea6a058ba7289c2`.

Earlier completed package-manager and local-file security children (#247/#249/#251/#253/#255 and their owning issues) remain retained by ancestry. Their historical RED/GREEN receipts stay in the owning PR/issue histories rather than being reused as current-head workflow evidence.

The current #129 head movement invalidates every predecessor workflow verdict as merge evidence. Fresh exact-current runs on `d113b4c5...` have materialized: CI `34459643118`, Fuzz `34459643221`, Security Scan `34459643129`, SAST Semgrep `34459643345`, and CodeQL PR `34459643153`. At the last ledger refresh, CI/Security/SAST were terminal SUCCESS while Fuzz and CodeQL PR were still in progress. None of the non-terminal lanes is promoted to GREEN. Fresh #129 inline review inventory has one historical resolved/outdated thread and therefore zero unresolved valid threads; submitted reviews are COMMENTED records, not independent approval.

The immediately preceding exact `ffbcd629...` supplies a fresh central CodeQL control-plane specimen: hosted language detection succeeded; compatibility successfully read the current-head dispatch verdict and then failed only at `Release runner or enforce current-head CodeQL verdict`; the later exact-head dispatch job succeeded. That evidence was handed to `.github#1929`. It is not a Wardnet source failure and does not justify a synthetic status or no-op source churn.

Issue #258 remains open until current canonical successor `d113b4c5...` has terminal exact-head CI/Fuzz, zero unresolved valid review findings and verified carry-forward of the hostile test/fix/evidence. Issue #128 remains open until the complete Agent Artifact Admission lineage reaches protected main and its foreign-owner/release acceptance is satisfied.

Wardnet argv admission cannot substitute for runtime environment isolation. Ambient package-manager environment/config authority remains `quarantine-sandbox-runtime` work; downstream execution must clear/bind it before payload release rather than making Wardnet duplicate quarantine policy. EgressWeave remains the executable transport-authorization owner.

## Outbound destination reputation

#173 remains Proposed architecture for the Wardnet-owned reputation engine. #175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent evidence line remains ordered through business authorization, freshness, source/evidence health, exact generation membership, lifecycle validity, producer-version/tombstone cursor, atomic source replacement and ABA replay resistance. The durable production-authority path remains the PostgreSQL #80/#192 lineage because bounded current-only lifecycle memory cannot prove historical opaque generation uniqueness.

Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns its destination/reputation verdict into transport authority.

## PostgreSQL production-state prerequisite stack

The canonical durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Acceptance/RED lanes are carried by verified successors rather than inserted as duplicate ancestry nodes. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The stack establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, migration rollback/reapply and startup serialization, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, fixed-pool fail-closed behavior, bounded per-slot replenishment and bounded readiness without replaying started database work.

Late-stack evidence remains materially useful but is not protected truth:

- #236 exact `e1131c2ce1078322b48caa87b2088b1866b08626` has terminal CI/Fuzz and owns typed `CommitOutcomeUnknown` for transport loss while awaiting COMMIT; automatic replay is forbidden.
- #241 exact `992d9c366c47515a121b786197c872db81957dcc` has terminal CI on a destructive PostgreSQL 18.4 base-backup/WAL/PITR recovery drill and unsafe-role guard. This is controlled fixture evidence, not production RPO/RTO/storage/encryption/IAM authority.
- #242 exact `641d7cd4b12d174015801ce4aee8f29803f239ad` has terminal CI on real PostgreSQL 18.4 divergent-writer serialization and byte-identical duplicate behavior without a global writer lock.
- #244 exact `91cab184c95984d5ffdb6b2a4eb8f8920fbae8f5` has terminal CI `34402494574` and Fuzz `34402494583`. Its real protocol-blackhole fixture proves bounded selective failover/all-stream fail-closed behavior without replay/reconnect storms, and 200 unexcluded real PostgreSQL preflight+probe samples meet p95 ≤20 ms while retaining the original two physical runtime sessions.

#244 introduces the canonical `docs/TEST_STRATEGY.md`; issue #243 remains open because `cargo test` alone is not evidence of 100% owned-production statement/branch/edge/rustdoc coverage. `StateAuthority::Postgres` remains disabled for production. Remaining durable-state gaps are dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 remains exact `ff47a9b6cc4cf978c0d3cf81c0556cc57c6e59cf`. Its real browser harness launches the shipped Wardnet binary on loopback and drives hosted Chrome. Current diagnostic evidence passes delayed loading, normal API state, permission denial, keyboard skip-link transfer, computed accessible name/description and atomic polite KPI semantics. It still fails the real 375 px horizontal-overflow assertion.

The causal production defect is unchanged: `header.app` is a non-wrapping flex row while 375 px leaves only 327 px after outer horizontal padding and the long heading plus toolbar/admin-token input cannot fit. The minimum source repair is outer header flex wrapping followed by unchanged 375/768/1440 real-browser acceptance. Hiding overflow, zooming, widening the test viewport or injecting test-only CSS is not acceptance. UI Delivery Gate remains **FAIL** until that exact-current browser suite is GREEN. Existing Fuzz/Security/SAST success and resolved historical CodeQL browser-harness findings do not substitute for responsive product behavior.

## Process lifecycle and graceful shutdown

Draft #245 remains exact `d953c1d94ebbde87a0f7c4121a8088e0b9fa14f2`, based on protected main. Its test-first Unix signal lineage established a real semantic RED for SIGINT terminating at the OS default disposition while SIGTERM passed. The minimum production repair registers SIGTERM and SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`; Windows behavior is unchanged and no second lifecycle authority is introduced.

On current #245 exact head, CI `34423929129`, Fuzz `34423929826`, Security Scan `34423929246`, and SAST Semgrep `34423929010` are terminal SUCCESS. Required CodeQL remains non-passing at the same delegated terminal-verdict settlement boundary and is handed to `.github#1929`. Draft/feature GREEN is not protected lifecycle truth.

## Release and operational buyer gaps

Wardnet is **not release-ready**. No immutable Wardnet GitHub Release exists. Release-evidence work remains feature/Draft evidence and cannot substitute for protected-main integration. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated only through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/CO/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet continues to fail closed rather than duplicating those canonical owners.

## Execution order

Continue repair-first rather than report-first. Allow exact `d113b4c5...` Agent Artifact Admission checks to settle without source churn; if CI/Fuzz remain GREEN and carry-forward is exact, close #258 only on that verified successor while #128 stays open for protected integration. Advance central CodeQL/OpenCode/governance failures through `.github#1929`, `.github#2045`, `.github#772` and `.github#712` with exact consumer evidence rather than leaf workarounds. Repair #127's 375 px header overflow on its own exact branch and reacquire 375/768/1440 real-browser evidence. Continue #244/#243 with explicit coverage/rustdoc and production storage/recovery/release invariants. Integrate dependencies only through ordinary protected governance, then create and verify the immutable release without force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.
