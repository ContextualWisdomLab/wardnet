# Product and technical gap baseline

Snapshot date: 2026-09-10. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. The branch is protected and repository-local `rust` remains a required status context. Wardnet has no GitHub Release, so protected source truth is not yet an immutable release identity.

Organization ruleset `18156473` remains active on `~DEFAULT_BRANCH`. It requires one generic approving review while declaring no required reviewer/team, code-owner review or last-push approval. Required review-thread resolution, central OpenCode/Noema/Strix/security/SAST/CodeQL workflows, deletion protection and non-fast-forward protection remain active. The rule exposes organization-admin bypass, but routine bypass is not an acceptance path. `.github#772` remains the canonical solo-maintainer governance defect; self-approval and model/bot-as-human approval remain forbidden.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication remains `.github#1929` or its live successor. Wardnet does not add leaf provider/model/group fallbacks, duplicate central workflows, synthesize statuses, or source-churn a clean candidate to repair those planes.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed its own current SHA as merge evidence. PR metadata, current-head workflows, review/thread state and protected-base compatibility must be re-read after each refresh.

## Context Fabric and EA compatibility

Fresh read-only owner inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both repositories still have empty GitHub Release inventories. Wardnet does not write either repository while the Context Fabric owner is active. Their intended protected-main/default convergence remains central owner work; mutable heads are compatibility evidence only.

Current CGC contract work and EA projection work remain Draft/unreleased. No mutable CGC/EA head, Context Assertion proposal, architecture projection, or self-declared release identity is Wardnet production authority. Package-manager argv, Wardnet-local reason codes, findings and verdicts remain local security truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `d9bad9580ca84ef2036619ba6441fcaaa8edd168`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Protected truth and later security children were adopted/integrated non-destructively through ordinary expected-head merges; no force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

The audit-evidence sequence is complete through issue #260 / PR #261. Earlier #256/#257 verifies effective owner-only permissions on the already-open descriptor. #258/#259 rejects multiply-linked audit files through same-descriptor `st_nlink == 1`. #260/#261 closes the Linux parent-directory symlink traversal gap through descriptor-pinned parent traversal plus final-child open, while retaining regular-file, owner-only, single-link, append, nonblocking, flush/sync and non-Linux fail-closed invariants. Exact successor verification completed before #260 closed.

The newest security child is issue #262 / PR #263 for pip TLS client-certificate authority. Test-only exact `9e16a0e5e6cb5aacba019ab49288e4f17c55b64f` kept production behavior unchanged and produced hosted semantic RED in CI `34478638913` / rust job `102875538906`: checkout/toolchain/format succeeded and an otherwise-approved `pip`/`pip3 install` carrying `--client-cert=/tmp/attacker-client.pem` was incorrectly admitted (`Allow` rather than `Block`). The minimum repair keeps authority in the existing pip alternate-trust-root classifier by adding only `--client-cert` to its forbidden trust-root flags. The retained contract covers both attached `--client-cert=/tmp/...` and separate `--client-cert /tmp/...` forms for `pip` and `pip3`, requiring `ReasonCode::AlternateTrustRoot` rather than relying on incidental positional-operand rejection.

Exact child `8c6fd25499a4add753fcd55531e51f51a43e546c` had CI `34481019959` and Fuzz `34481019957` terminal SUCCESS, no submitted reviews, no inline review threads, merge base exactly canonical parent `a43ebd2f35a63983fde0020a4ee56220329fd7c7`, and exactly two effective paths: one production line in `src/policy.rs` plus the hostile contract. PR #263 then merged normally with expected-head protection into #129 as `d9bad9580ca84ef2036619ba6441fcaaa8edd168`. Fresh parent carry-forward comparison from `a43ebd2...` is ahead 7 / behind 0 and still exactly those two effective paths.

On unchanged exact #129 head `d9bad958...`, CI `34481778107`, Fuzz `34481777946`, Security Scan `34481777928`, and SAST Semgrep `34481777965` are terminal SUCCESS. CodeQL PR `34481778401` is terminal FAILURE only at the central delegated terminal-verdict settlement boundary: detect job `102886092856` succeeded; compatibility job `102886209005` successfully read the exact-head dispatch state, then failed closed because the authenticated terminal verdict was still `pending`; exact-head dispatch job `102887083440` subsequently succeeded. This is a `.github#1929` control-plane specimen, not a Wardnet source failure, and does not justify source churn or synthetic status. Fresh submitted reviews remain COMMENTED only; the sole inline thread is resolved/outdated, so unresolved valid review-thread count is zero.

Issue #262 remains open until this security delta reaches protected main; child-to-feature integration alone is not issue completion. Issue #128 likewise remains open until the complete Agent Artifact Admission lineage reaches protected main and foreign-owner/release acceptance is satisfied. Ambient package-manager environment/config authority remains `quarantine-sandbox-runtime` work; EgressWeave remains executable transport-authorization authority.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. The evidence line remains ordered through business authorization, freshness, source/evidence health, exact generation membership, lifecycle validity, producer-version/tombstone cursor, atomic source replacement and ABA replay resistance. Durable production authority remains the PostgreSQL #80/#192 lineage because bounded current-only lifecycle memory cannot prove historical opaque generation uniqueness.

Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns destination/reputation verdict into transport authority.

## PostgreSQL production-state prerequisite stack

The canonical durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness and no automatic replay after database work begins.

Late-stack evidence remains useful but unreleased: #236 owns typed unknown-COMMIT outcome; #241 executes destructive PostgreSQL 18.4 base-backup/WAL/PITR recovery; #242 proves real divergent-writer serialization and byte-identical replay; #244 proves bounded half-open protocol failover and 200 unexcluded real PostgreSQL preflight+probe samples at p95 ≤20 ms while retaining two physical runtime sessions. `StateAuthority::Postgres` remains disabled.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps are dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 current exact head is `2ca5a8e55185730abec34886279b5aa576be5658`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. A contents/tree materialization attempt to apply the already-proven one-line responsive repair twice produced incomplete `src/lib.rs` trees; each was immediately repaired by ordinary fast-forward commits that restored the complete prior source. No force update or destructive rebase was used, and the current source tree again contains the complete admin console with the original non-wrapping header behavior.

On unchanged exact `2ca5a8e...`, hosted CI `34486350074` passed checkout, toolchain, formatting and all 121 library tests, then its real Chrome/ChromeDriver test again failed only at `tests/admin_console_browser.rs:240` with `console must not clip or horizontally overflow at 375px`. Fuzz `34486350227`, Security Scan `34486350160`, and SAST Semgrep `34486350184` are terminal SUCCESS. CodeQL PR `34486350097` is non-passing central delegated-settlement evidence and is not promoted as product GREEN.

Root cause remains product CSS: `header.app` is a non-wrapping flex row with 24 px side padding while the heading and toolbar/admin-token field cannot fit the resulting 327 px content width. Minimum repair remains the one-behavior production change `flex-wrap:wrap` on `header.app`, followed by unchanged 375/768/1440 browser acceptance. Hiding overflow, zooming, widening the viewport, injecting test-only CSS, or using another incomplete full-file materialization is not acceptance. UI Delivery Gate remains **FAIL** until an exact complete source tree carries the one-line repair and the shipped-route browser test is GREEN.

## Process lifecycle and graceful shutdown

Draft #245 remains the process-lifecycle candidate. Its test-first Unix signal lineage established a semantic SIGINT RED and the minimum production repair registers SIGTERM/SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`; no second lifecycle authority was added. Repository CI/Fuzz/Security/SAST are terminal GREEN on its current recorded head, while CodeQL remains central delegated-settlement work. Draft GREEN is not protected lifecycle truth.

## Release and operational buyer gaps

Wardnet is **not release-ready**. No immutable Wardnet GitHub Release exists. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Continue repair-first. Treat canonical #129 exact `d9bad958...` as the only Agent Artifact Admission successor after the ordinary #263 integration; its Wardnet-owned CI/Fuzz/Security/SAST and review-thread evidence is current GREEN, while CodeQL terminal-verdict settlement remains `.github#1929` owner work. Keep #262/#128 open until protected integration. Advance central governance and runner/control-plane failures through `.github#772`, `.github#1929` and `.github#712` with exact consumer evidence rather than leaf workarounds. Repair #127's proven 375 px header overflow on its own branch with the single header-wrap behavior change using a write path that preserves the complete source blob, then reacquire 375/768/1440 real-browser evidence. Continue #244/#243 with explicit coverage/rustdoc and production storage/recovery/release invariants. Integrate dependencies only through ordinary protected governance, then create and verify the immutable release without force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.
