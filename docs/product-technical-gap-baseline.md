# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. The branch is protected and repository-local `rust` remains a required status context. Fresh release inventory on 2026-09-11 is empty, so protected source truth is not yet an immutable Wardnet release identity.

Organization ruleset `18156473` remains the active default-branch governance contract. Its generic one-approval requirement remains structurally incompatible with the declared solo-maintainer model while no eligible independent reviewer/team exists; `.github#772` is the canonical governance repair path. Self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates are not to be weakened and routine administrator bypass is not an acceptance path.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication and wake ordering remains `.github#1929` or its live successor. Wardnet does not add leaf provider/model/group fallbacks, duplicate central workflows, synthesize statuses, or source-churn a clean candidate to repair those planes.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed its own current SHA as merge evidence. PR metadata, current-head workflows, review/thread state and protected-base compatibility must be re-read after each refresh.

## Context Fabric and EA compatibility

Fresh read-only owner inventory on 2026-09-11 keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both GitHub Release inventories are empty. Wardnet does not write either repository while the Context Fabric owner is active. Mutable owner heads are compatibility evidence only and cannot become Wardnet production authority.

Current CGC contract work and EA projection work remain owner-controlled and unreleased until immutable versioned releases are proven. No mutable CGC/EA head, Context Assertion proposal, architecture projection, or self-declared release identity is Wardnet production authority. Package-manager argv, Wardnet-local reason codes, findings and verdicts remain local security truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `618e4d83cecfd4ca317101edd4b448575501f2a6`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Protected truth and retained security children were adopted/integrated non-destructively through ordinary expected-head merges; no force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

The audit-evidence sequence remains complete through issue #260 / PR #261: owner-only permissions are checked on the already-open descriptor, multiply-linked audit files fail closed, and Linux parent traversal is descriptor-pinned before final-child open while retaining regular-file, owner-only, single-link, append, nonblocking, flush/sync and non-Linux fail-closed invariants.

The pip TLS client-certificate repair from issue #262 / PR #263 remains retained. Its hostile contract proves caller-selected `--client-cert` attached/separate forms for `pip` and `pip3` cannot silently replace reviewed TLS client-authentication authority; the minimum repair reuses the existing `alternate_trust_root` classification. Issue #262 stays open until the effective delta reaches protected main.

The uv configuration-authority repair from issue #264 / merged PR #265 also remains retained. Test-only exact `a718e68bd7f13df9d54f5bd85ef7cde781d4827d` produced hosted semantic RED in CI `34490519712` / rust `102915749368`. The minimum classifier rejects `--config-file` and `--config-file=<path>` on supported `uv pip install` as `alternate_trust_root` without parsing `uv.toml` or duplicating EgressWeave/quarantine authority. Exact child `cd8c1b3c18e2aa8c159fe2b8bd06589d8b0cb8fb` had CI `34491627083` and Fuzz `34491627033` terminal SUCCESS before ordinary expected-head integration. Issue #264 remains open until protected-main adoption.

The newest retained child is issue #266 / merged PR #267 for direct pip proxy argv authority. Test-only exact `030825ff451742ac39ae8858ce7a233aacc3c3b5`, based directly on predecessor canonical #129 `b54fa308b631cb8b293b0fa5ea4c4bcba50d5731`, preserved production bytes and produced hosted semantic RED in CI `34502756020` / rust `102957309570`: `pip install ... --proxy=http://attacker.invalid:8080` reached the intended assertion and was incorrectly `Allow` instead of required `Block`.

After the minimum `--proxy` classifier, exact `9a6767cb8f863a70dac5419eec2beb722c77d19e` reached CI `34503584318` SUCCESS. Fresh primary-source review then exposed the related `--no-proxy-env` authority. Test-only exact `7c63ef4369007b6e0a04bcf3108f12852d258108` produced a second semantic RED in CI `34504136332` / rust `102961974137`: the hostile environment-proxy suppression remained admissible while preceding proxy tests passed.

The current causal repair adds one Wardnet-local classifier limited to direct supported `pip`/`pip3 install`: `--proxy`, `--proxy=<value>`, and `--no-proxy-env` force `Block` with stable `alternate_trust_root`. Wardnet does not parse proxy credentials/URIs, inspect effective runtime proxy variables, perform network I/O or authorize transport. EgressWeave remains canonical executable transport authority and quarantine remains canonical effective runtime environment/isolation authority. Exact child `022627979418bee72a14144733dbfeff043cd195` had CI `34504553770` and Fuzz `34504553595` terminal SUCCESS, zero submitted reviews and zero inline review threads. PR #267 then merged ordinarily with expected-head protection into canonical #129 as current `618e4d83cecfd4ca317101edd4b448575501f2a6`. Issue #266 remains open until protected-main adoption.

All predecessor #129 workflow conclusions are historical after that integration. On unchanged current `618e4d83...`, CI `34505170543`, Fuzz `34505170573`, Security Scan `34505170621`, and SAST Semgrep `34505170523` are terminal SUCCESS. CodeQL PR `34505170531` is terminal FAILURE at the central delegated settlement boundary: detector `102965456825` succeeded; compatibility/actions `102965501474` successfully read current-head verdict state on a real hosted runner and failed only at `Release runner or enforce current-head CodeQL verdict` at 16:58:59Z; exact-head dispatch `102966234175` started only afterwards and completed SUCCESS at 16:59:09Z. A fresh commit-status read after dispatch still exposed Devin Review and CodeRabbit only, with no authenticated `codeql-dispatch/actions` terminal status. This exact consumer specimen was handed to `.github#1929`; it is not a Wardnet source finding.

Fresh #129 review submissions are COMMENTED only. Its sole inline thread remains resolved/outdated, so unresolved valid review-thread count is zero. Issue #128, #262, #264 and #266 remain open until their effective deltas reach protected main. Ambient package-manager environment/config authority remains `quarantine-sandbox-runtime` work; EgressWeave remains executable transport-authorization authority.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. The evidence line remains ordered through business authorization, freshness, source/evidence health, exact generation membership, lifecycle validity, producer-version/tombstone cursor, atomic source replacement and ABA replay resistance. Durable production authority remains the PostgreSQL #80/#192 lineage because bounded current-only lifecycle memory cannot prove historical opaque generation uniqueness.

Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns destination/reputation verdict into transport authority.

## PostgreSQL production-state prerequisite stack

The canonical durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness and no automatic replay after database work begins.

Late-stack evidence remains useful but unreleased: #236 owns typed unknown-COMMIT outcome; #241 executes destructive PostgreSQL 18.4 base-backup/WAL/PITR recovery; #242 proves real divergent-writer serialization and byte-identical replay; #244 proves bounded half-open protocol failover and 200 unexcluded real PostgreSQL preflight+probe samples at p95 ≤20 ms while retaining two physical runtime sessions. `StateAuthority::Postgres` remains disabled.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps are dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 current exact head is `2ca5a8e55185730abec34886279b5aa576be5658`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Two prior whole-file materialization attempts produced incomplete `src/lib.rs` blobs and were immediately repaired by ordinary fast-forward restoration commits. No force update or destructive rebase was used; the current complete source intentionally remains at the semantic product RED.

On unchanged exact `2ca5a8e...`, hosted CI `34486350074` passed checkout, toolchain, formatting and all 121 library tests, then its real Chrome/ChromeDriver test failed only at `tests/admin_console_browser.rs:240` with `console must not clip or horizontally overflow at 375px`. Fuzz `34486350227`, Security Scan `34486350160`, and SAST Semgrep `34486350184` are terminal SUCCESS. CodeQL remains separate central delegated-settlement evidence.

Root cause remains product CSS: `header.app` is a non-wrapping flex row with 24 px side padding while the heading and toolbar/admin-token field cannot fit the resulting 327 px content width. Minimum repair remains one `flex-wrap:wrap` behavior on the complete `header.app` declaration, followed by unchanged 375/768/1440 browser acceptance. Hiding overflow, zooming, widening the viewport, injecting test-only CSS, or using another incomplete full-file materialization is not acceptance. UI Delivery Gate remains **FAIL** until an exact complete source tree carries the repair and the shipped-route browser test is GREEN.

## Process lifecycle and graceful shutdown

Draft #245 remains the process-lifecycle candidate. Its test-first Unix signal lineage established a semantic SIGINT RED and the minimum production repair registers SIGTERM/SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`; no second lifecycle authority was added. Repository CI/Fuzz/Security/SAST are recorded GREEN on its unchanged candidate while CodeQL remains central delegated-settlement work. Draft GREEN is not protected lifecycle truth.

## Release and operational buyer gaps

Wardnet is **not release-ready**. Fresh 2026-09-11 release inventory is empty. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Continue repair-first. Treat canonical #129 exact `618e4d83...` as the only Agent Artifact Admission successor after ordinary #267 integration. Its Wardnet-owned CI/Fuzz/Security/SAST and review-thread evidence is current GREEN; CodeQL terminal-verdict settlement remains `.github#1929` owner work. Keep #128/#262/#264/#266 open until protected integration. Advance central governance and runner/control-plane failures through `.github#772`, `.github#1929` and `.github#712` with exact consumer evidence rather than leaf workarounds. Repair #127's proven 375 px header overflow on its own branch with the single header-wrap behavior change only through a write path that preserves the complete source blob, then reacquire 375/768/1440 real-browser evidence. Continue #244/#243 with explicit coverage/rustdoc and production storage/recovery/release invariants. Integrate dependencies only through ordinary protected governance, then create and verify the immutable release without force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.
