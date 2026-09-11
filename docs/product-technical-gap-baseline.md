# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth is `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. That protected change makes management writes fail closed when a public bind has no write-capable admin credential and carries its associated auth/security documentation and hostile tests. It is protected source truth, not an immutable release: the fresh Wardnet GitHub Release inventory is still empty.

The organization solo-maintainer governance defect remains canonical `.github#772`: live ruleset `18156473` still requires one generic approving review while naming no required reviewer/team. Self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/deletion/non-fast-forward controls stay fail closed; routine administrator bypass is not merge evidence.

Runner/materialization remains `.github#712` authority when an exact candidate genuinely has no checkout/runner/materialization evidence. Delegated CodeQL current-head verdict settlement remains `.github#1929` or its live successor. Wardnet does not copy central workflow logic, pin mutable central repair heads, add no-op source changes to manufacture dispatch, or promote a later dispatch over a failed required workflow.

PR #130 is the sole writer for this ledger. Every refresh advances its own exact head, so this file deliberately does not embed #130's current SHA as evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Wardnet does not write either repository while the Context Fabric owner is active. Fresh GitHub Release inventories for Wardnet, CGC and EA are all empty, so no mutable CGC/EA proposal is production dependency authority.

CGC dependency root #4 remains Draft at exact `794e20f31b3e0c1a7958c99cc8535d23b0c25f82`. Its SAST lane is terminal SUCCESS; required CodeQL remains non-passing at the delegated current-head verdict/release boundary even though the later dispatch succeeded; Security Scan remains non-passing because Dependency Review support verification failed while OSV/Trivy/Scorecard passed. `.github#712` owns central workflow/materialization defects, `.github#1929` owns CodeQL terminal-verdict settlement, and `.github#810` owns Dependency Review availability. Context Assertion #21 remains Draft/unreleased at exact `238773711aec5c22482fa073ccf3e73a0878d812`, on stale ancestry with no exact-head Actions execution, so it is not release authority. Accepted protected-main/default topology repair remains `.github#1137`, not a Wardnet source change.

EA Draft #40 remains exact `6bbdadddca345ba6eb33ad86e3fba99f417ad529` on #39 and has no exact-head hosted workflow set. Its current connector repair removes duplicate quarantine application-service lifecycle validation from the facade while retaining the canonical connector-contract validator. Future Wardnet architecture projection remains released-contract-only: Wardnet verdicts/IOCs/incidents stay Wardnet truth; EA receives only architecture-relevant lifecycle/ownership/risk/remediation context with provenance.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Protected `main` advanced while #129 was open, so the old `1f65f7bafe763b1ba33409852b6c33954768b6c3` exact-head checks became historical. Reverse-direction restack #303 adopted protected #155 normally without force or destructive rebase. Current #129 is exact `50be3016353f992100b782fb7765b212ef9fc551` on protected base `main@f8260f1e03836039ff9463dd99fa982e4e270c4b` and is mechanically mergeable but remains Draft.

The candidate preserves deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only; it is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

Integrated uv hardening includes keyring-provider authority, platform certificate-store selection, reinstall mutation authority, `--break-system-packages`, request-selected `--torch-backend`, and explicit caller-selected symlink link-mode authority. The #297/#298 slice retains its causal hosted RED at `e4625a26c6ca07b3676fec347608bb8e171fa545` and the minimum `ArtifactNotApproved` repair already integrated before restack.

Exact-current execution for unchanged `50be3016353f992100b782fb7765b212ef9fc551` is now terminal for the principal repository/security lanes: CI `34564995768`, Fuzz `34564995811`, SAST Semgrep `34564995820`, and Security Scan `34564995826` are SUCCESS. Required CodeQL PR `34564995839` is FAILURE at the delegated current-head settlement boundary. The previously observed pre-checkout queue is therefore historical for this exact head; do not rerun or churn source merely to reacquire already-terminal lanes. CodeQL settlement remains `.github#1929` owner work and no successful later dispatch may be promoted over the failed required workflow.

Keep #129 Draft until the unchanged exact head has terminal-valid CodeQL/current review evidence, owned-production coverage/rustdoc proof, protected-base compatibility and every then-live package/SBOM/provenance/governance gate. A Wardnet admission receipt remains distinct from foreign-owner fetch, transport, runtime isolation and installation authority.

## Phishing.Database SSRF repair

Protected-baseline companion #295 established causal RED in hosted CI `34557037833` / rust `103131783940`: an authenticated request-selected Phishing.Database loopback URL was actually fetched through the former non-default-host bypass. Production repair #291 removes request-controlled `domain_url`, `ip_url` and `allow_non_default_hosts`, resolves feed URLs server-side, keeps loopback override under `cfg(test)` only, validates the server-owned source host, and preserves the no-redirect HTTP client.

#295's hostile regression was transferred byte-identically into #291 before #295 closed. Review of the positive-path suggestion confirmed that `phishing_database_import_endpoint_supports_blocking_flow` already proves server-owned configured fetch/CREATED/import/audit/gateway blocking, while the separate integration regression proves legacy request-carried hostile URLs are never fetched. Both current inline review threads were resolved; resolution is finding evidence, not independent approval.

CodeRabbit's touched-function documentation finding was valid. Stacked #299 supplied the more complete rustdoc delta and merged normally into #291; overlapping #300 was closed only after exact comparison proved #299 carried all valid #300 documentation plus `AppState::new`. #305 then carried the remaining current-lineage documentation clarification into #291. The older CodeRabbit docstring warning is predecessor review evidence, not proof against the current source. Wardnet's stronger owned-production rustdoc contract remains 100% and must be demonstrated by exact-head evidence before promotion.

Protected `main` advanced through #155 and reverse-direction restack #301 adopted that protected delta normally. Current #291 is exact `e01683d526da058a813f8d8f0fe87a52c3594b39` on base `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. Exact-current CI `34565621792`, Fuzz `34565621778`, Security Scan `34565621750`, and SAST Semgrep `34565621831` are terminal SUCCESS. Required CodeQL PR `34565621754` is terminal FAILURE: compatibility-analysis job `103159995541` failed before a usable terminal current-head verdict, while later dispatch job `103161018713` succeeded. That ordering is fresh consumer evidence for `.github#1929`, not a Wardnet leaf-code reason to weaken or duplicate the central workflow.

Keep #291 Draft. Guarded bypass is not applicable while a required deterministic workflow itself is RED. Promotion requires one unchanged exact head with terminal-valid CodeQL, repository/security/static-analysis gates, hostile and positive security properties, owned-production coverage/rustdoc completion, fresh review/thread state, protected-base compatibility and then-live package/SBOM/provenance/governance requirements.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns a destination/reputation verdict into transport authority.

EA issue #49 remains the read-only owner projection path for this future capability. No site-reputation-specific EA implementation should become a Wardnet prerequisite before both Wardnet producer identity and compatible CGC Context Assertion surfaces are immutable protected releases.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness, ambiguous-COMMIT fail-closed handling, physical recovery drills, divergent-writer serialization and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and lifecycle buyer paths

Draft #127 retains its hosted real-browser product contract for loading/normal/permission-denied states, keyboard skip-link transfer, computed accessibility semantics and 375/768/1440 responsive clipping/overflow boundaries. Its existing exact-head browser evidence remains branch evidence only; delegated CodeQL/governance/coverage/package/SBOM/provenance still prevent protected integration.

Draft #245 carries the test-first Unix SIGINT graceful-shutdown repair: SIGTERM/SIGINT are registered before readiness and resolve the existing shutdown future through one `tokio::select!`, without creating a second lifecycle authority. Reverse-direction restack #304 adopted protected #155 normally. Current exact head is `ca499853b152f80f6bd642060f1b55c5e832e9c5` on protected base `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. Exact-current CI `34565440911`, Fuzz `34565440918`, Security Scan `34565440891`, and SAST Semgrep `34565440879` are SUCCESS; required CodeQL PR `34565440897` is FAILURE at the same delegated settlement boundary. The earlier stale-base/queued description is superseded. Keep #245 Draft until CodeQL, review, coverage/rustdoc, package/SBOM/provenance and governance are terminal-valid on one unchanged candidate.

## Release evidence and buyer gaps

Draft #164 remains the release-evidence foundation stacked on its Rust-toolchain prerequisite. It builds deterministic source/binary evidence and keeps OIDC-backed attestation authority protected-main/manual-dispatch only. That foundation is not a release. Fresh Wardnet release inventory remains empty.

Wardnet is not release-ready. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Protected #155 materially improves the management-authentication baseline, but material production gaps remain: complete Runtime Configuration/Keyverse integration and separation-of-duties; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup on current protected ancestry; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep canonical #129 exact `50be3016353f992100b782fb7765b212ef9fc551` Draft. Its CI/Fuzz/SAST/Security lanes are now exact-head GREEN; do not churn those lanes. Continue exact-source admission review and owned coverage/rustdoc proof while `.github#1929` repairs the required CodeQL settlement path. Any new security finding still requires a realistic RED before minimum causal repair.

Advance #291 independently without weakening its server-owned-source boundary. Exact current CI/Fuzz/SAST/Security are GREEN and its previous documentation finding has been repaired on the current lineage; required CodeQL remains RED through the central settlement defect. Preserve the hostile regression and positive import/blocking path unchanged while owner repair proceeds. #295 remains closed under verified complete-successor transfer unless later evidence proves a valid delta is missing.

Keep #245 on its current protected ancestry; its CI/Fuzz/SAST/Security lanes are exact-head GREEN and CodeQL is the current required-workflow failure. Do not manufacture additional source movement to retrigger central settlement.

Keep the PostgreSQL/recovery stack dependency-first and restack stale product lanes only by ordinary non-force integration. Continue central queue/materialization, delegated CodeQL, Dependency Review availability, Context Fabric branch topology and solo-maintainer governance through `.github#712`, `.github#1929`, `.github#810`, `.github#1137` and `.github#772` rather than leaf workarounds.

Only after protected prerequisites and all then-live gates are terminal-valid should Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL, mutable dependency authority or predecessor-evidence transfer.