# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Fresh Wardnet GitHub Release inventory is empty, so protected source truth is not yet an immutable release identity.

The organization solo-maintainer governance defect remains canonical `.github#772`: the generic one-approval requirement is structurally unsatisfiable without inventing a reviewer, while self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates remain fail closed.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication/wake ordering remains `.github#1929` or its live successor. Current central repair candidate `.github#2040@6706c231ab06a3c91c43fdb5b989cfcd79fff593` is Ready/Proposed and carries the valid #1902/#2004/#2043/#2044 producer/handler/recovery delta, but it is still mutable owner-path evidence rather than protected truth. Its exact-head runtime-quality lane is terminal SUCCESS while exact-head CodeQL PR run `34251822255` remains terminal FAILURE after repeated settlement attempts; later scheduler successes do not convert that failed required workflow into Wardnet GREEN. Wardnet does not copy central workflow logic, pin the mutable central PR, or churn clean product source to manufacture a terminal verdict.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed #130's own current SHA as merge evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Their mutable heads and open proposals are compatibility evidence only; Wardnet does not write either repository while the Context Fabric owner is active. Fresh GitHub Release inventories for Wardnet, CGC and EA are empty. Package-manager argv, Wardnet-local reason codes, findings and verdicts remain Wardnet-local security truth.

CGC dependency root #4 remains Draft at exact `794e20f31b3e0c1a7958c99cc8535d23b0c25f82`. Its SAST lane is terminal SUCCESS, but exact CodeQL remains non-passing at the central current-head verdict/release boundary even though the later dispatch succeeded, and Security Scan remains non-passing because Dependency Review support verification failed while OSV/Trivy/Scorecard passed. `.github#712` owns the workflow/dispatch defect and `.github#810` owns Dependency Review availability. CGC Context Assertion successor #21 remains Draft/unreleased at exact `238773711aec5c22482fa073ccf3e73a0878d812`, on stale ancestry with no exact-head Actions runs, so it is not release authority. Accepted protected-main/default topology repair remains `.github#1137`, not a Wardnet source change.

EA owner inventory remains consistent with that dependency boundary. Draft #40 is exact `6bbdadddca345ba6eb33ad86e3fba99f417ad529` on #39 and has no exact-head hosted workflow set; its current connector repair removes duplicate quarantine lifecycle validation from the facade while retaining the canonical private validator. EA issue #49 remains the owner-path integration record for future Wardnet outbound site-reputation projection: only released Context Assertions may carry architecture-relevant lifecycle/ownership/risk/remediation context, while Wardnet verdicts/IOCs/incidents stay Wardnet truth and EgressWeave stays executable transport authority. No mutable EA/CGC proposal satisfies a Wardnet production prerequisite.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 is `1f65f7bafe763b1ba33409852b6c33954768b6c3`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. It was produced by ordinary expected-head integration of serialized child #298; no force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only; it is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

Integrated uv hardening now includes keyring-provider authority, platform certificate-store trust selection, reinstall mutation authority, the `--break-system-packages` system-package boundary, request-selected `--torch-backend` source authority, and caller-selected symlink link-mode authority.

### Latest integrated slice: #297/#298 uv symlink link-mode authority

Exact test head `e4625a26c6ca07b3676fec347608bb8e171fa545` established hosted semantic RED in CI `34559512641`: the ordinary reviewed `uv pip install` control remained `Allow`, while explicit `--link-mode=symlink` incorrectly inherited approval. Fuzz `34559512694` succeeded on that RED head.

The minimum repair adopted the already-present narrow classifier, wired it into `admission_decision`, and reused stable `ArtifactNotApproved`. It recognizes only exact `uv pip install` attached/separate symlink forms; it does not inspect or mutate uv cache state, execute uv, read ambient `UV_LINK_MODE`, authorize mounts, or duplicate quarantine authority. Current child `a01c92e86637ee58ba84b7317a5d3aef5cb5f780` reached CI `34560823251` SUCCESS and Fuzz `34560823249` SUCCESS. Fresh compare to exact parent `efe728e0ae2d110e9fe5544e6b6f229028c28d41` was ahead-by-4/behind-by-0 with that exact merge base, and fresh submitted-review plus inline-review-comment inventories were empty. #298 then merged normally with expected-head protection, producing current #129 head `1f65f7bafe763b1ba33409852b6c33954768b6c3`. Issue #297 remains open until the effective policy reaches protected main or a verified successor carries it completely.

Current #129 repository/security lanes are terminal GREEN on exact `1f65f7b...`: CI `34561387995`, Fuzz `34561388116`, Security Scan `34561388010` and SAST Semgrep `34561387993`. Required CodeQL PR `34561388003` is terminal FAILURE only at the central delegated settlement ordering boundary: Detect `103144657912` succeeded; compatibility `103144957484` successfully read the current-head verdict and failed only at `Release runner or enforce current-head CodeQL verdict`; exact-head dispatch `103145554296` subsequently completed SUCCESS. The completed ordering reproduction and exact consumer tuple are recorded in `.github#1929`; GREEN still requires an authenticated terminal current-head receipt rather than a later dispatch alone. No child/predecessor result, synthetic status or source churn substitutes for that receipt.

## Concurrent phishing-feed SSRF repair

Protected-baseline companion #295 established causal RED in hosted CI `34557037833` / rust `103131783940`: an authenticated request-selected Phishing.Database loopback URL was actually fetched through the former non-default-host bypass. Production repair #291 removes request-controlled `domain_url`, `ip_url` and `allow_non_default_hosts`, resolves feed URLs server-side, keeps loopback override under `cfg(test)` only, and validates the server-owned source host.

Current exact #291 is `aeb53ec3bad7b65bb9fbb16722ef2cd1fd8abdcc`. CI `34559388209`, Fuzz `34559388203`, Security Scan `34559388221` and SAST Semgrep `34559388206` are terminal SUCCESS. CodeQL PR `34559388211` fails only at the central delegated terminal-verdict settlement boundary; its exact consumer tuple and GREEN acceptance are recorded in `.github#1929`.

#295's sole changed-file blob is byte-identical to the regression carried by #291, so #295 was closed only after verified complete-successor transfer. Its hosted RED remains historical evidence. Fresh review of #291's final inline thread found no additional security defect: the in-module `phishing_database_import_endpoint_supports_blocking_flow` already injects server-owned loopback feeds and proves CREATED/import/audit/gateway-blocking success, while the integration regression independently proves legacy request-carried hostile URLs are never fetched. Exposing the `cfg(test)` source seam to production or depending on the real upstream only to combine those properties would weaken the boundary/reproducibility, so that advisory thread was answered with exact-source evidence and resolved.

All current inline review threads are therefore resolved, but #291 remains Draft because review evidence reports only 50% touched-function docstring coverage while Wardnet's stronger owned-production rustdoc contract is 100%. That rustdoc/documentation gap remains valid and must be repaired causally; the exact head will then need fresh repository/security/review evidence. Thread resolution is not approval and does not transfer existing GREEN after source movement.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns a destination/reputation verdict into transport authority.

EA issue #49 is the read-only owner projection path for this future capability. It explicitly preserves Wardnet as reputation/security truth owner, EgressWeave as transport-enforcement owner and EA as architecture-context consumer; no site-reputation-specific EA implementation should be created before both Wardnet producer identity and compatible CGC Context Assertion surfaces are immutable protected releases.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness, ambiguous-COMMIT fail-closed handling, physical recovery drills and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 exact `83c4babc0e1bd9b428be7dc3afc5779ca68abdbd` retains hosted real-browser product GREEN: CI `34542012228`, Fuzz `34542012166`, Security Scan `34542012272` and SAST Semgrep `34542012155` are terminal SUCCESS. The browser contract covers loading/normal/permission-denied states, keyboard skip-link transfer, computed accessibility semantics and unchanged 375/768/1440 responsive clipping/overflow boundaries. UI Delivery Gate is PASS for the material UI/product contract on that exact head; delegated CodeQL/governance/coverage/package/SBOM/provenance still prevent protected integration.

## Process lifecycle and graceful shutdown

Draft #245 remains exact `d953c1d94ebbde87a0f7c4121a8088e0b9fa14f2`. Its test-first Unix signal lineage established semantic SIGINT RED; the minimum production repair registers SIGTERM/SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`, without creating a second lifecycle authority. Exact CI `34423929129`, Fuzz `34423929826`, Security `34423929246` and SAST `34423929010` are SUCCESS; delegated CodeQL remains central control-plane work.

## Release evidence foundation

Draft #164 remains stacked on Rust-toolchain prerequisite #77, exact head `42a673defb756d959cf754a8140227fbebfdd0f1`. It builds deterministic source/binary release evidence and keeps OIDC-backed attestation authority protected-main/manual-dispatch only. Exact CI `34425717320` is terminal SUCCESS. This foundation is not itself a release, and Wardnet release inventory remains empty.

## Release and operational buyer gaps

Wardnet is not release-ready. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep current canonical Agent Artifact Admission #129 exact `1f65f7bafe763b1ba33409852b6c33954768b6c3` Draft while the delegated CodeQL terminal receipt remains unresolved under `.github#1929`; its repository CI/Fuzz/Security/SAST are exact-head GREEN and do not justify source churn. Continue exact-source review for the next Wardnet-local admission gap rather than duplicating foreign-owner behavior. Any new finding must first prove realistic hostile RED on the unchanged canonical parent before minimum causal repair.

Advance concurrent #291 independently by closing its owned-production rustdoc gap, then reacquire exact-head repository/security/review evidence. Its current inline review-thread count is zero after exact-source adjudication of the final advisory suggestion. Delegated CodeQL remains `.github#1929` / central #2040 owner work; no source churn, synthetic status or mutable central pin substitutes for that repair. #295 stays closed under verified complete-successor transfer unless a later review proves a valid delta was not carried.

Let #127's hosted 375/768/1440 product contract stand without source churn while central CodeQL settles. Continue runner/materialization, delegated CodeQL, Dependency Review availability, branch-topology and solo-maintainer governance repairs through `.github#712`, `.github#1929`/current successor, `.github#810`, `.github#1137` and `.github#772`. Continue the PostgreSQL/recovery/coverage stack dependency-first. Only after protected prerequisites and all then-live gates are terminal-valid should Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.