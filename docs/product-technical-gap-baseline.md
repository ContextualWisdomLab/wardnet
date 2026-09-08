# Product and technical gap baseline

Snapshot date: 2026-09-08. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Historical commits below are retained only where they establish causal RED→repair lineage; predecessor results are never promoted as current-head GREEN.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, security evidence lifecycle, Wardnet policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, or promote foreign findings into Wardnet truth.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` remains the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` remains the EA Decision Plane. Wardnet reads those owners for compatibility and owner handoff only. Wardnet verdicts, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory is empty for Wardnet, EgressWeave, `context-graph-contracts`, `enterprise-architecture-core`, `contextual-orchestrator`, `quarantine-sandbox-runtime`, and `appguardrail`. Mutable owner PR heads are therefore design/compatibility evidence only, not immutable production authority.

## Protected truth, governance and control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. There is still no immutable Wardnet GitHub Release, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active on the default branch and still requires one approving review while naming no required reviewer, code owner or last-push approver. It also requires review-thread resolution plus central workflow gates, forbids deletion/non-fast-forward updates, and exposes `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model the bare approval count and routine bypass are central governance defects owned by `.github#772`; self-approval, bot/model-as-human approval and routine administrator bypass remain forbidden. `.github#1644@5f5d7a9e849984c052c72a08eba34f68cb694024` is still Draft and explicitly has not converged the live owner plane, so product PRs are not merge-policy probes.

Runner/materialization remains `.github#712` authority. A queued run is incomplete evidence. Exact Wardnet jobs across the current reputation and gateway lanes have repeatedly acquired real GitHub-hosted `ubuntu-24.04` runners, so remaining central failures must be diagnosed from exact logs rather than classified generically as a runner-label defect.

Delegated CodeQL terminal-status publication remains `.github#1929` authority. The current central issue is still open: identity/matrix defects have had partial owner repairs, but unchanged consumer heads still supply examples where leaf dispatch succeeds without an authenticated terminal receipt being reconciled back to the required job. Wardnet keeps those failures non-passing and does not substitute predecessor/native/model evidence.

Central Strix remains source/repository-scan authority, not a Wardnet runtime substitute. Fresh inspection of `.github/workflows/strix.yml@main` shows the trusted quick gate scans `__PR_SCOPE__`/repository data and does not yet expose a generic isolated live-service target. Wardnet #11 therefore remains open, and `.github#2027` now owns the reusable exact-head live-target contract needed to start Wardnet on an isolated listener, exercise it with Strix, and return an attack→Wardnet-detection receipt without copying the central workflow or selecting a direct provider/model fallback.

## Outbound destination reputation

### Proposed architecture #173

#173 remains open/Ready and mechanically mergeable at exact `7d0006b0f1fd3311c891bf359bd0c3e66a1831ec` against protected `main@a52ccd0...`. Its effective delta is four documentation files and the ADR remains Proposed, not shipped runtime truth.

CI `34025817869`, Security `34025817908`, SAST `34025817866`, and CodeQL `34025817876` are terminal success. Required Noema `34025816776` remains non-passing after the central CO sidecar/model phase ended with HTTP 502 and no typed terminal review/provider-unavailable envelope. `.github#1611` owns that control-plane repair. Wardnet adds no direct-provider fallback and consumes no mutable contextual-orchestrator source. Fresh contextual-orchestrator Releases is empty.

Production transport integration still requires an immutable compatible EgressWeave Rust-consumer boundary. Fresh EgressWeave Releases is empty; #173 therefore cannot claim runtime enforcement.

### Reputation contract root #175

#175 remains open/Draft and mergeable at exact `9de0ea568096a18b5c1fc9bc9fce097e08584d44` on protected main. The v1 pure Rust core separates malicious/suspicious/unknown assessment, evidence health, action and reason; rejects unknown wire fields; binds reviewed source/tenant eligibility; gives `ObservableUrl` an 8 KiB bound; and caps `DecisionEnvelopeV1.evidence_refs` at 32 while retaining the generic 64-item list bound.

Exact CI `34071995169`, Fuzz `34071995140`, Security `34071995181`, and SAST `34071995128` are terminal success. Required CodeQL `34071995171` remains terminal failure at the delegated terminal-verdict publication boundary after successful leaf dispatch. Root stays Draft until `.github#1929` proves the unchanged-head receipt path and `.github#772` makes ordinary governance satisfiable.

### Business authorization child #176

#176 remains open/Draft at exact `5d7166da2034d450f37ab69d37fbbb9d1301e287`, based on exact #175. It binds business authorization to exact policy/canonicalization/subject/scope/authorization revision/approver-ticket/provenance/validity and `policy_mode=protect`, while preserving the parent 32-reference decision cap and 8 KiB observable-URL invariant. Exact-current CI `34125618252` and Fuzz `34125618251` are terminal success. It remains a dependent Draft and cannot inherit root merge evidence.

### Decision freshness child #178

#178 remains open/Draft at exact `43faf199fde4a74a1f74a3c544f56f5f4e3b23e5` on current #176. It retains executed RED `76fa9a0e23a68853f5fa14c6cd9bad10a4b51a7b` and minimal GREEN `4a88e8a7f4b324c2593f3b1a4aa3e5d791fe80e9`, adding deterministic injected-time `DecisionEnvelopeV1::validate_at(now_unix)` without ambient-clock or transport authority. Exact CI `34130786226` and Fuzz `34130786225` are terminal success. It remains Draft behind #176/#175.

### Evidence-snapshot health child #179

#179 remains open/Draft and mergeable on exact parent #178; exact head is `6305284dd3bc9cca5e0d8da3927abf7d5ea075b8`.

The original snapshot model RED reached semantic workspace failure on `12e2cac1ea56283bf1da992fc625706f9863f68b` / CI `34114942581`. Fresh review then found a completion-order hole: a source snapshot could claim completion before Wardnet received an included record. Test-only exact `2e027de75c198afd1c032ab4a4e170addd17a9f9`, CI `34143773398` / rust job `101811265332`, passed checkout/toolchain/fmt and failed in the hostile workspace test while production remained unchanged. Minimal repair `6305284...` rejects `record.received_at_unix > source_snapshot.completed_at_unix` using the existing `InvalidTimeOrder` error.

Exact-current CI `34145736332` and Fuzz `34145736549` are terminal **SUCCESS**. Review-thread inventory is empty. This prerequisite stays Draft behind #178/#176/#175.

### Exact source-generation membership child #183

#183 remains open/Draft and mergeable on exact `#179@6305284dd3bc9cca5e0d8da3927abf7d5ea075b8`; exact head is `1b183e784750d56d4cbeda469d2ced75811ae08c`.

The first hostile RED `8246d42952e9447480280690647ebe23d3695d65` proved that stable `source_id` plus receive-before-completion could not establish membership in the exact completed source generation. The repair introduces `EvidenceSnapshotRecordV1 { source_generation, record }`, makes the generation-bound root `EvidenceSnapshotV1` the sole public v1 snapshot authority, and keeps unaffected `model::...` compatibility while excluding the obsolete unbound snapshot authority.

Fresh review of that repair found a second malformed-input defect: wrapper `source_generation` was unbounded before membership matching. Test-only RED `a2cfd2e108ec8e75c54dd896225809a7c1ccabb5`, CI `34152014206` / rust job `101836077859`, acquired hosted Ubuntu 24.04 and failed causally after checkout/toolchain/fmt because validation returned `MissingSourceSnapshot` for a 1,025-byte generation instead of `BoundExceeded("snapshot_record.source_generation")`. Minimal production repair `d86d8f2a18cce69f3bebb80ec3ef01f38db74ea7` applies the v1 nonblank/1,024-byte required-text contract before matching. Current documentation records the provenance decision and notes NIST SP 800-218 SSDF 1.1 as the final normative reference while SP 800-218 Rev. 1 / SSDF 1.2 remains an Initial Public Draft.

Exact-current CI `34152467045` / rust job `101837405034` is terminal **SUCCESS** through formatting, locked workspace tests and strict Clippy. Exact-current Fuzz `34152466976` / fuzz job `101837450961` is terminal **SUCCESS** across all four bounded targets. Formal review count is 0 and inline review-thread count is 0. #183 stays Draft until `#175 -> #176 -> #178 -> #179` integrates in order; future parent movement invalidates integration evidence and requires non-force restack/revalidation.

Issue #182 remains open intentionally until protected integration; feature-branch GREEN is not completion.

### Evidence lifecycle enforcement child #185

#185 remains open/Draft and mergeable on exact parent `#183@1b183e784750d56d4cbeda469d2ced75811ae08c`; exact head is `b2169d465aa15da9da78f5c42b785e44a4bc664d`.

Test-only hostile RED `f5d8f28d32cabca23a90acf86e578faeac703791` changed only `tests/evidence_lifecycle_enforcement.rs` while production remained byte-identical to #183. Hosted CI `34154105805` / rust job `101842225780` acquired a GitHub-hosted runner, passed checkout/toolchain/fmt, then failed at the workspace Test step because revoked or deleted producer evidence could still retain `enforcement_eligible=true`.

The minimal repair makes `EvidenceRecordV1::validate_at` return typed `LifecycleIneligibleEnforcementEvidence` when enforcement eligibility contradicts either producer lifecycle flag. It does not rewrite evidence: revoked/deleted records remain valid historical evidence when `enforcement_eligible=false`. `EVIDENCE_LIFECYCLE_TRACEABILITY.md` records the bounded-context decision, rejected alternatives and RED receipt. This stateless record validator intentionally leaves cross-generation monotonic producer-version/tombstone admission to the explicit lifecycle-state successor rather than guessing producer ordering.

Exact-current CI `34154846345` / rust job `101844429388` is terminal **SUCCESS** through exact checkout, formatting, locked workspace tests and strict Clippy. Exact-current Fuzz `34154846324` / fuzz job `101844430502` is terminal **SUCCESS** across all four bounded 60-second targets with no crash artifact. Formal review count is 0 and inline review-thread count is 0. #185 stays Draft behind `#175 -> #176 -> #178 -> #179 -> #183`; parent movement invalidates integration evidence and requires non-force restack/revalidation. Issue #184 remains open until protected integration.

### Producer lifecycle cursor child #187

#187 remains open/Draft on exact parent `#185@b2169d465aa15da9da78f5c42b785e44a4bc664d`; exact head is `b549c4e3f894492ae8d235c79f3447440981e3e8`.

The causal test-first RED is formatting-clean exact `76655da309351d50555af475f5dc38e9895680bc`: hosted CI `34158323025` / rust job `101854686599` passed checkout/toolchain/fmt and failed at `Test` because no producer lifecycle cursor/error contract existed. The pure Rust repair adds bounded `ProducerRecordLifecycleCursorV1` state keyed by exact `(source_id, producer_record_id)`, uses adapter-supplied authenticated normalized ordinal rather than ordering opaque `producer_record_version` text, rejects stale replay and tombstone resurrection/collisions, and preserves valid active→newer→tombstone plus idempotent same-version tombstone transitions. It adds no network, database or durable-store authority.

Exact-current CI `34158588558` / rust job `101855489287` and Fuzz `34158588557` / fuzz job `101855542494` are terminal **SUCCESS** on unchanged `b549c4e...`. Formal review and inline thread counts are zero at the latest read. The cursor is deterministic in-memory admission state only: durable cursor authenticity/persistence and crash-safe coupling to the accepted source snapshot remain a later storage/adapter responsibility.

### Atomic complete-source replacement child #189

#189 remains open/Draft and mergeable on exact parent `#187@b549c4e3f894492ae8d235c79f3447440981e3e8`; current exact head is `7f715a843236bcb79452fc1b3c84d50f34da9981`.

The initial test-only RED `64f60c0dfa0ecc4a21d29ce404618bce971ffe4c` / CI `34159300515` proved there was no bounded complete-source replacement operation. The pure transition now requires explicit `complete` state, supports authenticated complete-empty replacement, CAS-binds an existing source to the exact prior generation, preserves unrelated sources/records, and delegates the resulting candidate through the existing aggregate schema/bounds/duplicate/provenance/lifecycle validation.

Fresh review found two additional replay-integrity defects and repaired them test-first. Exact `b53ddde9bcd8524658cacac0efe108577bc9dd87` / CI `34160409623` proved changed state could reuse one immutable `source_generation`; the minimal equality guard rejects that reuse without trying to sort opaque generation tokens. Exact test-only `2904f11a47a149e97c1bb8f77fd7cb61376451f1` / CI `34161720520`, rust job `101864749405`, then passed checkout/toolchain/fmt and failed at `Test` because a distinct generation token could move authenticated `completed_at_unix` backwards. Minimal repair `7a6f56c5b576aa9948d7cd7c9e27310ef0c15212` adds typed `SourceCompletionRegression` and rejects only completion-time regression; equal completion timestamps remain valid and `valid_until_unix` may legitimately shrink.

Current documentation head `7f715a843236bcb79452fc1b3c84d50f34da9981` has exact CI `34162018684` / rust job `101865605262` terminal **SUCCESS** through checkout, toolchain, formatting, locked tests and strict Clippy. Exact Fuzz `34162018692` / fuzz job `101865650619` is terminal **SUCCESS** on the same head after the bounded targets completed on GitHub-hosted `ubuntu-24.04`; no crash artifact was produced. Formal review count and inline review-thread count are both zero. No predecessor GREEN is promoted.

### Source-generation ABA replay child #191 and durable successor #192

#191 remains open/Draft on exact parent `#189@7f715a843236bcb79452fc1b3c84d50f34da9981`; current exact source head is `ed6ba763b7feeb9a4ac67653776619c34783023e`. The movement from predecessor `9d42b7da750570a970785242b7f26072e89a558e` is a non-force, test-only +38-line change in `crates/wardnet-reputation-core/tests/source_generation_lifecycle.rs`; production source is unchanged.

Predecessor `9d42...` had terminal CI `34168771438` and Fuzz `34168771365` GREEN for the current-cursor/single-hop lifecycle contract. Fresh exact-source review proved that GREEN was insufficient for the issue-level historical ABA requirement: after valid `generation-8@8 -> generation-9@9`, the current implementation forgets the historical 8@8 binding and can accept the same opaque token as `generation-8@10`.

The new hostile case `source_generation_lifecycle_rejects_aba_token_rebinding_at_a_newer_ordinal` is now executed semantic RED. Hosted CI `34172081051` / rust job `101894179030` acquired real GitHub-hosted runner `1001761240`; exact checkout/toolchain and `cargo fmt --check` succeeded, then `cargo test --locked --workspace` failed only in that new lifecycle case. The observed value was `Ok(SourceReplacementTransitionV1 { ... source_generation: "generation-8", source_generation_ordinal: 10 ... })`; required behavior is `Err(ReusedSourceGeneration)`. Nine sibling lifecycle tests passed and Clippy was skipped after the causal test failure. Exact Fuzz `34172081085` / job `101894179222` is terminal **SUCCESS** on the same unchanged head: hosted runner `1001761232` completed all bounded targets with no crash artifact. That Fuzz success does not convert the semantic CI RED into GREEN.

Root cause is architectural, not formatting or runner behavior: `SourceGenerationLifecycleCursorV1` retains only the currently represented token/ordinal pair, so a current-only cursor cannot prove global historical token non-reuse. A fixed-size recent-token cache would only postpone ABA acceptance or impose an arbitrary source lifetime and is not an acceptable commercial replay invariant. #191 therefore remains Draft/RED; the hostile test is retained rather than weakened to manufacture GREEN.

New P0 #192 is the causal durable successor under #80. Wardnet must persist tenant-scoped source-generation token/ordinal bindings with uniqueness on both generation identity and normalized ordinal, and atomically commit those bindings with producer lifecycle state, the accepted immutable evidence snapshot, completeness/pagination proof and last-known-good publication. Real PostgreSQL acceptance includes `8@8 -> 9@9 -> 8@10`, ordinal collision, concurrent writers, crash/retry/idempotency, default-deny RLS and pooled-context isolation, migration/rollback and backup/restore survival. #140 Runtime Configuration is the prerequisite bootstrap foundation before reconstructing #80. Stale mixed #95 remains evidence only; its old non-loopback-bind inference is explicitly insufficient as production-mode authority because production may listen on loopback behind a proxy/sidecar.

## Gateway route-segment admission #180 / #181

Protected `main@a52ccd0a...` uses lexical route-prefix matching, so `/api` can capture `/apix` and `/api/admin` can capture `/api/administrator`, binding a request to the wrong route/enforcement/upstream authority. RFC 3986 §3.3 supplies the path-segment boundary.

Draft #181 executed the hostile RED on exact `93d097626d96f9adaffc267f47be162c397355f3`; CI `34129793580` / rust job `101766902311` passed checkout/toolchain/fmt and pre-existing tests, then failed exactly on the lexical sibling cases. Minimal causal candidate remains exact `fc5645bb2e661f9af63d84b1d08e939b3d7ab3fe`, changing only `select_route` to exact-or-slash-descendant matching while preserving root, trailing-slash, disabled-route and longest-valid-match behavior.

Exact-current CI `34141693656`, Fuzz `34141693771`, Security `34141693787`, and SAST `34141693672` are terminal success. CodeQL `34141693695` remains terminal failure only at delegated receipt reconciliation after a later exact dispatch succeeded. That owner specimen remains under `.github#1929`; no source churn or broad rerun is causal.

## Fresh protected-main adoption maintenance

Three bounded non-overlapping candidates were stale by exactly protected #171's ADR-only advance and were repaired non-destructively on 2026-09-08 rather than force-rebased or closed:

- #134 support-bundle regression now exact `ce58b6ec2968f314ea223ddb9ff7228fc4222e44`, merge base protected `a52ccd0...`, `behind_by=0`, with the same sole `src/lib.rs` +38-line test delta. Fresh CI/Fuzz/Security/SAST/CodeQL runs are queued and predecessor evidence does not transfer.
- #162 commercial-authority separation now exact `81a1705c04dd3cae4ea4e6466ae09b9c956517d6`, merge base protected `a52ccd0...`, `behind_by=0`, with the same six-file 2B-KRW-customer versus USD-20B-quality authority delta. Fresh exact-head CI/Security/SAST/CodeQL runs are queued.
- #144 Kubernetes source-path migration now exact `f5383585d3588d7b63b00a11bba61fa0d875743e`, merge base protected `a52ccd0...`, `behind_by=0`; protected #171's two ADR blobs were adopted while the 13-path path/deployment/docs/test delta remained unchanged. Fresh CI/Fuzz/Security/SAST/CodeQL runs are queued.

Queued states are lane-local non-passing evidence, not reasons for no-op commits or rerun storms. Their owning PR/issue bodies now bind the exact new heads and current runs.

## Agent Artifact Admission and other security lanes

#129 remains open/Draft at exact `14c0af32e7e4f68c682d55a1b1117629fa940336` with CI `34020063254`, Fuzz `34020063220`, Security `34020063214`, and SAST `34020063245` terminal success. CodeQL `34020063240` remains the same central delegated-verdict failure. Its Rust-first admission receipt is policy authority only; retrieved-byte integrity, AppGuardrail static analysis, quarantine hostile execution, Noema activation, EgressWeave transport and CO provider orchestration stay separate canonical authorities.

#167/#170 retain MISP/DNSBL source ownership and threat-level translation work; delegated CodeQL remains central-owner evidence. #140 is the single Runtime Configuration owner at exact `13da5928e22d195b5a2f3cbfcee415060747125b`: hostile RED proved `use std::env; ... env::var(...)` bypassed the recursive architecture-fitness detector; the minimal repair now rejects direct/aliased/grouped `std::env` imports. Exact CI `34166154917`, Fuzz `34166154875`, Security `34166154889`, and SAST `34166154908` are terminal success; CodeQL `34166154874` remains central delegated-receipt failure. #155 remains the fail-closed non-loopback management-authentication prerequisite; #93 remains the deterministic persistence-fault seam; #127 still needs material browser accessibility/state evidence.

#77 Rust-toolchain/reproducibility foundation remains exact `2856babd52b3131845a347c6d005b031b7099986` on current protected main. Exact CI `34019585668`, Security `34019585622`, and SAST `34019585640` are terminal success; all review threads are resolved. CodeQL `34019585679` fails only at the central current-head receipt boundary after a successful dispatch request, so source churn is not causal. #164 remains its dependent release-evidence child until #77 reaches protected truth.

Release blockers remain #80 PostgreSQL production authority/RLS/tenant isolation, #81 transactional outbox/idempotent workers, #82 Keyverse identity/approval, #83 bounded distributed admission/trusted attribution, #84 immutable signed release/promotion/rollback, #85 telemetry/SLO/incident/restore, #86 proven Coraza/CRS + Suricata enforcement, and #11 deployed Strix attack-path evidence. #192 adds the reputation-specific durable source-generation uniqueness/atomic-publication invariant under #80. For #11, `.github#2027` owns the missing reusable isolated live-service Strix target; a source-only scan is explicitly non-completion.

## Context Fabric / EA read-only inventory

Fresh read-only inventory confirms `context-graph-contracts` and `enterprise-architecture-core` remain unreleased owner paths. Both GitHub Release inventories are empty. CGC still has an active Draft dependency stack including the Context Assertion contract candidate; EA retains its Draft projection/reconstruction stack. Wardnet does not modify either owner and does not treat mutable Context Assertion/EA heads as production authority.

Architecture-relevant Wardnet technology/lifecycle/risk/ownership/remediation changes may be handed off as provenance-bound projections once a compatible immutable Context Graph contract exists. Wardnet finding/verdict truth is not copied into authoritative EA truth.

## Buyer-visible gap order

Authority and safety remain ahead of feature breadth. Current release-blocking order is: satisfiable protected governance and exact-head control-plane evidence; protected management authentication; #140 Runtime Configuration protected truth followed by #80/#192 durable PostgreSQL reputation admission that crash-safely couples authenticated completeness, globally unique source-generation token/ordinal bindings, producer-record lifecycle state and the accepted immutable evidence snapshot; immutable EgressWeave authorization/evidence integration; deployed Strix live-service attack→detection evidence through `.github#2027` and proven Coraza/CRS + Suricata enforcement; Agent Artifact Admission; the remaining PostgreSQL production authority/RLS/tenant isolation surface; transactional outbox/idempotent workers; Keyverse-backed identity/approval and distributed admission/trusted attribution; immutable package/image/SBOM/provenance/reproducibility/promotion/rollback; production telemetry/SLO/incident/restore evidence; then one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Fresh Wardnet GitHub Releases is empty. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
