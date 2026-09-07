# Product and technical gap baseline

Snapshot date: 2026-09-07. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger, not an archive of predecessor evidence.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation evaluation, security evidence, Wardnet policy decisions and incident/accountability surfaces. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns reusable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables or treat mutable PR heads as production authority.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is never transport authorization: an enforcement point must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither side may override the other's deny.

`context-graph-contracts` remains the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` remains the EA Decision Plane. Wardnet reads those repositories for compatibility and owner handoff only. Wardnet verdicts, destination scores, IOCs and incidents remain Wardnet truth; EA may project architecture-relevant lifecycle/ownership/risk/remediation context through released Context Assertions but must not promote security verdicts into authoritative architecture facts.

Fresh GitHub Release inventories remain empty for Wardnet and EgressWeave. Mutable foreign-owner heads are compatibility evidence only, never release authority.

## Protected truth and governance

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from #171. Organization ruleset `18156473` is active on `~DEFAULT_BRANCH` and still requires `required_approving_review_count=1` while `required_reviewers=[]`, CODEOWNER review is disabled and last-push approval is disabled. It also requires review-thread resolution plus central workflows, deletion and non-fast-forward protection, while exposing `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval, bot/model-as-human approval and routine administrator bypass remain forbidden.

`.github#772` is the canonical governance owner path. The causal GREEN remains a centrally repaired solo-maintainer policy in which the structurally impossible generic approval count is removed or replaced without weakening deterministic CI/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity evidence. Wardnet does not mutate that foreign owner surface or use a product merge as a governance probe. Current owner-plane PR `.github#1644@5f5d7a9e849984c052c72a08eba34f68cb694024` remains Draft and non-passing; source integration alone is not live ruleset convergence.

Runner/materialization remains `.github#712` authority. Evidence must distinguish repository source defects from pre-checkout `runner_id=0` jobs, unsupported runner labels, stale/predecessor run identity and delegated current-head verdict production. Queue or provider absence is incomplete evidence, never success and never a reason for no-op source churn.

Delegated CodeQL failure ownership remains central under `.github#1929` and verified successors. Current Wardnet specimens show source checkout, language detection, hosted-runner acquisition and current-head dispatch can succeed while terminal delegated-verdict enforcement fails. Wardnet requires an authenticated terminal verdict bound to the exact repository/head/language/run/job tuple and does not weaken CodeQL or promote predecessor results.

## Outbound site reputation

### Proposed architecture #173

#173 remains the design/ADR foundation on protected-main ancestry. Its contract keeps acquisition and transport ownership outside Wardnet, preserves monitor/shadow operation separately from protect enforcement, and defines business exceptions as bounded Wardnet policy evidence rather than network authority. Exact head `7d0006b0f1fd3311c891bf359bd0c3e66a1831ec` is Ready/mechanically mergeable with CI `34025817869`, Security `34025817908`, SAST `34025817866` and CodeQL `34025817876` terminal success and no unresolved inline review thread. It is still Proposed rather than shipped runtime truth. Ordinary protected integration remains governance-bound; an immutable compatible EgressWeave release is still required before runtime transport composition can be claimed.

### Reputation core #175

#175 remains Draft on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Current cleanup head is exact `9de0ea568096a18b5c1fc9bc9fce097e08584d44`, open and mechanically mergeable. The v1 core separates malicious/suspicious/unknown assessment from evidence health, action and reason; rejects unknown wire fields; binds reviewed source tenant eligibility; gives `ObservableUrl` an 8 KiB bound while ordinary bounded text remains 1 KiB; and caps `DecisionEnvelopeV1.evidence_refs` at 32 while preserving the generic 64-item list contract.

The invalid temporary-verifier selector defect from #177 was repaired with supported `macos-15`, exact-source assertions and PR-scoped concurrency; the focused regressions reached terminal GREEN and the purpose-complete verifier definitions were removed. Current exact-head repository evidence is CI `34071995169` SUCCESS, Fuzz `34071995140` SUCCESS, Security Scan `34071995181` SUCCESS and SAST Semgrep `34071995128` SUCCESS. CodeQL PR `34071995171` was retried after central `.github` CodeQL dispatch compatibility repair advanced protected truth. Attempt 2 kept exact head `9de0ea568096a18b5c1fc9bc9fce097e08584d44`: detector job `101668535462` completed SUCCESS, while required `CodeQL compatibility analysis (actions)` job `101668534364` remains queued before checkout with `steps=[]` and `runner_id=0` on `ubuntu-24.04`. This is incomplete current-head evidence, not a Wardnet source failure or passing result. Fresh inline review-thread inventory remains zero unresolved. No repeated rerun, no-op redispatch, predecessor-verdict transfer, Ready promotion or merge probe is authorized.

### Business authorization child #176

#176 remains an intentional Draft child of #175 and must not become an independent integration lane before #175 reaches protected truth. Its retained security delta binds business authorization to exact policy identity/revision, external canonicalization identity/version, exact destination subject/scope, immutable authorization revision, approver/ticket/provenance, validity and protect-mode execution. Existing RED→GREEN lineage also rejects non-exact authorization scope and non-`protect` decision envelopes.

Fresh parent/child comparison found the historical child had lost #175's 32-reference `DecisionEnvelopeV1.evidence_refs` invariant and retained only the generic 64-item list bound. The child was reconstructed non-force onto exact live parent `9de0ea568096a18b5c1fc9bc9fce097e08584d44`, producing an ahead-only stack with merge base exactly that parent. Hostile exact-head RED `9a1ddefc1413a7d8ba23ed042adb82e950dd41af`, run `34089437377` / job `101639765816`, proved the defect after exact checkout/source assertion/formatting passed and the 33-reference regression failed as intended.

Minimal causal production GREEN `b0219b33462f89c82b935d80536c494d1e4f7df6` restores only the 32-reference decision cap. Exact run `34089668753` / job `101640426155` completed success. The remaining valid parent `ObservableUrl` 8 KiB production invariant was adopted at `68318c0382f1d2bc7e00d1354effebd290cdfc51`, and the parent regression `enforces_declared_observable_url_v1_limit` was inherited at `191ee5f86b8d210767d39b4dfee1585c54261d79`. Combined focused verification on exact `ba28b5188be2c307599886488a5f8689664088f8`, run `34090068906` / job `101641566263`, completed GREEN for `cargo fmt --check` plus the complete `contract` and `decision_evidence_ref_limit` test targets; the temporary verifier was then deleted as purpose-complete.

Ordinary CI on cleanup head `35c2fc98ff1cd1257fa77a273dbe4f628ce6ba52` later acquired hosted runner `1001737477`, checked out synthetic candidate merge `6dd8c6f9e4b70e0a6ca3fd8d096f6f6140f61b3e`, passed formatting, then produced a real integration RED in `cargo test --locked --workspace`: 12 of 13 `business_authorization_binding.rs` cases failed before their assertions because the shared JSON fixture omitted the now-required `DecisionEnvelopeV1.policy_mode` field. This reclassifies the earlier queue-only snapshot as a leaf test-fixture drift once execution materialized; it is not a runner blocker.

Minimal causal repair `e74789d8da2d371965a8575e89b809eedf1df5ff` changes only the shared hostile/positive authorization fixture by adding `"policy_mode": "protect"`, matching the production enum and the already-proven v1 protect-only invariant without weakening production validation. #176 now points to exact `e74789d8...` on parent `#175@9de0ea568...`; fresh CI `34099642355` and Fuzz `34099642302` are current-head evidence and remain queued at this snapshot. The previous `35c2fc98...` CI failure remains the causal RED only; GREEN must come from the new unchanged head.

After #175 reaches protected `main`, re-read every intervening protected parent delta, non-force adopt the exact protected parent while retaining only the valid authorization/policy-mode/evidence-cap child slice, and reacquire every then-live repository/security/CodeQL/review/thread/candidate-base/governance gate before Ready/merge.

### Decision freshness child #178

#178 is a Draft child behind #176. Its security purpose is unchanged: `DecisionEnvelopeV1::validate()` remains structural/archival validation, while live admission gets one deterministic injected-time freshness check instead of ambient clock I/O or duplicated adapter checks.

The executed hostile RED is exact `76fa9a0e23a68853f5fa14c6cd9bad10a4b51a7b`, focused run `34093010158` / job `101650328620`: exact checkout and formatting succeeded, then `decision_freshness` failed because the live-use API did not exist. Minimal production GREEN `4a88e8a7f4b324c2593f3b1a4aa3e5d791fe80e9` adds `DecisionEnvelopeV1::validate_at(now_unix)`, reuses structural validation, rejects `now < evaluated_at_unix` or `now > expires_at_unix`, preserves inclusive boundaries and returns a separate typed live-validation error. Exact focused GREEN `34094330274` / job `101654415114` passed on `4a88e8a...`; the purpose-complete verifier was removed at cleanup head `d17928645d6fe175935e2277d161daea909cee7e`.

When parent #176 advanced with the test-only fixture repair, #178 adopted that exact parent non-force through ordinary two-parent merge commit `2cd872d14b7d9e194d59163ac0cdafa63757d44f`, preserving the child tree and adding only the parent fixture blob. PR base now resolves to `#176@e74789d8da2d371965a8575e89b809eedf1df5ff`; effective child delta remains the four decision-freshness source/docs/test paths. Fresh exact-head CI `34099813695` and Fuzz `34099813773` are queued at this snapshot. Historical focused GREEN proves the causal behavior but does not substitute for current cleanup/restack repository gates.

The live-validation contract must not authenticate the envelope, establish audience binding, parse/authorize URLs, resolve DNS/peers, follow redirects, choose proxies/TLS or claim transport enforcement. Keep #178 Draft behind #176 and reacquire all exact-current evidence after every parent movement.

EgressWeave issue #237 remains the canonical Rust-consumer owner path for immutable outbound authorization/evidence. EgressWeave still has no GitHub Release. Wardnet #136/#115 remain preservation/evidence lanes until a compatible immutable owner release exists; do not promote their local destination/DNS/redirect/proxy/TLS implementation.

## Other current security/product lanes

- **#166 exact-source CI evidence/queue repair** — exact `e00d61c994d3b1c2b7923bb1b781c1e06d32aae4` on protected `main@a52ccd0...`. CI/Fuzz/Security/SAST are terminal success; CodeQL remains fail-closed at delegated terminal-verdict enforcement.
- **#167 MISP admission + shared DNSBL ownership** — Draft exact `0c83cd5956f512d79c6600e823fcfa6d6f32af4e` on protected main. CI/Fuzz/Security/SAST are terminal success; CodeQL fails only at the central delegated verdict boundary. Source GREEN covers affirmative MISP `to_ids`, active attribute/Object lifecycle, shared feed/operator DNSBL ownership, stale withdrawal, restart and persistence rollback/retry.
- **#170 MISP threat-level severity** — Draft exact `2c8d499a5772b0be64d7cc3fc42ed2825ba1499e` on exact #167 parent. Its effective child delta is severity source/docs/tests and current CI/Fuzz are terminal success. It cannot integrate before #167; after parent protection it must non-force adopt/retarget and reacquire then-live gates.
- **#174 CodeQL SARIF uploader** — Draft exact `028caa05167f9e8f2589b681a8f79c633f406c30`, one path/one commit on protected main. CI/Security/SAST are terminal success; CodeQL is fail-closed at delegated verdict production.
- **#129 Agent Artifact Admission** — exact `14c0af32e7e4f68c682d55a1b1117629fa940336` preserves Wardnet's structured pre-execution admission authority only. CI/Fuzz/Security/Semgrep are terminal success; CodeQL fails only at delegated terminal-verdict enforcement. Downloaded-byte integrity, static scanning, hostile execution, activation and provider orchestration remain separate owner authorities.
- **#140 Runtime Configuration** — exact `a904558b79ef392515dff4b501692112ad6beabf` is the single Wardnet supporting/bootstrap owner. CI/Fuzz/Security/SAST are terminal success; CodeQL is the sole failing exact-head lane after current-head dispatch. Dependent trusted-proxy/admission work must consume it rather than create competing configuration authority.
- **#155 management authentication** remains the fail-closed non-loopback management prerequisite and must integrate before remote administration can be considered release-ready.
- **#93 deterministic persistence fault seam** remains the owner-correct replacement for permission-dependent failure testing.
- **#95 Coraza/CRS mixed aggregate** is preservation only. Reconstruct unique proven-engine WAF/IDS evidence into a bounded successor rather than merge unrelated egress/database/release/auth changes.
- **#88 contextual-orchestrator/LiteLLM aggregate** is preservation only until an immutable CO API/client/schema/Agent release exists. Wardnet must retain only its request/framing/header/streaming security evidence through a thin released ACL and remove provider/model/routing ownership.
- **#127 material admin-console accessibility** remains Draft because real-browser keyboard/focus/name/role/value, responsive and state evidence is still required; source-string checks alone are insufficient.

## Context Fabric read-only inventory

Context Graph Contracts remains a foreign single-writer owner. Wardnet consumes only immutable released provider-neutral contract/provenance and does not edit its source or PR state. Context Assertion and default/protection work remain unreleased owner-plane state; no mutable foreign head is Wardnet production authority.

EA Core likewise remains a foreign single-writer Decision Plane. Wardnet technology/risk lifecycle may be projected through released Context Assertions, but Wardnet verdict/reputation truth stays in Wardnet and EgressWeave remains outbound transport authorization authority. Branch/default/protection repair for CGC/EA remains owner automation work, not a Wardnet source change or user choice.

## Buyer-visible gap order

Authority and safety remain ahead of feature breadth. The next release-blocking sequence is: satisfiable protected governance and exact-head control-plane evidence; protected management authentication; outbound reputation contract completion plus immutable EgressWeave authorization/evidence integration; deployed Strix attack-path evidence and proven Coraza/CRS + Suricata enforcement; Agent Artifact Admission; PostgreSQL production authority/RLS/tenant isolation; transactional outbox/idempotent workers; Keyverse-backed identity/approval and distributed admission/trusted attribution; immutable package/image/SBOM/provenance/reproducibility/promotion/rollback; production telemetry/SLO/incident/restore evidence; then one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not tenant pricing, ARR, billing truth or a reason to change customer-contract thresholds. Root `src/lib.rs` remains modularity pressure, not proof that another deployable service boundary is justified; prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence pays for a split.

## Release gate

No Wardnet release is authorized at this snapshot. Release inventory remains empty. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence; immutable package/image/source identity; verified publication; and no unresolved valid security/buyer gaps required for the declared release. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
