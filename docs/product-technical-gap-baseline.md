# Product and technical gap baseline

Snapshot date: 2026-09-07. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger, not an archive of predecessor evidence.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation evaluation, security evidence, Wardnet policy decisions and incident/accountability surfaces. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns reusable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables or treat mutable PR heads as production authority.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is never transport authorization: an enforcement point must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither side may override the other's deny.

`context-graph-contracts` remains the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` remains the EA Decision Plane. Wardnet reads those repositories for compatibility and owner handoff only. Wardnet verdicts, destination scores, IOCs and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible Context Assertions/contracts with provenance.

Fresh GitHub Release inventories remain empty for Wardnet, EgressWeave, `contextual-orchestrator`, `quarantine-sandbox-runtime`, `context-graph-contracts`, and `enterprise-architecture-core`. Mutable foreign-owner heads are compatibility evidence only, never release authority.

## Protected truth and governance

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from #171. Organization ruleset `18156473` is active on `~DEFAULT_BRANCH` and still requires `required_approving_review_count=1` while `required_reviewers=[]`, CODEOWNER review is disabled and last-push approval is disabled. It requires review-thread resolution plus central workflows and deletion/non-fast-forward protection, while exposing `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval, bot/model-as-human approval and routine administrator bypass remain forbidden.

`.github#772` remains the canonical governance owner path. GREEN is a centrally repaired solo-maintainer policy that removes the structurally impossible generic approval requirement without weakening deterministic CI/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates. Wardnet does not use a product merge as a governance probe.

Runner/materialization remains `.github#712` authority. Current Wardnet specimens #176, #179 and #181 independently show substantive exact heads waiting pre-execution with queued jobs and `steps=null`; the owner handoff binds repository/PR/head/run/job identity and forbids no-op source churn. Delegated CodeQL terminal-verdict publication remains `.github#1929` authority. Queue/provider absence and missing delegated receipts are incomplete evidence, never leaf GREEN.

## Outbound site reputation

### Proposed architecture #173

#173 remains Ready/open at exact `7d0006b0f1fd3311c891bf359bd0c3e66a1831ec` on protected main. CI `34025817869`, Security `34025817908`, SAST `34025817866`, and CodeQL `34025817876` are terminal success. Required Noema run `34025816776` is independently non-passing: after live-head admission and central CO sidecar provisioning, the model phase ended with HTTP 502 and no typed terminal review/provider-unavailable envelope. `.github#1611` owns that control-plane repair. The ADR remains Proposed and does not claim shipped runtime interception.

EgressWeave issue #237 remains the canonical Rust-consumer owner path for immutable outbound authorization/evidence. Fresh EgressWeave Releases is empty. Wardnet #136/#115 therefore remain preservation/evidence lanes; their local destination/DNS/redirect/proxy/TLS semantics must not become a competing production authority.

### Reputation core #175

#175 remains Draft at exact `9de0ea568096a18b5c1fc9bc9fce097e08584d44` on protected main. The v1 core separates malicious/suspicious/unknown assessment from evidence health, policy action and reason; rejects unknown wire fields; binds source/tenant eligibility; gives `ObservableUrl` an 8 KiB bound; and caps `DecisionEnvelopeV1.evidence_refs` at 32 while preserving the generic 64-item list contract.

Exact CI `34071995169`, Fuzz `34071995140`, Security `34071995181`, and SAST `34071995128` are terminal success. CodeQL `34071995171` is terminal failure only at the central delegated-verdict boundary. No predecessor verdict, repeated rerun, source churn, Ready promotion or merge probe substitutes for an authenticated current-head terminal receipt.

### Business authorization child #176

#176 remains Draft on exact parent `#175@9de0ea568096a18b5c1fc9bc9fce097e08584d44`. The retained security delta binds business authorization to exact policy identity/revision, external canonicalization identity/version, exact subject/scope, immutable authorization revision, approver/ticket/provenance, validity and `policy_mode=protect`; it also retains the parent 32-reference decision cap and 8 KiB observable URL invariant.

Executed integration RED `34090230570` first exposed 12 stale `business_authorization_binding.rs` fixtures missing the required `policy_mode`; minimal test-only repair `e74789d8da2d371965a8575e89b809eedf1df5ff` corrected that shared fixture. Fresh ordinary CI `34099642355` then reached the separate `business_authorization_canonicalization_binding.rs` fixture and exposed the same schema drift there. Current exact head `0a79c8af6943ec7c5263b83be0b2d6a3b2e19b72` changes only that canonicalization fixture by adding `"policy_mode": "protect"`. CI `34115143713` / job `101720086183` and Fuzz `34115143856` are queued/non-passing. The two executed predecessor failures remain causal RED evidence only; current-head GREEN must execute on `0a79c8af...`.

### Decision freshness child #178

#178 retains the executed RED `76fa9a0e23a68853f5fa14c6cd9bad10a4b51a7b` / run `34093010158` and minimal production GREEN `4a88e8a7f4b324c2593f3b1a4aa3e5d791fe80e9`, which adds deterministic injected-time `DecisionEnvelopeV1::validate_at(now_unix)` while preserving structural/archival validation. Current recorded head is `2cd872d14b7d9e194d59163ac0cdafa63757d44f` on old exact parent `#176@e74789d8...`.

Because live parent #176 has advanced to `0a79c8af...`, GitHub now reports #178 non-mergeable against its recorded parent. This is a repair finding, not closure authority: after #176 current-head repair settles, non-force adopt the complete parent delta exactly once, retain the four decision-freshness paths, and reacquire all child gates. Do not duplicate the parent's canonicalization-fixture repair inside the child.

### Evidence snapshot health child #179

#179 remains RED-only on exact parent `#178@2cd872d14b7d9e194d59163ac0cdafa63757d44f`. Current exact head `12e2cac1ea56283bf1da992fc625706f9863f68b` differs from the original RED only by rustfmt and still contains only `crates/wardnet-reputation-core/tests/evidence_snapshot.rs`. The test intentionally imports not-yet-implemented `EvidenceSnapshotV1` / `SourceSnapshotV1` contracts and hostile error variants so a complete authenticated empty snapshot can be distinguished from source unavailability while duplicate source state, orphan evidence, invalid snapshot time and duplicate producer-record identity fail closed.

Current CI `34114942581` / job `101719447845` and Fuzz `34114942437` are queued/non-passing. Production GREEN remains intentionally withheld until this exact RED executes terminally. The current queue specimen is already on `.github#712`; no no-op commit, temporary verifier, selector churn or predecessor result is permitted.

## Gateway route-segment admission #180 / #181

Protected `main@a52ccd0a...` still selects routes with lexical `starts_with(path_prefix)`, so `/api` can capture `/apix` and `/api/admin` can capture `/api/administrator`. This is a Wardnet-owned gateway admission/routing defect because the wrong route can bind enforcement and upstream authority before later controls execute. RFC 3986 §3.3 supplies the path-segment boundary.

Draft #181 is the bounded RED-first repair lane at exact `e8946221bfc6f179348f86a954440573e1421957` on protected main. Its only semantic delta is the hostile route-boundary test; the current head only formats that RED. The regression requires exact or slash-delimited descendant matching, rejects lexical siblings, preserves longest valid match, root catch-all, trailing-slash compatibility and disabled-route behavior. CI `34114761832` / job `101718890656`, Fuzz `34114761835`, SAST `34114761840`, Security `34114761851`, and CodeQL `34114761953` remain queued. Production GREEN is withheld until exact current RED execution; then repair only the route-selection predicate without changing `RouteConfig`, EgressWeave authority or unrelated gateway behavior.

## Other current security/product lanes

- #167 retains causal GREEN for affirmative MISP `to_ids`, active attribute/Object lifecycle and shared feed/operator DNSBL snapshot ownership, including stale withdrawal, restart and persistence rollback/retry. Exact CI/Fuzz/Security/SAST are successful; CodeQL remains a central delegated-verdict failure.
- #170 retains the bounded MISP threat-level severity translation child behind #167; parent-first integration and exact-current revalidation remain mandatory.
- #129 retains Wardnet's structured Agent Artifact Admission authority. Retrieved-byte integrity, AppGuardrail static analysis, quarantine hostile execution, Noema activation, EgressWeave transport and CO provider orchestration remain separate owner authorities.
- #140 remains the single Runtime Configuration supporting-subdomain owner. #155 remains the fail-closed non-loopback management-authentication prerequisite. #93 remains the deterministic persistence-fault seam. #127 still requires real-browser material accessibility/state evidence.
- #80 PostgreSQL production authority/RLS/tenant isolation, #81 transactional outbox/idempotent workers, #82 Keyverse identity/approval, #83 bounded distributed admission/trusted attribution, #84 immutable signed release/promotion/rollback, #85 telemetry/SLO/incident/restore, #86 proven Coraza/CRS + Suricata enforcement and #11 deployed Strix attack-path evidence remain release blockers.

## Context Fabric read-only inventory

Context Graph Contracts remains a foreign single-writer owner. Wardnet consumes only immutable released provider-neutral contract/provenance and does not edit its source or PR state. EA Core remains the foreign single-writer Decision Plane. Wardnet technology/risk lifecycle may be projected through released Context Assertions, but Wardnet verdict/reputation truth stays in Wardnet and EgressWeave remains outbound transport authorization authority. Fresh release inventories for both owner repositories are empty.

## Buyer-visible gap order

Authority and safety remain ahead of feature breadth. The release-blocking sequence is: satisfiable protected governance and exact-head control-plane evidence; protected management authentication; outbound reputation contract completion plus immutable EgressWeave authorization/evidence integration; deployed Strix attack-path evidence and proven Coraza/CRS + Suricata enforcement; Agent Artifact Admission; PostgreSQL production authority/RLS/tenant isolation; transactional outbox/idempotent workers; Keyverse-backed identity/approval and distributed admission/trusted attribution; immutable package/image/SBOM/provenance/reproducibility/promotion/rollback; production telemetry/SLO/incident/restore evidence; then one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not tenant pricing, ARR, billing truth or a reason to change customer-contract thresholds. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence pays for a split.

## Release gate

No Wardnet release is authorized at this snapshot. Release inventory remains empty. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence; immutable package/image/source identity; verified publication; and no unresolved valid security/buyer gaps required for the declared release. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
