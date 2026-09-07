# Product and technical gap baseline

Snapshot date: 2026-09-08. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This file is Wardnet's sole commercial/product-technical current-state ledger; predecessor evidence is retained only when it is causal RED/repair lineage and is never promoted as current-head GREEN.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, security evidence lifecycle, Wardnet policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables or treat mutable PR heads as production authority.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` remains the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` remains the EA Decision Plane. Wardnet reads those owners for compatibility and owner handoff only. Wardnet verdicts, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory remains empty for Wardnet, EgressWeave, `context-graph-contracts` and `enterprise-architecture-core`. Mutable foreign-owner heads therefore remain design/compatibility evidence rather than production release authority.

## Protected truth, governance and control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. Main push CI `33998430723`, Scorecard `33998430707`, and scheduled Fuzz on the same protected source have terminal success. Protected truth is therefore stable source evidence, but it is not an immutable Wardnet release identity because GitHub Releases remains empty.

Organization ruleset `18156473` remains active on the default branch and still requires one approving review while naming no required reviewer, code owner or last-push approver. It also requires review-thread resolution plus central OpenCode/review-scheduler/security/Strix/SAST/Noema/CodeQL workflows, forbids deletion/non-fast-forward updates, and exposes `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model the bare approval count/routine bypass is a central governance defect owned by `.github#772`; self-approval, model/bot-as-human approval and routine administrator bypass remain forbidden, and product PRs are not merge-policy probes. The central owner implementation path remains `.github#1644`; source-level reconciliation is not equivalent to live ruleset convergence.

Runner/materialization remains `.github#712` authority. A queued exact-head run is incomplete evidence. Leaf branches do not manufacture success through no-op commits, repeated reruns or temporary verifier workflows; current-head evidence is preserved while owner-plane queue health is repaired. The unchanged #181 head and the #179 RED head have both acquired real `ubuntu-24.04` hosted runners after queue delay, so remaining queue specimens must not be misclassified as a categorical runner-label defect.

Delegated CodeQL terminal-receipt publication remains `.github#1929` authority. Current owner evidence shows the dispatch-identity gate is one serial defect, but not the only one: five runs admitted during a short permissive interval still failed downstream, and cross-repository terminal status publication has separate HTTP 403 evidence. #181 adds an exact sequencing specimen where the compatibility verifier failed before a separate exact-head dispatch job later succeeded, so owner GREEN must publish the authenticated terminal receipt and wake/rerun only the failed verifier without source churn. Repository checkout, language detection, dispatch admission or SARIF work is not equivalent to a terminal current-head CodeQL verdict. Wardnet does not weaken CodeQL or substitute predecessor/native scan evidence for the required delegated receipt.

## Outbound destination reputation

### Proposed architecture #173

#173 remains open/Ready and mechanically mergeable on exact `7d0006b0f1fd3311c891bf359bd0c3e66a1831ec` against protected `main@a52ccd0...`. Its protected-main-relative delta remains four documentation files and the ADR remains Proposed rather than shipped runtime truth.

CI `34025817869`, Security `34025817908`, SAST `34025817866`, and CodeQL `34025817876` are terminal success. Required Noema run `34025816776` is independently non-passing after the central CO sidecar/model phase ended with HTTP 502 and no typed terminal review/provider-unavailable envelope. `.github#1611` owns that model/control-plane repair. No direct-provider fallback or mutable CO source belongs in Wardnet.

EgressWeave #237 remains the canonical Rust-consumer owner path for immutable outbound authorization/evidence. Fresh EgressWeave Releases is empty, so #173 cannot claim production transport integration or consume mutable owner source.

### Reputation contract root #175

#175 remains open/Draft and mergeable at exact `9de0ea568096a18b5c1fc9bc9fce097e08584d44` on protected main. The v1 pure Rust core separates malicious/suspicious/unknown assessment, evidence health, action and reason; rejects unknown wire fields; binds reviewed source/tenant eligibility; gives `ObservableUrl` an 8 KiB bound; and caps `DecisionEnvelopeV1.evidence_refs` at 32 while retaining the generic 64-item list bound.

Exact CI `34071995169`, Fuzz `34071995140`, Security `34071995181`, and SAST `34071995128` are terminal success. Required CodeQL `34071995171` remains terminal failure at the central delegated-verdict publication boundary after language detection/dispatch. #175 stays Draft; no rerun storm, Ready promotion or merge attempt is justified before `.github#1929` proves the unchanged-head terminal receipt path.

### Business authorization child #176

#176 remains open/Draft and mergeable on exact parent `#175@9de0ea568...`. Live head is `5d7166da2034d450f37ab69d37fbbb9d1301e287`. The retained security delta binds business authorization to exact policy/canonicalization/subject/scope/authorization revision/approver-ticket/provenance/validity and `policy_mode=protect`, while preserving the parent 32-reference decision cap and 8 KiB observable-URL invariant.

Earlier ordinary CI exposed independent stale test fixtures missing the already-required `policy_mode`; those failures are causal integration REDs. The post-`0a79c8af...` movement to `5d7166da...` is one additional test-fixture line in `business_authorization_policy_scope.rs`, not a production-authority change. Exact current CI `34125618252` and Fuzz `34125618251` are terminal success. Because root #175 has not integrated into protected truth and current Draft guards do not materialize all security/review lanes, #176 remains Draft and cannot inherit #175's merge evidence.

### Decision freshness child #178

#178 remains open/Draft and mergeable on exact current parent `#176@5d7166da2034d450f37ab69d37fbbb9d1301e287`; live head is `43faf199fde4a74a1f74a3c544f56f5f4e3b23e5`. This confirms the moved parent was adopted non-force rather than treated as a race.

The child retains executed RED `76fa9a0e23a68853f5fa14c6cd9bad10a4b51a7b` and minimal GREEN `4a88e8a7f4b324c2593f3b1a4aa3e5d791fe80e9`, adding deterministic injected-time `DecisionEnvelopeV1::validate_at(now_unix)` without ambient clock or transport authority. Exact-current CI `34130786226` and Fuzz `34130786225` are terminal success on current head. It stays Draft behind #176/#175 and must reacquire its own integration/security/review evidence after protected-parent movement.

### Evidence-snapshot health child #179

#179 remains open/Draft and mergeable on exact parent `#178@43faf199fde4a74a1f74a3c544f56f5f4e3b23e5`; current exact head is causal production candidate `6305284dd3bc9cca5e0d8da3927abf7d5ea075b8`.

The original snapshot prerequisite retained a valid causal RED on `12e2cac1ea56283bf1da992fc625706f9863f68b`: CI `34114942581` / job `101719447845` reached workspace tests after checkout/formatting and failed because `EvidenceSnapshotV1`, `SourceSnapshotV1` and their fail-closed aggregate errors did not yet exist. Production candidate `1702cad...` added the bounded immutable snapshot model; its later exact-head CI `34130881874` exposed a real rustfmt-only defect before tests/Clippy, and `b6fceb680f172393e01fc2a6e27fa54ecf87d9d6` repaired only that layout.

Fresh exact-source review then found a separate snapshot-integrity hole: aggregate validation bound an evidence record to a source snapshot only by `source_id`, so a snapshot could claim `completed_at_unix=T` while including a record Wardnet did not receive until after T. That makes an immutable source generation claim completeness before an included record existed at the admission boundary. Test-only exact `2e027de75c198afd1c032ab4a4e170addd17a9f9` added the hostile regression: source completion at `NOW-30`, matching evidence receipt at `NOW-10`, required `InvalidTimeOrder`.

That RED is now executed rather than queued. CI `34143773398` / rust job `101811265332` acquired a real hosted runner, completed checkout/toolchain/`cargo fmt --check`, then failed in the workspace `Test` step while production remained unchanged. Fuzz `34143773493` is terminal success. Minimal causal GREEN candidate `6305284dd3bc9cca5e0d8da3927abf7d5ea075b8` changes only aggregate validation: it resolves the unique matched source snapshot, preserves `MissingSourceSnapshot`, and rejects `record.received_at_unix > source_snapshot.completed_at_unix` with the existing `InvalidTimeOrder`. Predecessor→fix compare is one production file, +5/-4, with no v1 wire-shape, provider, persistence or transport-authority change.

Exact-current CI `34145736332` and Fuzz `34145736549` have materialized and are queued/non-passing. Current review-thread inventory is empty. No predecessor GREEN transfers; keep Draft behind #178/#176/#175 and reacquire current-head GREEN before any next lifecycle transition.

## Gateway route-segment admission #180 / #181

Protected `main@a52ccd0a...` uses lexical route-prefix matching, so `/api` can capture `/apix` and `/api/admin` can capture `/api/administrator`, binding a request to the wrong route/enforcement/upstream authority before later controls. RFC 3986 §3.3 supplies the segment boundary.

Draft #181 executed the required hostile RED on exact test-only head `93d097626d96f9adaffc267f47be162c397355f3`. CI `34129793580` / rust job `101766902311` reached the new suite after checkout/toolchain/fmt and pre-existing crate tests. Two cases failed exactly on lexical sibling capture while root/trailing-slash compatibility passed; Fuzz `34129793534` was terminal success. This is the causal RED.

Minimal causal GREEN remains exact `fc5645bb2e661f9af63d84b1d08e939b3d7ab3fe`. The production delta changes only `crates/waf-ids-core/src/lib.rs::select_route`: an enabled prefix matches an exact path or slash-delimited descendant, while root `/`, trailing-slash compatibility, disabled-route behavior and longest valid match are preserved. Fresh compare against protected main is `behind_by=0`; effective delta is exactly the 77-line hostile regression plus the 8-line predicate repair. `RouteConfig` and EgressWeave-owned outbound authorization are unchanged.

Exact-current CI `34141693656`, Fuzz `34141693771`, Security Scan `34141693787`, and SAST Semgrep `34141693672` are terminal success on the unchanged head. CodeQL PR `34141693695` is terminal failure only at the delegated current-head verdict boundary: detect succeeded, compatibility failed closed before the separate dispatch job later succeeded. This exact sequencing specimen is handed to `.github#1929`. Keep Draft until the authenticated terminal CodeQL receipt is published/reconciled and governance permits the ordinary path; do not source-churn or broadly rerun to perturb that owner-plane state.

## Context Fabric / EA read-only dependency inventory

Fresh read-only inventory confirms the Context Fabric owners remain active and unreleased rather than blockers to Wardnet-local work. `context-graph-contracts` has a Draft dependency stack rooted at #4 plus Context Assertion successor #21; its accepted integration target is protected `main`, while live metadata still follows protected/default `develop`. Open issue #15 tracks that topology, and no GitHub Release exists. The current Context Assertion candidate therefore remains mutable compatibility evidence only.

`enterprise-architecture-core` likewise has a Draft protected-main reconstruction/projection stack, including #39/#40, and no GitHub Release. EA issue #49 already records the Wardnet outbound-site-reputation projection boundary: Wardnet retains verdict/IOC/incident truth, EgressWeave retains transport authorization, and EA may admit only architecture-relevant released Context Assertion evidence. Wardnet does not mutate either foreign owner.

## Other current security/product lanes

- #167 retains causal GREEN for affirmative MISP `to_ids`, active attribute/object lifecycle and feed/operator DNSBL snapshot ownership. Its remaining delegated CodeQL failure is central-owner evidence, not authority to weaken Wardnet security.
- #170 retains bounded MISP threat-level severity translation behind #167; parent-first protected integration and exact-current revalidation remain mandatory.
- #129 retains structured Agent Artifact Admission. Retrieved-byte integrity, AppGuardrail static analysis, quarantine hostile execution, Noema activation, EgressWeave transport and CO provider orchestration remain separate owner authorities.
- #140 remains the single Runtime Configuration supporting-subdomain owner; #155 remains the fail-closed non-loopback management-authentication prerequisite; #93 remains the deterministic persistence-fault seam; #127 still needs material browser accessibility/state evidence.
- #80 PostgreSQL production authority/RLS/tenant isolation, #81 transactional outbox/idempotent workers, #82 Keyverse identity/approval, #83 bounded distributed admission/trusted attribution, #84 immutable signed release/promotion/rollback, #85 telemetry/SLO/incident/restore, #86 proven Coraza/CRS + Suricata enforcement and #11 deployed Strix attack-path evidence remain release blockers.

## Buyer-visible gap order

Authority and safety remain ahead of feature breadth. Current release-blocking order is: satisfiable protected governance and exact-head control-plane evidence; protected management authentication; outbound reputation contract completion plus immutable EgressWeave authorization/evidence integration; deployed Strix attack-path evidence and proven Coraza/CRS + Suricata enforcement; Agent Artifact Admission; PostgreSQL production authority/RLS/tenant isolation; transactional outbox/idempotent workers; Keyverse-backed identity/approval and distributed admission/trusted attribution; immutable package/image/SBOM/provenance/reproducibility/promotion/rollback; production telemetry/SLO/incident/restore evidence; then one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Fresh Wardnet GitHub Releases is empty. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
