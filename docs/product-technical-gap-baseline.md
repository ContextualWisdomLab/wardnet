# Product and technical gap baseline

Snapshot date: 2026-09-07. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger, not an archive of predecessor evidence.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation evaluation, security evidence, Wardnet policy decisions and incident/accountability surfaces. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns reusable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables or treat mutable PR heads as production authority.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is never transport authorization: an enforcement point must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither side may override the other's deny.

`context-graph-contracts` remains the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` remains the EA Decision Plane. Wardnet reads those repositories for compatibility and owner handoff only. Wardnet verdicts, destination scores, IOCs and incidents remain Wardnet truth; EA may project architecture-relevant lifecycle/ownership/risk/remediation context through released Context Assertions but must not promote security verdicts into authoritative architecture facts.

Fresh GitHub Release inventories are empty for Wardnet, EgressWeave, contextual-orchestrator, Context Graph Contracts and EA Core. No mutable foreign-owner head is release authority.

## Protected truth and governance

Protected/default Wardnet truth is `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from #171. Organization ruleset `18156473` still requires `required_approving_review_count=1` while naming no required reviewer/team and requiring neither CODEOWNER nor last-push approval. It retains thread resolution, central required workflows, deletion/non-fast-forward protections and an `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval, bot/model-as-human approval and routine administrator bypass remain forbidden.

`.github#772` is the canonical governance owner path. Its live implementation PR `.github#1644` is currently exact `3b4140e70ddccab619a7c1c8b39a90e526d5b5c3`. `Ruleset Governance Reconcile` run `34053136057` is terminal success on that exact head; Security Scan `34053136034`, SAST `34053136143`, CodeQL `34053136128` and Python Security `34053136122` remain queued. Source convergence is therefore not yet live ruleset convergence and does not authorize Wardnet merge probes.

Runner/materialization remains `.github#712` authority. Current Wardnet #176 exact `3d640f6ca39b0941396641c23310702af3b05180` provides a fresh specimen: causal repair run `34053798438`, job `101541931671`, is queued before checkout with no steps/runner execution. CI `34053798405`, Fuzz `34053798395` and focused verifier `34053798426` are likewise queued. Exact evidence and RED/GREEN acceptance were handed to `.github#712`; Wardnet will not manufacture execution through no-op commits, selector churn, broad reruns or predecessor evidence.

## Outbound site reputation

### Proposed architecture #173

#173 remains the design/ADR foundation on protected-main ancestry. Its contract keeps acquisition and transport ownership outside Wardnet, preserves monitor/shadow operation separately from protect enforcement, and defines business exceptions as bounded Wardnet policy evidence rather than network authority. It is not Accepted or release authority merely because its documentation checks passed.

### Reputation core #175

#175 is Draft at exact `45f2aecd40983b785c1e37489596af641dedcc84` on protected `main@a52ccd0...`. The Wardnet-owned pure contract slice includes explicit tenant scope, source/evidence identity, protect evaluation semantics and fail-closed error precedence without parsing URLs, resolving DNS, choosing proxies, establishing TLS or performing HTTP transport. Exact-head Fuzz `34035086713`, CI `34035086747`, Security `34035086722` and SAST `34035086714` are terminal success. CodeQL `34035086718` fails only at the delegated current-head verdict boundary; focused source-head/error-precedence verifier `34035086703` remains queued. Its temporary verifier must be removed only after exact causal verification completes, followed by fresh exact-head gates on the cleanup head.

### Business authorization child #176

#176 remains Draft and stacked on exact parent #175. Concurrent review work added valid hostile RED `eab552e2e91168267ef16dac71593832a03825ee`: `DecisionEnvelopeV1` could encode an enforceable reputation decision without explicitly binding the policy execution mode, even though Proposed #173 distinguishes protect authorization from monitor/shadow `would_allow`/`would_deny` evidence. An enforceable v1 envelope must therefore fail closed unless it is explicitly bound to protect mode; monitor mode must never deserialize/validate as protect authority merely because assessment/action fields are otherwise coherent.

Current exact #176 head is `3d640f6ca39b0941396641c23310702af3b05180`. Its source-bounded one-shot repair first requires the hostile missing-mode test to fail, then minimally adds explicit `policy_mode`, rejects non-protect decision envelopes, updates hostile/positive fixtures and TRACEABILITY, runs focused/crate/workspace tests plus strict Clippy/format, removes itself, verifies the remote branch still equals the triggering SHA and pushes non-force. The repair has materialized but is still queued pre-checkout, so the RED is source-grounded and the intended causal GREEN is not yet claimed. No temporary workflow may become permanent product truth.

EgressWeave issue #237 remains the canonical Rust-consumer owner path for immutable outbound authorization/evidence. EgressWeave still has no GitHub Release. Wardnet #136/#115 stay preservation/evidence lanes until a compatible immutable owner release exists; do not promote their local destination/DNS/redirect/proxy/TLS implementation.

## Other current security/product lanes

- **#167 MISP admission + shared DNSBL ownership** — Draft exact `0c83cd5956f512d79c6600e823fcfa6d6f32af4e` on protected main. CI `34000987921`, Fuzz `34000988028`, Security `34000987843` and SAST `34000987891` are terminal success; CodeQL `34000987911` fails only at the central delegated verdict boundary. Source GREEN covers affirmative MISP `to_ids`, active attribute/Object lifecycle, shared feed/operator DNSBL ownership, stale withdrawal, restart and persistence rollback/retry. Keep #168/#172 open until the complete delta reaches protected truth.
- **#170 MISP threat-level severity** — Draft exact `2c8d499a5772b0be64d7cc3fc42ed2825ba1499e` on exact #167 parent. Its effective child delta is only severity source/docs/tests and current CI/Fuzz are terminal success. It cannot integrate before #167; after parent protection it must non-force adopt/retarget and reacquire then-live gates.
- **#174 CodeQL SARIF uploader** — Draft exact `028caa05167f9e8f2589b681a8f79c633f406c30`, one path/one commit on protected main. CI/Security/SAST are terminal success; CodeQL is fail-closed at the delegated verdict boundary. Central owner path is `.github#1929`; source churn is not a substitute.
- **#129 Agent Artifact Admission** — preserves Wardnet's structured pre-execution admission authority only. Downloaded-byte integrity, static scanning, hostile execution, activation and provider orchestration remain separate owner authorities. It is not complete until its exact current candidate reaches protected truth with all then-live gates.
- **#140 Runtime Configuration** remains the single Wardnet supporting/bootstrap owner; dependent trusted-proxy/admission work must consume it rather than create competing environment/configuration authority.
- **#155 management authentication** remains the fail-closed non-loopback management prerequisite.
- **#93 deterministic persistence fault seam** remains the owner-correct replacement for permission-dependent failure testing.
- **#95 Coraza/CRS mixed aggregate** is preservation only. Reconstruct unique proven-engine WAF/IDS evidence into a bounded #86 successor rather than merge unrelated egress/database/release/auth changes.
- **#88 contextual-orchestrator/LiteLLM aggregate** is preservation only until an immutable CO API/client/schema/Agent release exists. Wardnet must retain only its own request/framing/header/streaming security evidence through a thin released ACL and remove provider/model/routing ownership.

## Context Fabric read-only inventory

Context Graph Contracts still has live default `develop`; protected `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` remains the current owner line while accepted future integration is protected `main`. Root #4 is exact `5117383ac15cdfe3813340455cd99b92937ef47c`; Context Assertion child #21 is Draft/unreleased at exact `1783ff4563f12ac5dca69b5c71e5a6e3b4f96d8e` with no exact-head workflow runs. Its candidate preserves canonical CloudEvent identity, source authority, all six truth dispositions, valid/system time, provenance and explicit schema/profile/admission receipt identity. Wardnet must fail closed until equivalent behavior is published from an immutable protected-source release.

EA Core likewise still has live default `develop`; protected `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece` remains the current owner line. DDD root #39 is exact `c063570bd9177578fa75be69defd81c99e6ba2f3`; Context Fabric projection child #40 is Draft at exact `aa217ba09d9d944f18f479b355f50af61188de69` and remains unreleased/non-passing. EA issue #49 is the explicit Wardnet outbound-reputation owner path: only released Context Assertions may project architecture state; Wardnet verdict/reputation truth stays in Wardnet and EgressWeave remains outbound transport authorization authority.

Branch/default/protection repair for CGC/EA remains central/owner automation work, not a Wardnet source change or user choice.

## Buyer-visible gap order

Authority and safety remain ahead of feature breadth. The next release-blocking sequence is: satisfiable protected governance and exact-head control-plane evidence; protected management authentication; outbound reputation contract completion plus immutable EgressWeave authorization/evidence integration; deployed Strix attack-path evidence and proven Coraza/CRS + Suricata enforcement; Agent Artifact Admission; PostgreSQL production authority/RLS/tenant isolation; transactional outbox/idempotent workers; Keyverse-backed identity/approval and distributed admission/trusted attribution; immutable package/image/SBOM/provenance/reproducibility/promotion/rollback; production telemetry/SLO/incident/restore evidence; then one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not tenant pricing, ARR, billing truth or a reason to change customer-contract thresholds. Root `src/lib.rs` remains modularity pressure, not proof that another deployable service boundary is justified; prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence pays for a split.

## Release gate

No Wardnet release is authorized at this snapshot. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence; immutable package/image/source identity; verified publication; and no unresolved valid security/buyer gaps required for the declared release. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.