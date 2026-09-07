# Product and technical gap baseline

Snapshot date: 2026-09-07. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before any merge, release, restack or foreign-owner handoff. This file is Wardnet's sole commercial/product-technical current-state ledger; predecessor evidence is retained only when it is causal RED/repair lineage and is never promoted as current-head GREEN.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, security evidence lifecycle, Wardnet policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables or treat mutable PR heads as production authority.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` remains the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` remains the EA Decision Plane. Wardnet reads those owners for compatibility and owner handoff only. Wardnet verdicts, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory remains empty for Wardnet and EgressWeave. Mutable foreign-owner heads therefore remain design/compatibility evidence rather than production release authority.

## Protected truth, governance and control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. The protected branch requires the repository `rust` status. Organization governance still has a structurally incompatible generic approving-review requirement under the declared solo-maintainer model; `.github#772` remains the canonical owner path. Self-approval, model/bot-as-human approval and routine administrator bypass are forbidden, and product PRs are not used as merge-policy probes.

Runner/materialization remains `.github#712` authority. A queued exact-head run is incomplete evidence. Leaf branches do not manufacture success through no-op commits, repeated reruns or temporary verifier workflows; current-head evidence is preserved while owner-plane queue health is repaired.

Delegated CodeQL terminal-receipt publication remains `.github#1929` authority. Repository checkout, language detection or dispatch-request success is not equivalent to a terminal current-head CodeQL verdict. Wardnet does not weaken CodeQL or substitute predecessor/native scan evidence for the required delegated receipt.

## Outbound destination reputation

### Proposed architecture #173

#173 remains open/Ready and mechanically mergeable on exact `7d0006b0f1fd3311c891bf359bd0c3e66a1831ec` against protected `main@a52ccd0...`. Its protected-main-relative delta remains four documentation files and the ADR remains Proposed rather than shipped runtime truth.

CI `34025817869`, Security `34025817908`, SAST `34025817866`, and CodeQL `34025817876` are terminal success. Required Noema run `34025816776` is independently non-passing after the central CO sidecar/model phase ended with HTTP 502 and no typed terminal review/provider-unavailable envelope. `.github#1611` owns that model/control-plane repair. No direct-provider fallback or mutable CO source belongs in Wardnet.

EgressWeave #237 remains the canonical Rust-consumer owner path for immutable outbound authorization/evidence. Fresh EgressWeave Releases is empty, so #173 cannot claim production transport integration or consume mutable owner source.

### Reputation contract root #175

#175 remains open/Draft and mergeable at exact `9de0ea568096a18b5c1fc9bc9fce097e08584d44` on protected main. The v1 pure Rust core separates malicious/suspicious/unknown assessment, evidence health, action and reason; rejects unknown wire fields; binds reviewed source/tenant eligibility; gives `ObservableUrl` an 8 KiB bound; and caps `DecisionEnvelopeV1.evidence_refs` at 32 while retaining the generic 64-item list bound.

Exact CI `34071995169`, Fuzz `34071995140`, Security `34071995181`, and SAST `34071995128` are terminal success. Required CodeQL `34071995171` remains terminal failure at the central delegated-verdict publication boundary after language detection/dispatch. #175 stays Draft; no rerun storm, Ready promotion or merge attempt is justified before `.github#1929` proves the unchanged-head terminal receipt path.

### Business authorization child #176

#176 remains open/Draft and mergeable on exact parent `#175@9de0ea568...`. Live head is now `5d7166da2034d450f37ab69d37fbbb9d1301e287`. The retained security delta binds business authorization to exact policy/canonicalization/subject/scope/authorization revision/approver-ticket/provenance/validity and `policy_mode=protect`, while preserving the parent 32-reference decision cap and 8 KiB observable-URL invariant.

Earlier ordinary CI exposed two independent stale test fixtures missing the already-required `policy_mode`; those failures are causal integration REDs. The post-`0a79c8af...` movement to `5d7166da...` is one additional test-fixture line in `business_authorization_policy_scope.rs`, not a production-authority change. Exact current CI `34125618252` and Fuzz `34125618251` are terminal success. Because root #175 has not integrated into protected truth and current Draft guards do not materialize all security/review lanes, #176 remains Draft and cannot inherit #175's merge evidence.

### Decision freshness child #178

#178 remains open/Draft and mergeable on exact current parent `#176@5d7166da2034d450f37ab69d37fbbb9d1301e287`; live head is `43faf199fde4a74a1f74a3c544f56f5f4e3b23e5`. This confirms the moved parent was adopted non-force rather than treated as a race.

The child retains executed RED `76fa9a0e23a68853f5fa14c6cd9bad10a4b51a7b` and minimal GREEN `4a88e8a7f4b324c2593f3b1a4aa3e5d791fe80e9`, adding deterministic injected-time `DecisionEnvelopeV1::validate_at(now_unix)` without ambient clock or transport authority. It stays Draft behind #176/#175 and must reacquire its own exact-current integration/security/review evidence after each parent movement.

### Evidence-snapshot health child #179

#179 remains open/Draft and mergeable on exact parent `#178@43faf199fde4a74a1f74a3c544f56f5f4e3b23e5`; current head is `1702cad96336ed9d546e6ebbb64c80186605c02d`.

The first test-only RED `af23e1a...` reached CI but stopped at formatting and is not the causal semantic RED. Rustfmt-only head `12e2cac1ea56283bf1da992fc625706f9863f68b` then acquired a real runner in CI `34114942581` / job `101719447845`: checkout and formatting passed, and `cargo test --locked --workspace` failed exactly because `EvidenceSnapshotV1`, `SourceSnapshotV1`, `DuplicateSourceSnapshot`, `MissingSourceSnapshot`, and `DuplicateEvidenceRecord` did not yet exist.

Current production GREEN `1702cad...` adds only the bounded snapshot model and the hostile test. A complete authenticated source generation may contain zero adverse records; duplicate source snapshots, orphan evidence, duplicate producer record identities and future/inverted snapshot time order fail closed. Structural validation does not invent provider availability or transport authorization; later evaluation must compare represented source state with reviewed required-source policy and classify `fresh`/`expired`/`unavailable` without extending TTL.

Fresh current-head CI `34130881874` and Fuzz `34130881882` are queued/non-passing. Production GREEN exists only because a semantic RED executed first; it is not merge authority until exact-current GREEN executes.

## Gateway route-segment admission #180 / #181

Protected `main@a52ccd0a...` still uses lexical route-prefix matching, so `/api` can capture `/apix` and `/api/admin` can capture `/api/administrator`, binding a request to the wrong route/enforcement/upstream authority before later controls. RFC 3986 §3.3 supplies the segment boundary.

Draft #181 is the bounded RED lane at exact `93d097626d96f9adaffc267f47be162c397355f3` on protected main. Its only changed path is `crates/waf-ids-core/tests/route_path_segment_boundary.rs`; production code remains untouched. The hostile regression requires exact/slash-delimited descendant matching, rejects `/apix` and `/api-v2`, requires `/api/administrator` to fall back to `/api` rather than `/api/admin`, and preserves longest valid match, `/` catch-all, trailing-slash prefixes and disabled-route behavior.

Exact CI `34129793580` / rust job `101766902311` is queued pre-checkout with `steps=null`; Fuzz `34129793534`, Security `34129793543`, SAST `34129793525`, and CodeQL `34129793524` are also queued. The exact specimen has been handed to `.github#712`. Production GREEN remains withheld until this hostile RED executes; then only the Wardnet route-selection predicate may change.

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