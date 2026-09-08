# Product and technical gap baseline

Snapshot date: 2026-09-08. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; PR and issue bodies retain detailed RED→GREEN receipts.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory remains empty for Wardnet, EgressWeave, `contextual-orchestrator`, `quarantine-sandbox-runtime`, `context-graph-contracts` and `enterprise-architecture-core`. Mutable owner PR heads are design/compatibility evidence, not immutable production authority.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. There is no immutable Wardnet GitHub Release, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active and still requires one generic approving review while naming no required reviewer/team/code-owner/last-push reviewer. It also exposes `OrganizationAdmin/always` bypass. `.github#772` remains the canonical solo-maintainer governance repair. Self-approval, model/bot-as-human approval and routine or implicit administrator bypass remain forbidden; deterministic workflow/security/coverage/thread/branch-integrity gates stay fail closed.

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0` is incomplete evidence, not by itself a leaf-source defect. The earlier #140 `e2822571...` CI specimen later acquired GitHub-hosted runner `1001777797`; its `.github#712` handoff was updated so the pre-checkout state is not misreported as a persistent runner-label defect. No-op source commits or runner-label churn are not default repairs.

Delegated CodeQL remains a central producer/receipt path. Canonical repair PR `.github#1902` remains Draft/mergeable and has advanced ordinarily/non-force to exact `930797366572053b3c2b770f170d596f3f834d82` on protected `.github main@7fd571dbcdbae6acf29d8f4ee704d7ba6297e4db`. The current owner repair additionally closes a GitHub `repository_dispatch.client_payload` cardinality defect: run `34214980549` reached OIDC/App-token success but HTTP 422 because eleven properties were sent, and RED `310e9e60...` / run `34217639402` reproduced `11 <= 10`; the repair groups mode plus exact failed-job identities under `rerun_request` while preserving compatibility for already queued payloads. Fresh exact-owner runs on `930797366...` show Security Scan `34218623394` and Agent Review Runtime Quality `34218623442` terminal **SUCCESS**, while Python Security `34218623479` and CodeQL `34218623513` remain queued and SAST Semgrep `34218623588` remains in progress. No predecessor owner result is promoted. Cross-repository status publication remains `.github#1929` authority.

Wardnet #140 supplies an exact cross-repository consumer specimen on unchanged `93a51f9706cf8a9704f69aed4a69df5be16c84e4`: CodeQL run `34214356266` detected the language successfully, compatibility job `102025386815` acquired hosted runner `1001778528`, read the current-head verdict successfully, then failed closed before later dispatch job `102029295622` successfully dispatched on hosted runner `1001778625`. A fresh combined-status read still contains no authenticated `codeql-dispatch/actions` terminal receipt on the Wardnet SHA. Exact evidence and owner GREEN acceptance were handed to `.github#1929` comment `5584141703`. This is neither Wardnet source failure nor runner starvation and does not authorize no-op source churn, synthetic status, predecessor receipt, broad rerun, or gate weakening.

## Outbound destination reputation stack

### Architecture and pure core

#173 remains Proposed architecture for the Wardnet-owned reputation engine. It does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement URL/DNS/peer/redirect/proxy/TLS/resource authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent Draft evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 explicit evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid enforcement rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. Exact-head child results do not transfer after parent movement.

### Durable ABA authority: #192 under #80

#191 preserves the executed hostile RED proving a current-only lifecycle cursor cannot prevent historical opaque source-generation ABA reuse after multiple transitions. The causal production authority is durable state, not a larger in-memory recent-token cache.

P0 #192 requires tenant-scoped durable uniqueness for both `(source_id, source_generation)` and `(source_id, source_generation_ordinal)`, atomically coupled with producer lifecycle state, accepted immutable evidence snapshot, completeness/pagination proof and last-known-good publication. Real PostgreSQL acceptance must cover `8@8 -> 9@9 -> 8@10`, ordinal collision, concurrent writers, crash/retry/idempotency, default-deny RLS, pooled-context isolation, migrations and backup/restore survival.

#80 remains canonical for the broader production PostgreSQL repository/transaction/migration/RLS/recovery boundary. Stale mixed #95 is preservation evidence only and must not be imported wholesale.

### Production-state prerequisites: #140 → #193 → #194

#140 is the canonical Runtime Configuration foundation. Fresh concurrent review advanced its hostile syntax coverage beyond the prior `3d933140...` candidate. Test-only `0f9ad5ce5fe0b392b55d9c3618454b6010e11dc7` added two equivalent Rust root-alias bypasses: `use std::{self as standard}; ... standard::env::var(...)` and `extern crate std as standard; ...`. Hosted CI `34212119942`, rust job `102015307615`, acquired a GitHub-hosted runner, passed checkout/toolchain/format and failed in `Test`, establishing a semantic RED against unchanged production. `7765da43d7d1a8063061064fdf222e66c0b0983b` repaired the extern-crate form; immediate source verification showed grouped `self as ...` was still uncovered, so `e2822571e0c7029022548f5850b5b448ef51ba3a` added the missing grouped-root predicate.

Exact `e2822571...` then acquired hosted runner `1001777797` in CI `34213607339`, rust job `102020076519`, checked out the exact merge candidate and failed only `cargo fmt --check`: rustfmt required the final EOF newline in `src/runtime_config.rs`, so Test/Clippy were skipped. Current exact child `93a51f9706cf8a9704f69aed4a69df5be16c84e4` adds only that formatting newline. Protected base remains `main@a52ccd0...`; re-read candidate-base compatibility immediately before any readiness or merge transition.

The former non-terminal #140 snapshot is superseded. On unchanged exact `93a51f9706cf8a9704f69aed4a69df5be16c84e4`, CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311`, and SAST Semgrep `34214356338` are terminal **SUCCESS**. CodeQL PR `34214356266` remains terminal **FAILURE** only at the delegated verdict/publication-settlement boundary described above. Fresh review-thread inventory is fully resolved; submitted bot/model reviews remain COMMENTED/advisory and do not satisfy human approval. #140 therefore stays Draft: Wardnet-owned source/security checks are exact-head GREEN, but CodeQL and the live solo-maintainer governance defect remain non-passing. No predecessor GREEN, no source churn, no routine bypass.

#193 is a Draft child of #140 that makes deployment intent and mutable-state authority explicit. Production requires an explicit PostgreSQL authority declaration and cannot silently fall back to file/memory state; PostgreSQL selection remains fail closed until #80's durable adapter exists. Exact head `88e54cd18fb686a6b61525c400531820f7a014b4` has repository-owned CI/Fuzz GREEN, but those stacked results will not transfer when #140 moves into protected truth.

#194 is the next Draft child and owns PostgreSQL DSN bootstrap secrecy. Semantic RED `9436ad4c7729f1a6a9f6542aa2919b9ae0e45012` / CI `34185447086` reached locked workspace tests with production source unchanged. Minimal repair exact `eeddc49170b30169bb3fd6a918ee91a74e1ce9f3` keeps `postgres_dsn` inside `CredentialRegistry`, applies credentials-file-over-environment precedence per key, omits empty DSNs, and deliberately keeps `CredentialSource` limited to administrator-auth provenance so support/health surfaces do not become generic secret-presence side channels. This slice opens no database connection and claims no durability. Exact-head CI `34189654335` / rust `101944919704` and Fuzz `34189654329` / job `101944919192` are terminal **SUCCESS** on the unchanged repair head; those stacked results do not transfer across parent integration.

## Gateway and Agent Artifact Admission security lanes

#181 owns the route path-segment boundary repair. Its hostile RED proves raw lexical prefix matching lets `/api` capture `/apix` and `/api/admin` capture `/api/administrator`; the minimal candidate uses exact-or-slash-descendant matching while preserving root, trailing slash, disabled routes and longest valid match. Repository/Fuzz/Security/SAST are GREEN on its unchanged code head; delegated CodeQL receipt reconciliation remains central-owner evidence.

#129 remains the Rust-first Agent Artifact Admission lane. It is pre-execution policy/evidence authority only: retrieved-byte integrity, AppGuardrail analysis, quarantine execution, Noema activation, EgressWeave transport and CO provider orchestration remain separate canonical authorities. Its unchanged code head has repository/Fuzz/Security/SAST GREEN and the same central delegated-CodeQL failure class.

#155 remains the fail-closed management-authentication prerequisite for non-loopback exposure. #93 remains the deterministic persistence-fault seam. #127 remains incomplete until the material embedded admin-console accessibility change has real-browser current-head keyboard/focus/name/role/value, responsive and state evidence rather than source-string tests alone.

#77 remains the Rust-toolchain/reproducibility prerequisite; #164 remains its dependent release-evidence lane and cannot publish from a feature branch or transfer predecessor SBOM/provenance evidence after restack.

## Other preservation and integration lanes

#165 is the canonical trusted forwarded-client attribution slice for #83 and remains Draft behind #140 plus preservation transfer from #157. It owns direct-peer trust, right-to-left forwarded-chain attribution, observed mapped-address normalization and fail-closed trusted-CIDR grammar; broader local limiter cardinality and distributed admission remain separate #83 work.

#135 preserves the bounded local-limiter cardinality/expiry/stable-429 slice but was incorrectly Ready while carrying overlapping Runtime Configuration and trusted-proxy prerequisite authority. It is Draft at exact `b45e99d4ddd5448238aa58d272409968127df08b`; its unique limiter delta must be reconstructed after #140 and #165 reach protected truth rather than integrating a second configuration/trusted-attribution foundation.

#167/#170 retain MISP/DNSBL source-ownership and source-severity semantics. #115/#136 preserve threat-feed and outbound-policy hostile consumer evidence but cannot merge a second EgressWeave transport-policy authority. #88 preserves credential-guard evidence pending an immutable compatible contextual-orchestrator boundary rather than retaining LiteLLM/provider-routing authority in Wardnet. #90/#95/#112 are preservation lanes whose valid unique Wardnet deltas must be reconstructed from current protected truth instead of mechanically merging stale aggregate source.

#134 support-bundle contract, #162 customer-contract-vs-USD-20B-quality authority separation, and #144 Kubernetes source-path migration have non-force adopted protected #171 and retain bounded deltas. Their repository/security lanes are GREEN where Wardnet owns them; code-bearing CodeQL failures remain central delegated-receipt specimens rather than reasons for leaf churn.

## Release blockers and buyer-visible gap order

Authority and safety remain ahead of feature breadth. Current release-blocking order is:

1. satisfiable protected governance and authenticated exact-head central evidence;
2. protected management authentication and Runtime Configuration truth;
3. #80/#192 PostgreSQL production authority, tenant/RLS isolation and crash-safe reputation-history publication, with #193/#194 prerequisites integrated first;
4. trusted client attribution and bounded/distributed admission reconstructed without duplicate #140/#165 authority;
5. immutable EgressWeave authorization/evidence integration for outbound transport;
6. deployed attack-path evidence and proven Coraza/CRS + Suricata enforcement without inventing substitute detection authority;
7. Agent Artifact Admission integrated with its released foreign-owner ports;
8. transactional outbox/idempotent workers, Keyverse-backed identity/approval and distributed admission/trusted attribution;
9. immutable package/image/SBOM/provenance/reproducibility/promotion/rollback plus production telemetry/SLO/incident/restore evidence;
10. one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
