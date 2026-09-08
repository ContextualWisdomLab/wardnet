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

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0` is incomplete evidence, not by itself a leaf-source defect. The earlier #140 `e2822571...` specimen later acquired GitHub-hosted runner `1001777797`. Draft #207 exact `80af90273def9f72042ef378d3a74ea31b8a6de6` likewise initially materialized as CI `34244982960` / rust job `102124556929` with `runner_id=0`, was handed to `.github#712`, then acquired hosted runner `1001788214` and completed SUCCESS without no-op source or selector churn. These resolved specimens must not be misreported as persistent runner-label defects.

Delegated CodeQL remains a central producer/receipt path. `.github#1902` is still Draft and its actual live head is `c8d7caa0d699cec0200815fdfbca8bc0b2f7a4ec` on protected `.github main@7fd571dbcdbae6acf29d8f4ee704d7ba6297e4db`; older exact-head text inside that PR body is historical rather than live identity. Ready `.github#2040` is the current combined producer/handler successor at `d7bb95f6d6ca705725596df5170d6e1345080535`, preserving the evidence-complete producer and backward-compatible handler/recovery contract. Its fresh exact-head checks and qualifying independent review remain owner-side integration gates. Cross-repository terminal-status publication and consumer authentication remain `.github#1929` authority. These mutable owner repairs are compatibility evidence only, not Wardnet release dependencies, and exact owner state must be re-read at admission rather than copied as durable product truth.

Wardnet #140 supplies an exact cross-repository consumer specimen on unchanged `93a51f9706cf8a9704f69aed4a69df5be16c84e4`: CodeQL run `34214356266` detected the language successfully, compatibility job `102025386815` acquired hosted runner `1001778528`, read the current-head verdict successfully, then failed closed before later dispatch job `102029295622` successfully dispatched on hosted runner `1001778625`. A fresh combined-status read still contains no authenticated `codeql-dispatch/actions` terminal receipt on the Wardnet SHA. Exact evidence and owner GREEN acceptance were handed to `.github#1929`. This is neither Wardnet source failure nor runner starvation and does not authorize no-op source churn, synthetic status, predecessor receipt, broad rerun, or gate weakening.

## Outbound destination reputation stack

### Architecture and pure core

#173 remains Proposed architecture for the Wardnet-owned reputation engine. It does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement URL/DNS/peer/redirect/proxy/TLS/resource authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent Draft evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 explicit evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid enforcement rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. Exact-head child results do not transfer after parent movement.

### Durable ABA authority: #192 under #80

#191 preserves the executed hostile RED proving a current-only lifecycle cursor cannot prevent historical opaque source-generation ABA reuse after multiple transitions. The causal production authority is durable state, not a larger in-memory recent-token cache.

P0 #192 requires tenant-scoped durable uniqueness for both `(source_id, source_generation)` and `(source_id, source_generation_ordinal)`, atomically coupled with producer lifecycle state, accepted immutable evidence snapshot, completeness/pagination proof and last-known-good publication. The implemented Draft stack now executes the PostgreSQL 18.4 generation-admission and publication parts of that contract, including concurrent writers, ordinal regression, rollback, tenant RLS and runtime privilege isolation. Production acceptance still requires repository wiring, deployment roles, pooled-context isolation, migration/recovery, crash/retry and backup/restore survival.

#80 remains canonical for the broader production PostgreSQL repository/transaction/migration/RLS/recovery boundary. Stale mixed #95 is preservation evidence only and must not be imported wholesale.

### Production-state prerequisites: #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207

#140 is the canonical Runtime Configuration foundation. Fresh concurrent review advanced its hostile syntax coverage beyond the prior `3d933140...` candidate. Test-only `0f9ad5ce5fe0b392b55d9c3618454b6010e11dc7` added two equivalent Rust root-alias bypasses: `use std::{self as standard}; ... standard::env::var(...)` and `extern crate std as standard; ...`. Hosted CI `34212119942`, rust job `102015307615`, acquired a GitHub-hosted runner, passed checkout/toolchain/format and failed in `Test`, establishing a semantic RED against unchanged production. `7765da43d7d1a8063061064fdf222e66c0b0983b` repaired the extern-crate form; immediate source verification showed grouped `self as ...` was still uncovered, so `e2822571e0c7029022548f5850b5b448ef51ba3a` added the missing grouped-root predicate.

Exact `e2822571...` then acquired hosted runner `1001777797` in CI `34213607339`, rust job `102020076519`, checked out the exact merge candidate and failed only `cargo fmt --check`: rustfmt required the final EOF newline in `src/runtime_config.rs`, so Test/Clippy were skipped. Current exact child `93a51f9706cf8a9704f69aed4a69df5be16c84e4` adds only that formatting newline. Protected base remains `main@a52ccd0...`; re-read candidate-base compatibility immediately before any readiness or merge transition.

The former non-terminal #140 snapshot is superseded. On unchanged exact `93a51f9706cf8a9704f69aed4a69df5be16c84e4`, CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311`, and SAST Semgrep `34214356338` are terminal **SUCCESS**. CodeQL PR `34214356266` remains terminal **FAILURE** only at the delegated verdict/publication-settlement boundary described above. Fresh review-thread inventory is fully resolved; submitted bot/model reviews remain COMMENTED/advisory and do not satisfy human approval. #140 therefore stays Draft: Wardnet-owned source/security checks are exact-head GREEN, but CodeQL and the live solo-maintainer governance defect remain non-passing. No predecessor GREEN, no source churn, no routine bypass.

#193 remains a Draft child of #140 that makes deployment intent and mutable-state authority explicit. Production requires an explicit PostgreSQL authority declaration and cannot silently fall back to file/memory state; PostgreSQL selection remains fail closed until #80's durable adapter exists. Its live head is `7a93322c9a824e6e939a8143b1f20eccaeac856d`, an ordinary non-force stack adoption of the current #140 foundation that preserves the bounded state-authority delta. Earlier exact `88e54cd18fb686a6b61525c400531820f7a014b4` CI/Fuzz GREEN remains historical evidence only; current-head gates must be reacquired after every parent movement.

#194 remains the PostgreSQL DSN secret-bootstrap child. Semantic RED `9436ad4c7729f1a6a9f6542aa2919b9ae0e45012` / CI `34185447086` reached locked workspace tests with production source unchanged. Minimal repair `eeddc49170b30169bb3fd6a918ee91a74e1ce9f3` keeps `postgres_dsn` inside `CredentialRegistry`, applies credentials-file-over-environment precedence per key, omits empty DSNs, and keeps `CredentialSource` limited to administrator-auth provenance so support/health surfaces do not become generic secret-presence side channels. That repair had terminal CI `34189654335` and Fuzz `34189654329` SUCCESS. Live head `03037b41208afb3e587513f1371f9afdae9effd9` carries the parent adoption; predecessor GREEN does not transfer.

#196 rejects whitespace-only PostgreSQL DSN material from both environment and credentials-file bootstrap while preserving admitted nonblank bytes exactly. Hosted RED `c63fcbb7a445c7c982efd85af88d94f975275ec6` / CI `34221277296` proves both blank paths were previously admitted; causal repair `78149209ed2c3c7443edacad423e26c4ae6c521d` had terminal synthetic-merge CI `34221566705` and Fuzz `34221566709` SUCCESS. Live head `b85de68d1f97c384eb0b307d6620ed3800474049` carries later parent ancestry. The old workflow's synthetic merge receipt is not mislabeled as exact-source-head GREEN and does not transfer through the current stack.

#198 fails closed when an explicitly present credentials-file `postgres_dsn` is JSON number, boolean, array or object instead of string/null. RED `543b1f76aaf06ca6eb8f60fac829b9509e8db11b` / CI `34222777163` proved the former generic conversion admitted `42` as `"42"`. Repair `4fdc1854f46e5178e29d6276fdbf098ee93c1a2a` preserves nonblank string bytes, treats blank/null as absent, rejects every other type without reflecting secret material, and had terminal CI `34223467828` plus Fuzz `34223468107` SUCCESS. Live head `53d17b89f31eb297980e24aea806b9737f4fe87c` carries the current #196 ancestry; no predecessor result transfers.

#199 is the first bounded durable PostgreSQL schema/RLS slice and remains Draft directly behind #198. Test-only RED `18b9228c32acc607a94d4638093a0d21d0ac2c22` / CI `34225504005` failed because the required migration did not exist. It introduced tenant-scoped immutable generation history with unique `(tenant_id, source_id, source_generation)` and `(tenant_id, source_id, source_generation_ordinal)`, `ENABLE` + `FORCE ROW LEVEL SECURITY`, default-deny tenant context and a non-owner/non-`BYPASSRLS` PostgreSQL 18.4 acceptance role. Its competing copy of this ledger was removed at `e0e0cbb75ce5f2f39f501bf4d145755965b983ea`, restoring #130 as the sole writer. Current exact `2ce6ddbb86b370928eebdae22ab17b0042663c56` is an ordinary two-parent non-force adoption of current #198 while preserving #199's durable-generation delta. Exact-current CI `34234948897` and Fuzz `34234948958` are terminal **SUCCESS**.

#200 is the bounded generation-admission child. Its real PostgreSQL 18.4 RED required `wardnet_admit_reputation_source_generation(...)` to distinguish first commit, exact immutable replay, divergent replay, historical token rebound and occupied ordinal conflicts without leaving rejected residue. A harness collision between parallel Docker tests was repaired by unique per-process container suffixes rather than serializing the suite. Current exact `63b2731d7173d24fc15cc1c340fb177727d33251` is an ordinary two-parent non-force adoption of current #199 while preserving the admission delta. Exact-current CI `34234982519` is terminal **SUCCESS**. This still does not select PostgreSQL as production authority.

#207 is the atomic publication and privilege-boundary child of exact #200. Executed RED lineage is preserved: `d8d0cd3ba5c8eca454b1510a745b29b36136fe99` failed because migration `0003` was absent; `f2ef0b0bbaa5599c9d82dbc54e3e27b71e5d643a` proved an unused but regressive ordinal could advance authority; and `43c6396e750d27c35f0a071543e81fce4cc788f2` proved a `SECURITY INVOKER` design plus runtime DML let the runtime directly mutate the last-known-good head and bypass CAS/monotonicity despite RLS. The PostgreSQL Official Image harness was separately repaired to wait for the final-server startup marker plus `pg_isready`, avoiding the temporary-init-server socket race.

Current exact #207 `1d45a024f7e6a0cc351eda3b9fb317ccf6e35300` provides immutable publication evidence, exact-prior CAS, strict ordinal advance, transaction-scoped tenant/source serialization, atomic last-known-good movement, rollback after evidence-completeness failure and tenant FORCE RLS. The outer publication capability is `SECURITY DEFINER` with `search_path = pg_catalog, pg_temp` and PUBLIC execution revoked. Real PostgreSQL acceptance provisions a dedicated `NOLOGIN`/`NOSUPERUSER`/`NOBYPASSRLS` state owner, transfers the function to it, proves the runtime has no direct publication INSERT/head UPDATE authority, proves function-mediated publication still succeeds, and rejects direct head regression/history forgery. Hosted exact-current CI `34245836806`, rust job `102127456517`, is terminal **SUCCESS** through formatting, all locked workspace/PostgreSQL 18.4 tests and strict Clippy. Proposed ADR `docs/adr/2026-09-08-reputation-source-publication-transaction-boundary.md` and CHANGELOG are code-current; neither claims Accepted or release. #80/#192 still own deployment role provisioning, repository wiring, pooled tenant-context checkout/reset, upgrade/rollback/recovery, crash/retry, backup/restore and protected immutable release acceptance.

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
3. #80/#192 PostgreSQL production authority, tenant/RLS isolation and crash-safe reputation-history publication, with #193/#194/#196/#198/#199/#200/#207 integrated dependency-first;
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
