# Product and technical gap baseline

Snapshot date: 2026-09-09. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This file is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts stay in the owning PR and issue histories.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory is empty for Wardnet, `context-graph-contracts`, and `enterprise-architecture-core`. Their live Draft PR heads are design/compatibility evidence only, never immutable production authority. Current CGC root/Context Assertion work still reports the unresolved protected-default topology and unreleased contract stack; EA Core likewise remains on Draft consumer-projection work and must fail closed on mutable CGC source.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. There is no immutable Wardnet GitHub Release, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active and requires one generic approving review while naming no required reviewer/team/code-owner/last-push reviewer. It retains required thread resolution, central required workflows, deletion/non-fast-forward protection, and exposes `OrganizationAdmin/always` bypass. `.github#772` is the canonical solo-maintainer governance repair. Self-approval, model/bot-as-human approval and routine or implicit administrator bypass remain forbidden; deterministic workflow/security/coverage/thread/branch-integrity gates stay fail closed. PR #130 remains a clean product-side specimen rather than a bypass probe.

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0` is incomplete evidence, not by itself a leaf-source defect. Later hosted acquisition supersedes a transient queue snapshot without source churn; selector/no-op changes require causal evidence.

Delegated CodeQL remains a central producer/receipt path. Cross-repository terminal-status publication and consumer authentication remain `.github#1929` authority. Mutable `.github` owner repairs are compatibility evidence only; Wardnet must re-read them at admission rather than consume a mutable owner head as released dependency.

Wardnet #140 remains the Runtime Configuration consumer specimen at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311` and SAST Semgrep `34214356338` are SUCCESS. CodeQL `34214356266` remains a delegated terminal-receipt/publication failure owned by `.github#1929`; it is neither a Runtime Configuration source failure nor runner starvation. No synthetic status, predecessor receipt, broad rerun or no-op source churn is authorized.

## Outbound destination reputation stack

#173 remains Proposed architecture for the Wardnet-owned reputation engine and does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement transport authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. Child results do not transfer after parent movement.

#191 preserves the hostile RED proving a current-only lifecycle cursor cannot prevent historical opaque source-generation ABA reuse. P0 #192 therefore requires durable tenant-scoped uniqueness for `(source_id, source_generation)` and `(source_id, source_generation_ordinal)`, atomically coupled with producer lifecycle, accepted immutable evidence, completeness/pagination proof and last-known-good publication. #80 is the canonical production PostgreSQL repository/transaction/migration/RLS/recovery owner; stale mixed #95 is preservation evidence only.

## PostgreSQL production-state prerequisite stack

Current canonical dependency order is `#140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217`. Every parent movement requires ordinary non-force adoption and fresh exact-head gates; predecessor GREEN does not transfer. Parallel #214/#215 contains overlapping migration/recovery experiments and remains preservation evidence until every still-valid unique fixture, test and operability contract is transferred to the canonical stack or proven obsolete. #215's supported-starting-shape preflight/restartability may be transferable, but its current post-recovery `expected_prior = NULL` generation-2 acceptance is now positively disproved by #217 and must not transfer.

#140 is the Runtime Configuration foundation at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. It is source/security GREEN except for the delegated CodeQL receipt path above and remains Draft under live governance.

#193 is the explicit state-authority child. Production requires explicit PostgreSQL authority and cannot silently fall back to file/memory state; PostgreSQL remains fail closed until #80's adapter is complete.

#194 keeps PostgreSQL DSN bootstrap inside `CredentialRegistry`; connection material does not become public Runtime Configuration or support/health secret-presence metadata. #196 rejects whitespace-only DSN material without normalizing admitted bytes, and #198 rejects non-string/non-null credentials-file DSN values rather than serializing arbitrary JSON into credentials.

#199 is the first durable PostgreSQL schema/RLS slice at exact `2ce6ddbb86b370928eebdae22ab17b0042663c56`. It provides immutable tenant/source generation and ordinal identities, `ENABLE` + `FORCE ROW LEVEL SECURITY`, default-deny tenant context and non-owner/non-`BYPASSRLS` PostgreSQL 18.4 acceptance. Exact CI `34234948897` and Fuzz `34234948958` are SUCCESS. Its former competing copy of this ledger was removed, restoring #130 as sole writer.

#200 is generation admission at exact `63b2731d7173d24fc15cc1c340fb177727d33251`. PostgreSQL 18.4 acceptance distinguishes first commit, exact immutable replay, divergent replay, historical token rebound and occupied ordinal conflicts without rejected residue. Exact CI `34234982519` is SUCCESS.

#207 is atomic publication at exact `1d45a024f7e6a0cc351eda3b9fb317ccf6e35300`. Executed hostile evidence proved missing publication authority, acceptance of a regressive successor ordinal, and direct runtime head mutation under the earlier `SECURITY INVOKER`/DML design. The repaired outer capability is `SECURITY DEFINER`, pins `search_path = pg_catalog, pg_temp`, revokes PUBLIC execute, serializes one tenant/source chain, binds immutable publication evidence and exact-prior CAS, and advances last-known-good only atomically. Exact CI `34245836806` / rust `102127456517` is SUCCESS. The publication ADR remains Proposed, not Accepted/released.

#208 moves the least-privilege capability-role contract into executable deployment state. Hostile exact `282f0fec7ff16b3aa4aae1a9a1f8b96a8fb25053` / CI `34248558975` proved psql autocommit could strand both capability roles and temporary state-owner schema `CREATE` after injected ownership-transfer failure. The repair makes the complete role creation/convergence/grant/ownership-transfer/revocation sequence one transaction. Current exact #208 is `5a4c510aad6a63c738fcf69656fa385e8343521b`; hosted CI `34249592067` / rust `102140309527` is terminal SUCCESS with idempotent replay, dedicated `NOLOGIN`/`NOSUPERUSER`/`NOBYPASSRLS` roles, bounded runtime reads plus outer EXECUTE, no direct mutation/inner-admission authority, no retained state-owner schema CREATE and rollback of a deterministic mid-installation failure. Login credentials and principal membership remain deployment/IAM concerns.

#209 exact `b191c98ec539dbee92700b32f3fbe0c42c8b77d9` adds the supported 0003 down migration. Test-only lineage reached semantic RED when the rollback artifact was absent; exact CI `34250487750` / rust `102143370052` is terminal SUCCESS after the transactional rollback removes the publication function/head/history while preserving 0001 generation identities plus the 0002 admission boundary, permits safe rollback replay and clean 0003 reapply, and does not duplicate preserved generation identity. This proves schema rollback/reapply only.

#212 exact `32b070c3ef2456efc58dc56733531f24fcbaf4f3` makes forward migration 0003 failure-atomic. Test-only `fa44632f3f12aefeb796e024f9786e7382d3f4b4` / CI `34252354098` reached PostgreSQL semantic RED after checkout/toolchain/formatting. The minimum production repair wraps the complete 0003 DDL in explicit `BEGIN`/`COMMIT`; exact CI `34252852169` / rust `102151645755` is terminal SUCCESS and proves an injected mid-migration failure leaves the complete 0001/0002 predecessor boundary with no partial 0003 object before clean replay.

#216 exact `7c7b980b7a2f41e2a369a71bb32e945de7f30bfd` extends the same failure-atomic contract to forward migrations 0001 and 0002. Test-only `284ea3c4188f8533416a6ac68cdda6325c5565d6` / CI `34257768388` established semantic RED: injected failure could strand a generation table or admission function under autocommit. The minimum repair gives each migration its own explicit transaction boundary without `IF NOT EXISTS`, partial-state normalization, role creation or authority widening. Hosted exact CI `34258628942` / rust `102170699585` is terminal SUCCESS across formatting, all locked workspace/PostgreSQL 18.4 rollback/replay tests and strict Clippy. Proposed ADR `docs/adr/2026-09-09-reputation-foundation-migration-atomicity.md` keeps the 0001→0003 schema boundary code-current.

#217 is the current deployment/recovery child at exact `fdbf01cfac25a9cd8173e30a7e6497b551cb1745`, 16 commits ahead / 0 behind exact #216 with #216 as the merge base. The initial test-only `3999f0583eddfe87bc07b7ef477998a66fefe246` / CI `34259899229` reached semantic RED because no executable post-reapply role-recovery sequencer existed. The recovery artifact reuses canonical transactional `reputation_state_roles.sql` through psql `\ir`, so positive cluster-role/grant/ownership truth remains single-sourced.

A first exact-prior recovery test then established that surviving generation identity is not restored publication evidence: 0003 rollback intentionally removes publication history/head, so generation 2 naming generation 1 as expected prior must conflict until prior evidence is restored. Fresh hostile inspection found the more dangerous remaining path: if runtime EXECUTE is simply restored after rollback/reapply, the normal first-publication path accepts `expected_prior = NULL`, allowing a later surviving generation to become a new first head and silently skip the lost last-known-good publication evidence.

Formatted hostile exact `6a18312c9cc74d4b02daf54dc1033a4335a04a87`, hosted CI `34263214416`, rust `102186066201`, proves that bypass on real PostgreSQL 18.4: hosted acquisition, exact checkout, toolchain and formatting passed, then `postgres_publication_recovery_evidence_gap` failed because runtime successfully published generation 2 with NULL prior while generation-1 publication evidence/head was absent.

The minimum repair keeps normal publication semantics unchanged and makes recovery itself fail closed. After canonical owner/grant convergence, `reputation_state_recovery.sql` checks for any surviving generation-bearing `(tenant_id, source_id)` with no authoritative publication head and globally revokes runtime outer-function EXECUTE if any gap exists. Controlled deployment/recovery authority restores verified prior publication evidence through the hardened outer capability; rerunning the sequencer reactivates bounded runtime publication only once every such gap is closed. Tests also retain state-owner `NOLOGIN`/`NOSUPERUSER`/`NOBYPASSRLS`, hardened SECURITY DEFINER/search path, no PUBLIC EXECUTE, bounded runtime reads, no direct mutation/inner-admission authority, no state-owner schema CREATE, deterministic mid-recovery rollback, identity preservation and idempotent replay.

Exact-current #217 CI `34264097571`, rust `102189169461`, is terminal **SUCCESS** on unchanged `fdbf01cf...`: hosted runner, exact checkout, formatting, all locked workspace tests including the real PostgreSQL 18.4 hostile recovery cases, strict Clippy and cleanup passed. Fresh submitted reviews and inline review threads are both zero. Proposed `docs/adr/2026-09-09-reputation-publication-recovery-order.md` records four distinct states: schema recovery, owner/least-privilege reconvergence, publication-evidence restoration with runtime reactivation, and production state-authority enablement.

Production PostgreSQL authority remains disabled. #80/#192 still own actual deployment-principal/login membership, application repository/transaction wiring, pooled transaction-local tenant-context checkout/reset, startup migration locking/version compatibility, crash/retry/idempotency, authoritative backup/restore of generation + publication history/head with retention/encryption and declared RPO/RTO, readiness/degraded evidence, protected integration and immutable release evidence.

## Gateway and Agent Artifact Admission security lanes

#181 owns the route path-segment boundary repair: exact-or-slash-descendant matching replaces raw lexical prefix capture while preserving root, trailing slash, disabled routes and longest valid match. Repository/Fuzz/Security/SAST are GREEN on its unchanged code head; delegated CodeQL receipt reconciliation remains central-owner evidence.

#129 remains the Rust-first Agent Artifact Admission lane. It is pre-execution policy/evidence authority only: retrieved-byte integrity, AppGuardrail analysis, quarantine execution, Noema activation, EgressWeave transport and contextual-orchestrator provider orchestration remain separate canonical authorities.

#155 remains the fail-closed management-authentication prerequisite for non-loopback exposure. #93 remains the deterministic persistence-fault seam. #127 remains incomplete until the material embedded admin-console accessibility change has real-browser current-head keyboard/focus/name/role/value, responsive and state evidence rather than source-string tests alone.

#77 remains the Rust-toolchain/reproducibility prerequisite; #164 remains its dependent release-evidence lane and cannot publish from a feature branch or transfer predecessor SBOM/provenance evidence after restack.

## Other preservation and integration lanes

#165 is the canonical trusted forwarded-client attribution slice for #83 and remains Draft behind #140 plus preservation transfer from #157. It owns direct-peer trust, right-to-left forwarded-chain attribution, mapped-address normalization and fail-closed trusted-CIDR grammar; broader local limiter cardinality and distributed admission remain separate #83 work.

#135 preserves bounded local-limiter cardinality/expiry/stable-429 behavior but carries overlapping Runtime Configuration/trusted-proxy prerequisite authority. Its unique limiter delta must be reconstructed after #140 and #165 reach protected truth rather than integrating a second configuration/trusted-attribution foundation.

#167/#170 retain MISP/DNSBL source-ownership and source-severity semantics. #115/#136 preserve threat-feed and outbound-policy hostile consumer evidence but cannot merge a second EgressWeave transport-policy authority. #88 preserves credential-guard evidence pending an immutable compatible contextual-orchestrator boundary rather than retaining provider-routing authority in Wardnet. #90/#95/#112 are preservation lanes whose valid unique Wardnet deltas must be reconstructed from current protected truth instead of mechanically merging stale aggregate source.

#134 support-bundle contract, #162 customer-contract-vs-USD-20B-quality authority separation, and #144 Kubernetes source-path migration retain bounded Wardnet deltas. Their code-bearing delegated CodeQL failures remain central receipt specimens rather than reasons for leaf churn.

## Release blockers and buyer-visible gap order

Authority and safety remain ahead of feature breadth. Current release-blocking order is:

1. satisfiable protected governance and authenticated exact-head central evidence;
2. protected management authentication and Runtime Configuration truth;
3. #80/#192 PostgreSQL production authority with the dependency stack through #217, followed by production principal mapping, repository/pool transaction wiring, crash/retry, authoritative backup/restore and readiness evidence;
4. trusted client attribution and bounded/distributed admission reconstructed without duplicate #140/#165 authority;
5. immutable EgressWeave authorization/evidence integration for outbound transport;
6. deployed attack-path evidence and proven Coraza/CRS + Suricata enforcement without inventing substitute detection authority;
7. Agent Artifact Admission integrated with released foreign-owner ports;
8. transactional outbox/idempotent workers, Keyverse-backed identity/approval and distributed admission/trusted attribution;
9. immutable package/image/SBOM/provenance/reproducibility/promotion/rollback plus production telemetry/SLO/incident/restore evidence;
10. one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
