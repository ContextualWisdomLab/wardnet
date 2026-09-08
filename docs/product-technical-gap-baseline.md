# Product and technical gap baseline

Snapshot date: 2026-09-08. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This file is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts stay in the owning PR and issue histories.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory is empty for Wardnet, EgressWeave, `contextual-orchestrator`, `quarantine-sandbox-runtime`, `context-graph-contracts` and `enterprise-architecture-core`. Mutable owner PR heads are design/compatibility evidence, not immutable production authority.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. There is no immutable Wardnet GitHub Release, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active and requires one generic approving review while naming no required reviewer/team/code-owner/last-push reviewer. It retains required thread resolution, central required workflows, deletion/non-fast-forward protection, and also exposes `OrganizationAdmin/always` bypass. `.github#772` is the canonical solo-maintainer governance repair. Self-approval, model/bot-as-human approval and routine or implicit administrator bypass remain forbidden; deterministic workflow/security/coverage/thread/branch-integrity gates stay fail closed. PR #130 supplies a clean exact-head specimen to #772 rather than using bypass.

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0` is incomplete evidence, not by itself a leaf-source defect. The #207 `80af9027...` specimen was handed to #712, then acquired hosted runner `1001788214` and completed SUCCESS without source churn. Resolved queue specimens must not be misreported as persistent runner-label defects.

Delegated CodeQL remains a central producer/receipt path. `.github#1902` is Draft at live head `c8d7caa0d699cec0200815fdfbca8bc0b2f7a4ec`; Ready `.github#2040` is the current combined producer/handler successor at `d7bb95f6d6ca705725596df5170d6e1345080535`. Cross-repository terminal-status publication and consumer authentication remain `.github#1929` authority. These mutable owner repairs are compatibility evidence only; Wardnet must re-read them at admission rather than treat them as a released dependency.

Wardnet #140 remains the exact consumer specimen at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311` and SAST Semgrep `34214356338` are SUCCESS. CodeQL `34214356266` remains FAILURE only at delegated terminal receipt/publication settlement and was handed to `.github#1929`; it is neither a leaf-source failure nor runner starvation. No synthetic status, predecessor receipt, broad rerun or no-op source churn is authorized.

## Outbound destination reputation stack

#173 remains Proposed architecture for the Wardnet-owned reputation engine and does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement transport authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. Child results do not transfer after parent movement.

#191 preserves the hostile RED proving a current-only lifecycle cursor cannot prevent historical opaque source-generation ABA reuse. P0 #192 therefore requires durable tenant-scoped uniqueness for `(source_id, source_generation)` and `(source_id, source_generation_ordinal)`, atomically coupled with producer lifecycle, accepted immutable evidence, completeness/pagination proof and last-known-good publication. #80 is the canonical production PostgreSQL repository/transaction/migration/RLS/recovery owner; stale mixed #95 is preservation evidence only.

## PostgreSQL production-state prerequisite stack

Dependency order is `#140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208`. Every parent movement requires ordinary non-force adoption and fresh exact-head gates; predecessor GREEN does not transfer.

#140 is the Runtime Configuration foundation at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. It is source/security GREEN except for the delegated CodeQL receipt path above and remains Draft under live governance.

#193 is the explicit state-authority child at live head `7a93322c9a824e6e939a8143b1f20eccaeac856d`. Production requires explicit PostgreSQL authority and cannot silently fall back to file/memory state; PostgreSQL remains fail closed until #80's adapter is complete.

#194 is the PostgreSQL DSN secret-bootstrap child at `03037b41208afb3e587513f1371f9afdae9effd9`. `postgres_dsn` stays inside `CredentialRegistry`, credentials-file values take per-key precedence over environment, and support/health surfaces do not become generic secret-presence side channels.

#196 at `b85de68d1f97c384eb0b307d6620ed3800474049` rejects whitespace-only PostgreSQL DSN material while preserving admitted nonblank bytes exactly.

#198 at `53d17b89f31eb297980e24aea806b9737f4fe87c` rejects non-string/non-null credentials-file `postgres_dsn` values instead of converting numbers, booleans, arrays or objects into credentials.

#199 is the first durable PostgreSQL schema/RLS slice at exact `2ce6ddbb86b370928eebdae22ab17b0042663c56`. It provides immutable tenant/source generation and ordinal identities, `ENABLE` + `FORCE ROW LEVEL SECURITY`, default-deny tenant context and non-owner/non-`BYPASSRLS` PostgreSQL 18.4 acceptance. Its exact CI `34234948897` and Fuzz `34234948958` are SUCCESS. Its former competing copy of this ledger was removed, restoring #130 as the sole writer.

#200 is the generation-admission child at exact `63b2731d7173d24fc15cc1c340fb177727d33251`. PostgreSQL 18.4 acceptance distinguishes first commit, exact immutable replay, divergent replay, historical token rebound and occupied ordinal conflicts without rejected residue. Exact CI `34234982519` is SUCCESS. The parallel Docker-test container collision was fixed with unique per-process suffixes rather than serializing the suite.

#207 is the atomic publication and privilege-boundary child at exact `1d45a024f7e6a0cc351eda3b9fb317ccf6e35300`. Executed hostile evidence proved three material defects before repair: missing publication transaction authority; acceptance of an unused but regressive ordinal; and a `SECURITY INVOKER` design whose required runtime DML let the runtime directly mutate the last-known-good head and bypass CAS/monotonicity despite RLS. The PostgreSQL Official Image harness was separately corrected to wait for the final-server startup marker plus `pg_isready` rather than the temporary init server.

#207 now provides immutable publication evidence, exact-prior CAS, strict ordinal advance, tenant/source transaction serialization, atomic last-known-good movement, rollback after evidence-completeness failure and tenant FORCE RLS. The outer publication capability is `SECURITY DEFINER` with `search_path = pg_catalog, pg_temp` and PUBLIC execute revoked. Real PostgreSQL acceptance proves a dedicated `NOLOGIN`/`NOSUPERUSER`/`NOBYPASSRLS` state owner can mediate publication while runtime has no direct publication INSERT/head UPDATE authority. Exact CI `34245836806` / rust `102127456517` is SUCCESS through formatting, locked workspace/PostgreSQL 18.4 tests and strict Clippy. Proposed ADR `docs/adr/2026-09-08-reputation-source-publication-transaction-boundary.md` and CHANGELOG remain Proposed/Unreleased, not Accepted/released.

#208 moves that least-privilege role contract from a test fixture into executable deployment state. Test-only `0cf9fe514047b320a4aae1a9a1f8b96a8fb25053` reached semantic RED in CI `34247087136` / rust `102131737688` because `deploy/postgresql/reputation_state_roles.sql` did not exist. The first deployment candidate then exposed a test-oracle-only `f/t` boolean representation mismatch, repaired without changing the privilege contract.

Fresh hostile review subsequently added deterministic installation-failure coverage at `282f0fec7ff16b3aa4e1e086900970e154e4f1c0`. CI `34248558975` / rust `102137217073` passed all preceding PostgreSQL 18.4 acceptance and then proved the installer was non-atomic: an injected `ALTER FUNCTION` failure left both capability roles and temporary state-owner schema `CREATE` authority behind. The cause was psql autocommit across the installer statements.

Current exact #208 `03af6b3c962ce7d681bd49f5a80487aa94283bc6` wraps the complete role creation/convergence/grant/ownership-transfer/revocation sequence in one explicit PostgreSQL transaction. The installer idempotently converges dedicated `wardnet_state_owner` and `wardnet_runtime` roles to `NOLOGIN`/`NOSUPERUSER`/`NOCREATEDB`/`NOCREATEROLE`/`NOINHERIT`/`NOBYPASSRLS`/`NOREPLICATION`, grants runtime only bounded reads plus outer publication EXECUTE, removes direct mutation and inner-admission authority, temporarily grants schema `CREATE` only for function ownership transfer, then revokes it. Login credentials and principal membership remain deployment/IAM concerns.

Exact-current #208 CI `34248937286` / rust `102138060537` is terminal **SUCCESS**: formatting, all locked workspace tests including PostgreSQL 18.4 role replay/least-privilege mediation and injected mid-flight rollback, strict Clippy and cleanup passed. Fresh review-thread inventory is empty. Production PostgreSQL authority remains disabled; #80/#192 still own repository wiring, actual deployment principal mapping, pooled tenant-context checkout/reset, migration upgrade/rollback/recovery, crash/retry behavior, backup/restore survival and protected immutable release evidence.

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
3. #80/#192 PostgreSQL production authority with the dependency stack through #208, followed by repository wiring, pool context hygiene, recovery and restore evidence;
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
