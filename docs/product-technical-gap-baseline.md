# Product and technical gap baseline

Snapshot date: 2026-09-09. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts stay in the owning PR and issue histories.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory is empty for Wardnet, `context-graph-contracts`, and `enterprise-architecture-core`. Their live Draft PR heads are design/compatibility evidence only, never immutable production authority. CGC still has unreleased Context Assertion/provenance/conformance work; EA Core remains on Draft consumer-projection work and must fail closed on mutable CGC source.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. No immutable Wardnet GitHub Release exists, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active and requires one generic approving review while naming no required reviewer/team/code-owner/last-push reviewer. It retains required thread resolution, central required workflows, deletion/non-fast-forward protection, and exposes `OrganizationAdmin/always` bypass. `.github#772` is the canonical solo-maintainer governance repair. Self-approval, model/bot-as-human approval and routine or implicit administrator bypass remain forbidden; deterministic workflow/security/coverage/thread/branch-integrity gates stay fail closed. PR #130 remains a clean product-side specimen rather than a bypass probe.

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0` is incomplete evidence, not by itself a leaf-source defect. Delegated CodeQL terminal-status publication/consumer authentication remains `.github#1929` authority. Mutable central-owner repairs are compatibility evidence only and must be re-read at admission.

Wardnet #140 remains the Runtime Configuration consumer specimen at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311` and SAST Semgrep `34214356338` are SUCCESS. CodeQL `34214356266` remains a delegated terminal-receipt/publication failure owned by `.github#1929`; it is neither a Runtime Configuration source failure nor runner starvation. No synthetic status, predecessor receipt, broad rerun or no-op source churn is authorized.

## Outbound destination reputation stack

#173 remains Proposed architecture for the Wardnet-owned reputation engine and does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement transport authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. Child results do not transfer after parent movement.

#191 preserves the hostile RED proving a current-only lifecycle cursor cannot prevent historical opaque source-generation ABA reuse. P0 #192 therefore requires durable tenant-scoped uniqueness for `(source_id, source_generation)` and `(source_id, source_generation_ordinal)`, atomically coupled with producer lifecycle, accepted immutable evidence, completeness/pagination proof and last-known-good publication. #80 is the canonical production PostgreSQL repository/transaction/migration/RLS/recovery owner; stale mixed #95 is preservation evidence only.

## PostgreSQL production-state prerequisite stack

Current canonical dependency order is `#140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217`. Every parent movement requires ordinary non-force adoption and fresh exact-head gates; predecessor GREEN does not transfer.

Parallel overlap is now reduced through verified successor transfer rather than discard. #214 is closed because exact #216 reconstructs every valid migration-atomicity source/test/ADR/evidence delta on the canonical #212 lineage. #215 is closed because #217 reconstructs every valid complete-0002/complete-0003 recovery preflight, partial-state refusal and restartability delta; #215's post-recovery `expected_prior = NULL` generation-2 behavior was positively disproved and intentionally not transferred.

#193 requires explicit PostgreSQL authority for production and forbids silent file/memory fallback; PostgreSQL remains fail closed until #80's adapter is complete. #194 keeps PostgreSQL DSN bootstrap inside `CredentialRegistry`; #196 rejects whitespace-only DSN material without normalizing admitted bytes; #198 rejects non-string/non-null credentials-file DSN values rather than serializing arbitrary JSON into credentials.

#199 exact `2ce6ddbb86b370928eebdae22ab17b0042663c56` provides immutable tenant/source generation and ordinal identities, `ENABLE` + `FORCE ROW LEVEL SECURITY`, default-deny tenant context and real PostgreSQL 18.4 acceptance. #200 exact `63b2731d7173d24fc15cc1c340fb177727d33251` adds generation admission with first commit, exact immutable replay, divergent replay, historical token rebound and occupied ordinal conflict acceptance without rejected residue.

#207 exact `1d45a024f7e6a0cc351eda3b9fb317ccf6e35300` establishes atomic publication: hardened `SECURITY DEFINER`, `search_path = pg_catalog, pg_temp`, PUBLIC execute revoked, one serialized tenant/source chain, immutable evidence binding, exact-prior CAS and atomic last-known-good advancement. Hosted CI `34245836806` / rust `102127456517` is SUCCESS. Its publication ADR remains Proposed, not Accepted/released.

#208 exact `5a4c510aad6a63c738fcf69656fa385e8343521b` moves least-privilege capability roles into executable deployment state. A prior injected ownership-transfer failure proved psql autocommit could strand roles and temporary schema authority; the repaired role installer is one transaction. Hosted CI `34249592067` / rust `102140309527` is terminal SUCCESS with idempotent replay, dedicated `NOLOGIN`/`NOSUPERUSER`/`NOBYPASSRLS` roles, bounded runtime reads plus outer EXECUTE, no direct mutation/inner-admission authority, no retained state-owner schema CREATE and rollback of a deterministic mid-installation failure.

#209 exact `b191c98ec539dbee92700b32f3fbe0c42c8b77d9` adds supported transactional 0003 rollback: remove publication function/head/history while preserving generation identities and 0002 admission; replay and clean reapply are tested. #212 exact `32b070c3ef2456efc58dc56733531f24fcbaf4f3` makes forward 0003 failure-atomic. #216 exact `7c7b980b7a2f41e2a369a71bb32e945de7f30bfd` extends explicit failure-atomic transactions to 0001 and 0002; hosted CI `34258628942` / rust `102170699585` is terminal SUCCESS. Proposed `docs/adr/2026-09-09-reputation-foundation-migration-atomicity.md` keeps the 0001→0003 schema boundary code-current.

#217 is the current deployment/recovery child at exact `7a6cb5c55e7d440768792dfa3f750a1594ef3ebe`, 22 commits ahead / 0 behind exact #216 with #216 as exact merge base. It has three causal hostile/recovery REDs and a single bounded recovery sequencer:

- Missing sequencer: `3999f0583eddfe87bc07b7ef477998a66fefe246`, CI `34259899229` / rust `102174943790`, failed after checkout/toolchain/formatting because `deploy/postgresql/reputation_state_recovery.sql` did not exist.
- Recovery-evidence bypass: formatted `6a18312c9cc74d4b02daf54dc1033a4335a04a87`, CI `34263214416` / rust `102186066201`, proved on real PostgreSQL 18.4 that restoring runtime EXECUTE while rollback-removed publication evidence/head is absent lets a later surviving generation use `expected_prior = NULL` to become a new first head and skip last-known-good evidence.
- Supported-shape recovery: formatted `30bc7e77592b6b7cf4e861760aeea2af24f5fc50`, CI `34264941085` / rust `102191822902`, failed from complete 0002 because role convergence ran before publication schema existed (`relation "public.reputation_source_publication" does not exist`). Candidate `09c6b896898f0a98e83d36d6ca0d87ff7e8ade3c`, CI `34265174608` / rust `102192601576`, then exposed that client-side `\quit 3` did not reliably provide the required nonzero partial-shape refusal.

The minimum #217 repair keeps schema and positive role/grant truth single-sourced. The recovery sequencer accepts only complete supported shapes: complete 0002 advances through canonical transactional migration 0003; complete 0003 skips schema DDL; mixed/partial publication table/head/function state raises a PostgreSQL exception under `ON_ERROR_STOP` and remains untouched for diagnosis. It then invokes canonical transactional `reputation_state_roles.sql`. If any surviving generation-bearing `(tenant_id, source_id)` lacks an authoritative publication head, runtime outer-function EXECUTE is globally revoked. Verified prior evidence must be restored under controlled deployment/recovery authority; rerunning the sequencer reactivates bounded runtime publication only when every gap is closed, after which runtime advances only through exact-prior/monotonic publication. Normal first-publication semantics remain unchanged.

Exact-current #217 hosted CI `34265888259`, rust `102195122469`, is terminal **SUCCESS** on unchanged `7a6cb5c...`: hosted `ubuntu-24.04`, exact checkout, pinned toolchain, formatting, every locked workspace test including all real PostgreSQL 18.4 owner/evidence-gap/supported-shape recovery regressions, strict Clippy and cleanup passed. Fresh submitted reviews and inline review threads are both zero. Proposed `docs/adr/2026-09-09-reputation-publication-recovery-order.md` records the supported recovery state machine and distinguishes schema recovery, owner/least-privilege reconvergence, publication-evidence restoration with runtime reactivation, and production state-authority enablement.

Production PostgreSQL authority remains disabled. #80/#192 still own actual deployment-principal/login membership, application repository/transaction wiring, pooled transaction-local tenant-context checkout/reset, startup migration locking/version compatibility, crash/retry/idempotency, authoritative backup/restore of generation plus publication history/head with retention/encryption and declared RPO/RTO, readiness/degraded evidence, protected integration and immutable release evidence.

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
