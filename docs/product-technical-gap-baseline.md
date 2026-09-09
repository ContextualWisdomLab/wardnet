# Product and technical gap baseline

Snapshot date: 2026-09-09. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts stay in the owning PR and issue histories.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory is empty for Wardnet, `context-graph-contracts`, and `enterprise-architecture-core`. CGC remains protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` with Draft/unreleased Context Assertion/conformance/source-provenance work. EA Core remains protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece` with Draft/unreleased Context Fabric consumer projection work. Those mutable heads are compatibility evidence only, never Wardnet production authority.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. No immutable Wardnet GitHub Release exists, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active and requires one generic approving review while naming no required reviewer/team/code-owner/last-push reviewer. It retains required thread resolution, central required workflows, deletion/non-fast-forward protection, and exposes `OrganizationAdmin/always` bypass. `.github#772` is the canonical solo-maintainer governance repair. Self-approval, model/bot-as-human approval and routine administrator bypass remain forbidden; deterministic workflow/security/coverage/thread/branch-integrity gates stay fail closed.

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0`/`runner_id=null` is incomplete evidence, not by itself a Wardnet leaf defect. Delegated CodeQL terminal-status publication/consumer authentication remains central owner authority under `.github#1902/#2040` and applicable successors.

Fresh central-owner evidence on `.github#2040@6706c231ab06a3c91c43fdb5b989cfcd79fff593` is still non-passing. Security Scan `34251822390`, SAST Semgrep `34251822314`, Python Security `34251822251`, and Agent Review Runtime Quality CI `34251822381` are terminal SUCCESS, while CodeQL PR `34251822255` is terminal FAILURE. Its compatibility jobs acquired hosted runners and failed in current-head dispatch-verdict settlement, and the dispatch coordinator also failed. This remains central control-plane evidence; no Wardnet source churn, manual rerun storm, synthetic status, or bypass is justified.

Wardnet #228 has now separated queue recovery from a leaf formatting defect. Exact `5d4ce5b2d1708f51cddae9d954fab7d1a70eb6a5` eventually acquired a hosted runner in CI `34305711608` / rust `102321860124`; checkout/toolchain succeeded and `cargo fmt --check` failed only on the new `IncompletePublication` display-arm line wrap, so test/clippy were skipped. Wardnet repaired exactly that emitted rustfmt delta at current `f0c42b84b16549f58a0f93d8b74d643cebba91bf`. Fresh CI `34306473646` and Fuzz `34306473577` are queued and therefore non-passing. The recovered-old/new-current evidence and unchanged-head acceptance are current in `.github#712` comment `5595229287`; Wardnet does not churn source or runner selectors to manufacture execution.

Wardnet #140 remains the Runtime Configuration consumer specimen at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311` and SAST Semgrep `34214356338` are SUCCESS. CodeQL `34214356266` remains delegated central evidence, not a Runtime Configuration source or runner-acquisition defect.

## Outbound destination reputation stack

#173 remains Proposed architecture for the Wardnet-owned reputation engine and does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement transport authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. #191 preserves the hostile RED proving that current-only lifecycle memory cannot enforce historical opaque generation uniqueness. Durable production authority therefore remains #80/#192 PostgreSQL work rather than a bounded recent-token cache.

## PostgreSQL production-state prerequisite stack

Current canonical dependency order is `#140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217 -> #219 -> #221 -> #223 -> #224 -> #225 -> #226 -> #228`. #227 is the issue that defines #228's current complete-published-read acceptance rather than an additional branch node. Every parent movement requires ordinary non-force adoption and fresh exact-head gates; predecessor GREEN does not transfer.

#193 makes PostgreSQL authority explicit/fail-closed for production; #194 keeps PostgreSQL DSN material inside `CredentialRegistry`; #196 rejects blank DSN material without normalizing admitted bytes; #198 rejects non-string/non-null credential-file DSN values.

#199 persists tenant/source generation token+ordinal identities under ENABLE+FORCE RLS and default-deny tenant context. #200 adds immutable generation admission and deterministic replay/token/ordinal conflict behavior. #207 atomically binds generation evidence to publication history plus last-known-good head using a hardened `SECURITY DEFINER` function, exact-prior CAS and one serialized tenant/source chain. #208 adds transactional least-privilege capability roles. #209/#212/#216 make supported rollback/reapply and forward migration failure atomic.

#217 exact `7a6cb5c55e7d440768792dfa3f750a1594ef3ebe` supplies the bounded recovery sequencer. It admits only supported complete shapes, advances complete 0002 through canonical 0003, refuses mixed/partial publication state for diagnosis, reconverges canonical roles, and revokes runtime publication if surviving generation state lacks authoritative publication-head evidence. Hosted CI `34265888259` / rust `102195122469` is terminal SUCCESS on that exact head.

#219 exact `55c8e7c4e4ac022e4d6ca5090c111c79068d137b` serializes startup migration with a PostgreSQL session advisory lock, durable schema-version receipt, exact supported-shape checks, future/partial-schema refusal and ENABLE+FORCE RLS postconditions. Exact-head CI `34270783027` / rust `102211539102` is terminal SUCCESS.

#221 current exact `e2ff0fe4055a598a5c450e7942fed2051ec21238` maps an externally managed ordinary PostgreSQL LOGIN to exactly the existing bounded `wardnet_runtime` capability. The first hostile RED (`32485204874cf80dc06de897066b961c9d31ee7c`) proved an unowned indirect runtime-membership path could survive an apparently bounded direct grant; the repair rejects every alternate path. A second hostile RED `6f43c8627bad7b3bfa381e34745038b9034875f7`, CI `34275200086` / rust `102226380112`, proved that an otherwise ordinary LOGIN could arrive with inherited Wardnet table mutation/inner-admission authority. Minimum repair `e2ff0fe...` rejects that wider effective authority before granting runtime membership. Exact CI `34275523673` / rust `102227465852` is terminal SUCCESS; fresh submitted reviews and inline threads are zero. Credential/password/principal lifecycle and state-owner capability remain outside this slice.

#223 current exact `0876c55fdc82927adaece4f3bb414a7a631dea68` is the pooled transaction-local tenant-session child on exact #221. It sets `wardnet.tenant_id` only through parameterized transaction-local `set_config(..., true)`, holds a checked-out connection through commit/rollback, transfers a cancelled checkout into asynchronous rollback before reuse, and proves physical-connection cleanup, cross-tenant RLS isolation and concurrent tenant independence on real PostgreSQL 18.4. Its test-only `NoTls` helper additionally rejects remote `hostaddr` targets rather than validating only `host`. Exact CI `34284257853` / rust `102256023876` and Fuzz `34284257807` / `102256114065` are terminal SUCCESS. Production connection construction remains TLS-capable.

#224 current exact `c805d83484be91a157ed8350944bf7d35d37bc7e` is the bounded typed publication-repository child on exact #223. Its real PostgreSQL 18.4 acceptance publishes `8@8 -> 9@9`, rejects historical `8@10` ABA as stable `PublicationConflict`, preserves generation 9 as replayable last-known-good, and rejects a different token rebound to ordinal 9. The Rust adapter calls only the canonical publication function inside the #223 transaction-local tenant session and maps canonical outcomes/errors into `Committed`, `Replay`, and stable conflict semantics; callers do not construct SQL or parse database error text. Exact-current CI `34290913936` and Fuzz `34290913959` are terminal SUCCESS; fresh submitted reviews and inline threads are zero.

#225 current exact `fa9d2afe7783489581ee68fad0be4b4b55dcebc0` is the attributable-publication child on exact #224. Its hostile lineage proves both the typed repository's missing-attribution defect and the deeper direct ordinary-runtime `SECURITY DEFINER` capability bypass. Schema v5 now requires transaction-local `wardnet.actor_subject_id` plus `wardnet.decision_id` for every newly inserted publication; missing/partial attribution aborts without residue, exact replay does not duplicate audit evidence, and the typed repository treats replay with mismatched attribution as stable `PublicationConflict`. Recovery fixtures were repaired to restore attributable evidence rather than weakening the invariant. Exact CI `34299081730` and Fuzz `34299081819` are terminal SUCCESS; fresh submitted reviews and inline threads are zero.

#226 current exact `da5f2b01163e9db1416bfa4162ebdb7953778fc5` closes the inherited generic raw-SQL repository escape hatch on exact #225. `TenantTransaction`, `TenantTransactionFuture`, and `with_tenant_transaction` are crate-private; generic scalar SQL helpers compile only under `cfg(test)`, while the existing real-PostgreSQL tenant-context/cancellation suite remains behind a crate-local white-box seam. Ordinary application callers therefore retain typed tenant-scoped repository operations without an arbitrary-SQL callback/query API. Test-first RED is `765680969cf9ffe3e179c6fdf95a57039c765781`; minimum repairs are `9cd919b2f87f6049275878610353f1d56af02be3` and `da5f2b...`. Exact CI `34300579943` and Fuzz `34300579966` are terminal SUCCESS; fresh submitted reviews and inline threads are zero. The PR stays Draft behind #225.

#227 defines the next verified durable-state gap: read only the complete authoritative current publication. #228 current exact `f0c42b84b16549f58a0f93d8b74d643cebba91bf` is its Draft child on exact #226. The real PostgreSQL 18.4 acceptance publishes generations 8 and 9, then deliberately admits generation 10 without publishing it, and requires the typed read to keep generation 9 as current complete truth with immutable evidence/provenance/completeness/producer-lifecycle and actor/decision attribution. It also requires tenant isolation, typed absence for never-published state, source-input rejection, and fail-closed behavior when a publication head cannot be joined to required audit evidence. Exact predecessor `d5b8bb17e3ebc6f97a1c7c88f7c63456f617e356` produced the semantic RED in CI `34303075828` / rust `102313985043`. Production candidate `5d4ce5b2...` then reached repository execution and failed only rustfmt; current `f0c42b84...` applies exactly that formatting repair. Current CI/Fuzz are queued and therefore non-passing until the unchanged head executes.

Production PostgreSQL authority remains disabled. #80/#192 still require complete-published-aggregate reads through #227/#228, divergent-writer concurrency, crash/cancellation/connection-loss phase atomicity and idempotent retry, authoritative backup/restore with retention/encryption and measured RPO/RTO, readiness/degraded semantics, protected integration and immutable release evidence. An admitted or partially persisted generation must never silently become current truth.

## Gateway and Agent Artifact Admission security lanes

#181 owns the route path-segment boundary repair: exact-or-slash-descendant matching replaces raw lexical prefix capture while preserving root, trailing slash, disabled routes and longest valid match. Repository/Fuzz/Security/SAST are GREEN on its unchanged code head; delegated CodeQL receipt reconciliation remains central-owner evidence.

#129 remains the Rust-first Agent Artifact Admission lane. It is pre-execution policy/evidence authority only: retrieved-byte integrity, AppGuardrail analysis, quarantine execution, Noema activation, EgressWeave transport and contextual-orchestrator provider orchestration remain separate canonical authorities.

#155 remains the fail-closed management-authentication prerequisite for non-loopback exposure. #93 remains the deterministic persistence-fault seam. #127 remains incomplete until its material embedded admin-console accessibility change has real-browser current-head keyboard/focus/name/role/value, responsive and normal/loading/empty/error/permission-state evidence rather than source-string tests alone.

#77 remains the Rust-toolchain/reproducibility prerequisite; #164 remains its dependent release-evidence lane and cannot publish from a feature branch or transfer predecessor SBOM/provenance evidence after restack.

## Other preservation and integration lanes

#165 is the canonical trusted forwarded-client attribution slice for #83 and remains Draft behind #140 plus preservation transfer from #157. It owns direct-peer trust, right-to-left trusted forwarded-chain attribution, mapped-address normalization and fail-closed trusted-CIDR grammar; broader local limiter cardinality and distributed admission remain separate #83 work.

#135 preserves bounded local-limiter cardinality/expiry/stable-429 behavior but carries overlapping Runtime Configuration/trusted-proxy prerequisite authority. Its unique limiter delta must be reconstructed after #140 and #165 reach protected truth rather than integrating a second configuration/trusted-attribution foundation.

#167/#170 retain MISP/DNSBL source-ownership and source-severity semantics. #115/#136 preserve threat-feed and outbound-policy hostile consumer evidence but cannot merge a second EgressWeave transport-policy authority. #88 preserves credential-guard evidence pending an immutable compatible contextual-orchestrator boundary rather than retaining provider-routing authority in Wardnet. #90/#95/#112 are preservation lanes whose valid unique Wardnet deltas must be reconstructed from current protected truth instead of mechanically merging stale aggregate source.

#134 support-bundle contract, #162 customer-contract-vs-USD-20B-quality authority separation, and #144 Kubernetes source-path migration retain bounded Wardnet deltas. Their code-bearing delegated CodeQL failures remain central receipt specimens rather than reasons for leaf churn.

## Release blockers and buyer-visible gap order

Authority and safety remain ahead of feature breadth. Current release-blocking order is:

1. satisfiable protected governance and authenticated exact-head central evidence;
2. protected management authentication and Runtime Configuration truth;
3. #80/#192 PostgreSQL production authority with the dependency stack through #226, then #227/#228 complete-current reads, concurrency/crash-retry/backup-restore/readiness acceptance;
4. trusted client attribution and bounded/distributed admission reconstructed without duplicate #140/#165 authority;
5. immutable EgressWeave authorization/evidence integration for outbound transport;
6. deployed attack-path evidence and proven Coraza/CRS + Suricata enforcement without inventing substitute detection authority;
7. Agent Artifact Admission integrated with released foreign-owner ports;
8. transactional outbox/idempotent workers, Keyverse-backed identity/approval and distributed admission/trusted attribution;
9. immutable package/image/SBOM/provenance/reproducibility/promotion/rollback plus production telemetry/SLO/incident/restore evidence;
10. one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, in-progress/queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
