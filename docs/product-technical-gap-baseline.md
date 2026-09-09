# Product and technical gap baseline

Snapshot date: 2026-09-09. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts stay in the owning PR and issue histories.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh GitHub Release inventory remains empty for Wardnet, `context-graph-contracts`, and `enterprise-architecture-core`. CGC remains protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` with Draft/unreleased Context Assertion/conformance/source-provenance work. EA Core remains protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece` with Draft/unreleased Context Fabric consumer projection work. Those mutable heads are compatibility evidence only, never Wardnet production authority.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. No immutable Wardnet GitHub Release exists, so protected source truth is not yet a release identity.

Organization ruleset `18156473` remains active and requires one generic approving review while naming no required reviewer/team/code-owner/last-push reviewer. It retains required thread resolution, central required workflows, deletion/non-fast-forward protection, and exposes `OrganizationAdmin/always` bypass. `.github#772` is the canonical solo-maintainer governance repair. Self-approval, model/bot-as-human approval and routine administrator bypass remain forbidden; deterministic workflow/security/coverage/thread/branch-integrity gates stay fail closed.

Runner/materialization remains `.github#712` authority. Queued or pre-checkout `runner_id=0`/`runner_id=null` is incomplete evidence, not by itself a Wardnet leaf defect. #234 supplied a current-head `runner_id=0` specimen to #712 and then acquired real hosted compute without source churn; that exact head subsequently completed GREEN. Delegated CodeQL terminal-status publication/consumer authentication remains central owner authority under `.github#1902/#2040` and applicable successors.

Fresh central-owner evidence on `.github#2040@6706c231ab06a3c91c43fdb5b989cfcd79fff593` remains non-passing: Security Scan `34251822390`, SAST Semgrep `34251822314`, Python Security `34251822251`, and Agent Review Runtime Quality CI `34251822381` are terminal SUCCESS, while CodeQL PR `34251822255` is terminal FAILURE. This remains central control-plane evidence; no Wardnet source churn, manual rerun storm, synthetic status, or routine bypass is justified.

Wardnet #140 remains the Runtime Configuration consumer specimen at `93a51f9706cf8a9704f69aed4a69df5be16c84e4`. CI `34214356329`, Fuzz `34214356312`, Security Scan `34214356311` and SAST Semgrep `34214356338` are SUCCESS. CodeQL `34214356266` remains delegated central evidence, not a Runtime Configuration source or runner-acquisition defect.

## Outbound destination reputation stack

#173 remains Proposed architecture for the Wardnet-owned reputation engine and does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement transport authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. The dependent evidence stack remains ordered: #176 business-authorization binding → #178 decision freshness → #179 evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. #191 preserves the hostile RED proving that current-only lifecycle memory cannot enforce historical opaque generation uniqueness. Durable production authority therefore remains #80/#192 PostgreSQL work rather than a bounded recent-token cache.

## PostgreSQL production-state prerequisite stack

Current canonical branch dependency order is `#140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217 -> #219 -> #221 -> #223 -> #224 -> #225 -> #226 -> #228 -> #229 -> #231 -> #233 -> #234 -> #236`. Issue #227 defines #228's complete-published-read acceptance, #230 defines #231's capacity-replenishment acceptance, #232 defines #233/#234 degraded-readiness work, and #235 defines #236's ambiguous-commit acceptance rather than adding issue nodes to branch ancestry. Every parent movement requires ordinary non-force adoption and fresh exact-head gates; predecessor GREEN does not transfer.

#193 makes PostgreSQL authority explicit/fail-closed for production; #194 keeps PostgreSQL DSN material inside `CredentialRegistry`; #196 rejects blank DSN material without normalizing admitted bytes; #198 rejects non-string/non-null credential-file DSN values.

#199 persists tenant/source generation token+ordinal identities under ENABLE+FORCE RLS and default-deny tenant context. #200 adds immutable generation admission and deterministic replay/token/ordinal conflict behavior. #207 atomically binds generation evidence to publication history plus last-known-good head using a hardened `SECURITY DEFINER` function, exact-prior CAS and one serialized tenant/source chain. #208 adds transactional least-privilege capability roles. #209/#212/#216 make supported rollback/reapply and forward migration failure atomic.

#217 exact `7a6cb5c55e7d440768792dfa3f750a1594ef3ebe` supplies the bounded recovery sequencer. It admits only supported complete shapes, advances complete 0002 through canonical 0003, refuses mixed/partial publication state for diagnosis, reconverges canonical roles, and revokes runtime publication if surviving generation state lacks authoritative publication-head evidence. Hosted CI `34265888259` / rust `102195122469` is terminal SUCCESS on that exact head.

#219 exact `55c8e7c4e4ac022e4d6ca5090c111c79068d137b` serializes startup migration with a PostgreSQL session advisory lock, durable schema-version receipt, exact supported-shape checks, future/partial-schema refusal and ENABLE+FORCE RLS postconditions. Exact-head CI `34270783027` / rust `102211539102` is terminal SUCCESS.

#221 exact `e2ff0fe4055a598a5c450e7942fed2051ec21238` maps an externally managed ordinary PostgreSQL LOGIN to exactly the existing bounded `wardnet_runtime` capability. Its hostile lineage rejects alternate inherited membership and wider effective table/inner-admission authority before granting runtime membership. Exact CI `34275523673` / rust `102227465852` is terminal SUCCESS; fresh submitted reviews and inline threads are zero.

#223 exact `0876c55fdc82927adaece4f3bb414a7a631dea68` is the pooled transaction-local tenant-session child. It binds `wardnet.tenant_id` only through parameterized transaction-local `set_config(..., true)`, holds checkout through commit/rollback, transfers cancelled checkout into asynchronous rollback before reuse, and proves physical-connection cleanup, cross-tenant RLS isolation and concurrent tenant independence on real PostgreSQL 18.4. Exact CI `34284257853` and Fuzz `34284257807` are terminal SUCCESS. Production connection construction remains TLS-capable.

#224 exact `c805d83484be91a157ed8350944bf7d35d37bc7e` is the bounded typed publication-repository child. Its real PostgreSQL acceptance publishes `8@8 -> 9@9`, rejects historical `8@10` ABA as stable `PublicationConflict`, preserves generation 9 as replayable last-known-good, and rejects a different token rebound to ordinal 9. Exact CI `34290913936` and Fuzz `34290913959` are terminal SUCCESS.

#225 exact `fa9d2afe7783489581ee68fad0be4b4b55dcebc0` requires transaction-local actor and decision attribution for every new publication, makes missing/partial attribution abort without residue, keeps exact replay from duplicating audit evidence, and treats replay with mismatched attribution as `PublicationConflict`. Exact CI `34299081730` and Fuzz `34299081819` are terminal SUCCESS.

#226 exact `da5f2b01163e9db1416bfa4162ebdb7953778fc5` closes the generic raw-SQL repository escape hatch. Ordinary application callers retain typed tenant-scoped operations without an arbitrary-SQL callback/query API. Exact CI `34300579943` and Fuzz `34300579966` are terminal SUCCESS.

#228 exact `f0c42b84b16549f58a0f93d8b74d643cebba91bf` reads only the complete authoritative current publication and fails closed when the current head cannot resolve to required immutable publication/audit evidence. Exact CI `34306473646` and Fuzz `34306473577` are terminal SUCCESS.

#229 exact `1df6e3e094d92ad8038fa6c911a7a1aaddc7a6c0` skips only driver-known closed clients before any Wardnet database operation begins, never replays a live query/transaction after failure, and returns typed `PoolUnavailable` when every fixed member is closed. Exact CI `34308523814` and Fuzz `34308523755` are terminal SUCCESS.

#231 exact `b2476631f1cfd6b30ca5d95a883e7dfedb4ec2c5` keeps a private TLS-capable reconnect capability, replenishes one failed fixed slot under its mutex before new work, and proves sequential original-member loss, prompt reconnect failure, and one replacement under eight concurrent checkouts. CI `34312273421` and Fuzz `34312273443` are terminal SUCCESS.

#233 current exact `c56e041c149ec77fdd2d4e36ba253be665ed6c65` closes the first slow-reconnect head-of-line slice. Test-only `24ef736bc88f848206f43cba6c746ebcc1d4783c` reached the intended real-PostgreSQL RED in CI `34314318818`: a stalled replacement for one dead slot prevented use of an unrelated established healthy slot before 750 ms. The minimum repair scans the complete round-robin window non-blockingly, immediately returns established healthy capacity, and repairs a closed candidate only after separately acquiring/rechecking that slot. A predecessor fixture was repaired to test bounded eventual asynchronous replenishment instead of a fixed three-probe timing assumption. Exact CI `34318164350` and Fuzz `34318164292` are terminal SUCCESS.

#234 current exact `ca21804350476b4dc916d53c6e0e05f13f124bbf` closes the bounded reconnect-readiness continuation without replaying database work. Two hostile real-PostgreSQL REDs were executed. Test-only `f47f6191e4fc3bd4236c6d6de584740eb2a1e759`, CI `34321911134`, proved all-dead stalled reconnect could exceed the outer 750 ms buyer-path guard. Test-only `3faa20396cc1646720641f8ce0b45ac842890362`, CI `34323310347`, then proved a stalled background repair could own a failed slot mutex and let the same unbounded condition escape after the last healthy member died. Minimum production `744564c8ab6048d9296bff2794baa2571859b112` applies one 500 ms repository-owned readiness window to background replacement and to all-dead slot-lock plus reconnect acquisition. Formatter-only current `ca218043...` is terminal GREEN: CI `34324806953` / rust `102379503888` and Fuzz `34324806980` are SUCCESS; fresh submitted reviews and inline threads are zero. #234 remains Draft behind #233, so its evidence is not protected truth and does not transfer forward.

#235 records the next explicit durability gap: a network failure after PostgreSQL durably commits but before Wardnet receives COMMIT acknowledgement cannot be classified as rollback, and the pool must not blindly replay an already-started publication. Draft #236 is now the test-first child of exact #234. Exact test-only head `1a8ba3402e8f50403a260000d6922b465b029b58` adds a protocol-aware loopback fault proxy around real PostgreSQL 18.4. It forwards one simple-query COMMIT, reads PostgreSQL's first backend response, drops that response before Wardnet can observe success, then requires direct durable `publication:audit:head = 1:1:1`, exact typed resubmission as `Replay`, divergent evidence/attribution rejection, and a stable commit-outcome-unknown classification instead of a generic connection error. Production is byte-identical to #234 on this candidate. No semantic RED is claimed until exact hosted execution reaches the intended final classification assertion; Docker/bootstrap/protocol/rustfmt/runner failures are fixture defects and must be repaired first.

Production PostgreSQL authority remains disabled. #80/#192 still require #236's complete committed-but-ack-lost and pre-COMMIT-loss recovery evidence; any separately unresolved divergent-writer concurrency; complete unreliable-network/readiness/liveness semantics; authoritative backup/restore with retention/encryption and measured RPO/RTO; protected integration and immutable release evidence. An admitted or partially persisted generation must never silently become current truth.

## Gateway and Agent Artifact Admission security lanes

#181 owns the route path-segment boundary repair: exact-or-slash-descendant matching replaces raw lexical prefix capture while preserving root, trailing slash, disabled routes and longest valid match. Repository/Fuzz/Security/SAST are GREEN on its unchanged code head; delegated CodeQL receipt reconciliation remains central-owner evidence.

#129 remains the Rust-first Agent Artifact Admission lane. It is pre-execution policy/evidence authority only: retrieved-byte integrity, AppGuardrail analysis, quarantine execution, Noema activation, EgressWeave transport and contextual-orchestrator provider orchestration remain separate canonical authorities.

#155 remains the fail-closed management-authentication prerequisite for non-loopback exposure. #93 remains the deterministic persistence-fault seam.

#127 remains a material embedded admin-console accessibility lane and now has a real-browser acceptance harness rather than source-string-only evidence. Production UI remains confined to its accessibility candidate; test-only browser work launches the shipped Wardnet binary on an ephemeral loopback address, uses runner-provided Chrome/ChromeDriver through W3C WebDriver/CDP, observes a real loading state and configured-auth permission-denied audit state, verifies Tab→visible skip-link→Enter→`#main` focus transfer, inspects Chrome's computed accessibility tree for the admin credential name/description, verifies atomic polite KPI status semantics, and checks 375/768/1440 px overflow/clipping. Exact `72d8ee69745f0f493e2a20888d7ecd561e608d2b` acquired hosted compute and failed only `cargo fmt --check`; formatter-only successor `6ec3d18f85b6e76645566b671de04d062b8aa96a` is current. No browser RED/GREEN claim is made until exact-current CI actually executes the shipped-browser assertions. Hosted absence of `CHROMEWEBDRIVER` would be infrastructure failure, not a passing skip.

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
3. #80/#192 PostgreSQL production authority through #236, then remaining divergent-writer/unreliable-network/backup-restore acceptance;
4. trusted client attribution and bounded/distributed admission reconstructed without duplicate #140/#165 authority;
5. immutable EgressWeave authorization/evidence integration for outbound transport;
6. deployed attack-path evidence and proven Coraza/CRS + Suricata enforcement without inventing substitute detection authority;
7. Agent Artifact Admission integrated with released foreign-owner ports;
8. transactional outbox/idempotent workers, Keyverse-backed identity/approval and distributed admission/trusted attribution;
9. material admin-console real-browser/accessibility/responsive acceptance where the console remains buyer-visible;
10. immutable package/image/SBOM/provenance/reproducibility/promotion/rollback plus production telemetry/SLO/incident/restore evidence;
11. one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, in-progress/queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.