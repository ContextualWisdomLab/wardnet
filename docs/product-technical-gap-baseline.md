# Product and technical gap baseline

Snapshot date: 2026-09-08. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. PR and issue bodies retain detailed RED→GREEN receipts; this document keeps the current authority, dependency and buyer-gap state rather than duplicating every historical run.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protect-mode forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

Fresh release inventory remains empty for Wardnet and the owner contracts required for the current runtime integration path. Mutable owner PR heads are therefore design/compatibility evidence, not immutable production authority.

## Protected truth, governance and central control plane

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` from merged #171. There is no immutable Wardnet GitHub Release, so protected source truth is not yet a release identity.

Organization ruleset `18156473` still has the solo-maintainer-incompatible generic approval requirement. `.github#772` is the canonical governance repair: remove or replace only the structurally impossible human-approval count while preserving deterministic CI/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity requirements. Self-approval, model/bot-as-human approval and routine administrator bypass remain forbidden.

Runner/materialization remains `.github#712` authority. Queued/pre-checkout `runner_id=0` is incomplete evidence, not a leaf-source defect. Wardnet has repeatedly shown the same `ubuntu-24.04` lanes later acquiring GitHub-hosted compute, so source or runner-label churn is not a default repair.

Delegated CodeQL remains a central producer/receipt path until its repaired exact head reaches protected central truth. `.github#2028` was squash-merged into central protected `main@7fd571dbcdbae6acf29d8f4ee704d7ba6297e4db`, but its statusless fallback was rejected because it did not bind enough provenance. Canonical successor `.github#1902` is now open/Ready at exact `df35cfe57b90bfcf6caac1440390c057ddc48347`: it preserves the authenticated receipt/SARIF design, repairs mixed terminal/pending settlement-map loss, and paginates all producer job/artifact collections before provenance filtering. The previously identified later-page completeness finding is therefore repaired in source and executable RED→GREEN contracts. Five exact-head hosted workflows and qualifying independent review are still pending merge authority; predecessor local verification does not transfer. Until this exact central repair reaches protected truth and unchanged Wardnet consumers prove the then-live receipt path, code-bearing Wardnet CodeQL failures remain valid non-passing consumer evidence. Docs-only CodeQL success is not proof of producer integration.

## Outbound destination reputation stack

### Architecture and root contract

#173 remains Proposed architecture for the Wardnet-owned reputation engine. It does not claim runtime enforcement. Production composition still requires immutable compatible EgressWeave authorization/evidence; Wardnet does not implement URL/DNS/peer/redirect/proxy/TLS/resource authorization locally.

#175 is the root pure-Rust `wardnet.reputation.v1` contract. It keeps assessment, evidence health, action and reason independent; bounds untrusted fields; binds tenant/source/policy/canonicalization evidence; and remains Draft because its code-bearing exact head is still subject to the central delegated-CodeQL/governance path.

The dependent evidence stack remains ordered and Draft: #176 business-authorization binding → #178 decision freshness → #179 explicit evidence-snapshot health → #183 exact source-generation membership → #185 lifecycle-invalid enforcement rejection → #187 producer-version/tombstone lifecycle cursor → #189 atomic complete-source replacement → #191 source-generation ABA replay. Their exact-head repository/fuzz GREEN receipts remain in their PR bodies and do not transfer after parent movement.

### Durable ABA authority: #192 under #80

#191 currently preserves the executed hostile RED proving a current-only lifecycle cursor cannot prevent historical opaque source-generation ABA reuse across multiple transitions. The causal production authority is therefore durable state, not a larger in-memory recent-token cache.

P0 #192 requires tenant-scoped durable uniqueness for both `(source_id, source_generation)` and `(source_id, source_generation_ordinal)`, atomically coupled with producer lifecycle state, accepted immutable evidence snapshot, completeness/pagination proof and last-known-good publication. Real PostgreSQL acceptance must cover `8@8 -> 9@9 -> 8@10`, ordinal collision, concurrent writers, crash/retry/idempotency, default-deny RLS, pooled-context isolation, migrations and backup/restore survival.

#80 remains canonical for the broader production PostgreSQL repository/transaction/migration/RLS/recovery boundary. Stale mixed #95 is preservation evidence only and must not be imported wholesale.

### Production-state prerequisites: #140 → #193 → #194

#140 is the canonical Runtime Configuration foundation. Its current bounded candidate centralizes non-secret bootstrap into one immutable snapshot and includes the executed architecture-fitness repair that rejects aliased/grouped direct `std::env` reads. It remains Draft pending the central CodeQL/governance path and must reach protected truth before dependent state work integrates.

#193 is a Draft child of #140 that makes deployment intent and mutable-state authority explicit. Production requires an explicit PostgreSQL authority declaration and cannot silently fall back to file/memory state; PostgreSQL selection remains fail-closed until #80's durable adapter exists. Exact current #193 head is `88e54cd18fb686a6b61525c400531820f7a014b4`, with repository-owned CI/Fuzz GREEN recorded in the PR body.

#194 is the next Draft child and now owns PostgreSQL DSN bootstrap secrecy. Semantic RED `#194@9436ad4c7729f1a6a9f6542aa2919b9ae0e45012`, CI `34185447086` / rust `101932754357`, acquired a real GitHub-hosted `ubuntu-24.04` runner, passed formatting, then failed in locked workspace tests while production source was unchanged. Current causal repair head `eeddc49170b30169bb3fd6a918ee91a74e1ce9f3` keeps `postgres_dsn` inside `CredentialRegistry`, applies file-over-environment precedence, drops empty DSNs, and deliberately leaves `CredentialSource` as administrator-auth provenance so PostgreSQL secret presence is not exposed through health/support metadata. This slice opens no database connection and does not claim durability. Exact-current CI `34189654335` and Fuzz `34189654329` are currently queued/non-passing; the CI job is pre-checkout `runner_id=0` and has been handed to `.github#712` without no-op retrigger or source churn.

## Gateway and Agent Artifact Admission security lanes

#181 owns the route path-segment boundary repair. Its hostile RED proves raw lexical prefix matching lets `/api` capture `/apix` and `/api/admin` capture `/api/administrator`; the minimal candidate uses exact-or-slash-descendant matching while preserving root, trailing slash, disabled routes and longest valid match. Repository/Fuzz/Security/SAST are GREEN on its unchanged code head; delegated CodeQL receipt reconciliation remains central-owner evidence.

#129 remains the Rust-first Agent Artifact Admission lane. It is pre-execution policy/evidence authority only: retrieved-byte integrity, AppGuardrail analysis, quarantine execution, Noema activation, EgressWeave transport and CO provider orchestration remain separate canonical authorities. Its unchanged code head has repository/Fuzz/Security/SAST GREEN and the same central delegated-CodeQL failure class.

#155 remains the fail-closed management-authentication prerequisite for non-loopback exposure. #93 remains the deterministic persistence-fault seam. #127 remains incomplete until the material embedded admin-console accessibility change has real-browser current-head keyboard/focus/name/role/value, responsive and state evidence rather than source-string tests alone.

#77 remains the Rust-toolchain/reproducibility prerequisite; #164 remains its dependent release-evidence lane and cannot publish from a feature branch or transfer predecessor SBOM/provenance evidence after restack.

## Other preservation and integration lanes

#167/#170 retain MISP/DNSBL source-ownership and source-severity semantics. #115/#136 preserve threat-feed and outbound-policy hostile consumer evidence but cannot merge a second EgressWeave transport-policy authority. #88 preserves credential-guard evidence pending an immutable compatible contextual-orchestrator boundary rather than retaining LiteLLM/provider-routing authority in Wardnet. #90/#95/#112 are preservation lanes whose valid unique Wardnet deltas must be reconstructed from current protected truth instead of mechanically merging stale aggregate source.

#134 support-bundle contract, #162 customer-contract-vs-USD-20B-quality authority separation, and #144 Kubernetes source-path migration have already non-force adopted protected #171 and retain unchanged bounded deltas. Their repository/security lanes are GREEN where Wardnet owns them; code-bearing CodeQL failures remain central delegated-receipt specimens rather than reasons for leaf churn.

## Release blockers and buyer-visible gap order

Authority and safety remain ahead of feature breadth. Current release-blocking order is:

1. satisfiable protected governance and authenticated exact-head central evidence;
2. protected management authentication and Runtime Configuration truth;
3. #80/#192 PostgreSQL production authority, tenant/RLS isolation and crash-safe reputation-history publication, with #193/#194 prerequisites integrated first;
4. immutable EgressWeave authorization/evidence integration for outbound transport;
5. deployed attack-path evidence and proven Coraza/CRS + Suricata enforcement without inventing substitute detection authority;
6. Agent Artifact Admission integrated with its released foreign-owner ports;
7. transactional outbox/idempotent workers, Keyverse-backed identity/approval and distributed admission/trusted attribution;
8. immutable package/image/SBOM/provenance/reproducibility/promotion/rollback plus production telemetry/SLO/incident/restore evidence;
9. one immutable protected Wardnet release identity.

The USD 20 billion ambition is a product-quality bar, not pricing, ARR or billing truth. Prefer a modular monolith until transaction/isolation/scale/deployment/reuse evidence justifies a split.

## Release gate

No Wardnet release is authorized. Release requires one exact protected integrated head with terminal current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/thread/migration/rollback/recovery/operability evidence, immutable package/image/source identity and verified publication. Feature-branch artifacts, mutable foreign heads, queued workflows, predecessor GREEN and implicit/routine administrator bypass are non-passing evidence.
