# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth is `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. That protected change makes management writes fail closed when a public bind has no write-capable administrator credential and carries the associated security documentation and hostile tests. It is protected source truth, not an immutable release: the fresh Wardnet GitHub Release inventory remains empty.

Live ruleset `18156473` still carries the generic one-approval solo-maintainer incompatibility tracked by `.github#772`. Self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/deletion/non-fast-forward controls stay fail closed; routine administrator bypass is not merge evidence.

Runner/materialization remains `.github#712` authority when an exact candidate genuinely has no checkout/runner/materialization evidence. Delegated CodeQL current-head verdict settlement remains `.github#1929`; current repair successor `.github#2040` is still an open mutable PR and its recorded base predates current protected central `.github/main`, so it is owner-path progress rather than immutable production authority. Wardnet does not copy central workflow logic, pin mutable central repair heads, add no-op source changes to manufacture dispatch, or promote a later dispatch over a failed required workflow.

PR #130 is the sole writer for this ledger. Every refresh advances its own exact head, so this file deliberately does not embed #130's current SHA as product evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Wardnet does not write either repository while the Context Fabric owner is active. Wardnet, CGC and EA have no immutable GitHub Release at this snapshot, so no mutable CGC/EA proposal is production dependency authority.

CGC #4/#21 remain Draft/unreleased owner work. EA #40 remains Draft owner work. Wardnet does not duplicate their source or promote Wardnet findings into authoritative EA truth; future projection must use released CGC contracts/provenance only.

## Commercial authority separation

Draft #162 owns the naming/authority repair that separates the 2B KRW customer-contract readiness predicate from the standing USD 20 billion product-quality ambition. Reverse-direction restack #315 normally merged protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b` into the commercial-authority branch with expected-head protection and no force/rebase, producing current exact #162 head `3e3a19a115448d5787ceaa34929018fb832fdd3d` on the current protected base.

The protected-main-relative delta remains exactly six paths: `CLAUDE.md`, `README.md`, `docs/commercial/20b-krw-sale-readiness.md`, `docs/commercial/2b-krw-customer-contract-readiness.md`, `docs/commercial/usd-20b-product-quality-bar.md`, and `tests/commercial_authority_architecture.rs`. Protected #155 authentication/security truth is inherited rather than copied. Current exact CI `34577138782` and SAST Semgrep `34577138762` are SUCCESS; Security Scan `34577138789` is queued/non-passing and required CodeQL `34577138720` is FAILURE at the delegated settlement boundary. Keep Draft; no predecessor evidence, no-op redispatch, self/model approval or routine bypass substitutes for exact-current terminal evidence.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Reverse-direction restack #303 adopted protected #155 normally without force or destructive rebase. Current #129 is exact `50be3016353f992100b782fb7765b212ef9fc551` on protected base `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`.

The candidate preserves deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only; it is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

Exact-current CI `34564995768`, Fuzz `34564995811`, SAST Semgrep `34564995820`, and Security Scan `34564995826` are SUCCESS. Required CodeQL PR `34564995839` is FAILURE at the delegated current-head settlement boundary. Keep #129 Draft until terminal-valid CodeQL/current review evidence, owned-production coverage/rustdoc proof, protected-base compatibility and then-live package/SBOM/provenance/governance gates all bind one unchanged head.

## Phishing.Database SSRF repair

Protected-baseline companion #295 established causal RED in hosted CI `34557037833` / rust `103131783940`: an authenticated request-selected Phishing.Database loopback URL was actually fetched through the former non-default-host bypass. Production repair #291 removes request-controlled `domain_url`, `ip_url` and `allow_non_default_hosts`, resolves feed URLs server-side, keeps loopback override under `cfg(test)` only, validates the server-owned source host, and preserves the no-redirect HTTP client.

Current #291 is exact `e01683d526da058a813f8d8f0fe87a52c3594b39` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. Exact-current CI `34565621792`, Fuzz `34565621778`, Security Scan `34565621750`, and SAST Semgrep `34565621831` are SUCCESS. Required CodeQL PR `34565621754` is FAILURE: compatibility job `103159995541` failed before a usable terminal current-head verdict while later dispatch `103161018713` succeeded. That ordering is exact consumer evidence for `.github#1929`, not a reason to weaken or duplicate central workflow authority.

## Gateway route-boundary repair

Issue #180 / Draft #181 owns only the Wardnet route-selection lexical-prefix defect. Its causal RED at `93d097626d96f9adaffc267f47be162c397355f3` proved `/api` captured lexical siblings and `/api/admin` captured `/api/administrator`. The minimum production change keeps exact/slash-delimited descendant matching, root catch-all and longest-valid-match semantics without changing `RouteConfig` or duplicating EgressWeave transport authority.

Reverse-direction restack #309 adopted protected #155 normally, producing current exact #181 `abbaff14a452671238c83c1325da22e15f9ee2ac`. Exact-current CI `34569413771`, Fuzz `34569413780`, Security Scan `34569413792`, and SAST Semgrep `34569413795` are SUCCESS. Required CodeQL `34569413791` is FAILURE at the delegated terminal-verdict settlement boundary. The earlier queued snapshot is superseded. Keep Draft; source churn or guarded bypass is not justified while a required workflow is RED.

## Outbound destination reputation

#173 remains the Proposed Wardnet-owned reputation architecture and has been restored to Draft rather than treated as shipped architecture. Its current exact head `8408c2d50e6419d551bfcccd8d72a97284f36a82` is based on current protected main and has CI `34571861872`, Security `34571861916`, SAST `34571861944`, and CodeQL `34571861874` terminal SUCCESS. Historical Noema/OpenCode failures bind predecessor head `7d0006b0...` and do not transfer as current-head failure or approval.

Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns a destination/reputation verdict into transport authority and does not consume mutable EgressWeave source/PR heads.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence.

Root #140 remains on pre-#155 protected ancestry. Restack helper #310 is Draft and mechanically conflicted against `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`; this is a repair finding, not a close condition. Fresh changed-path comparison isolates the semantic overlap to `src/credentials.rs` and `src/lib.rs`: #140's other four paths do not overlap #155. Repair must preserve #140's immutable non-secret `RuntimeConfiguration` bootstrap/architecture-fitness authority and all #155 credential/header/RBAC/public-bind/401-403/`auth_mode` security semantics, keep secrets under the hardened `CredentialRegistry`, keep parse helpers single-sourced in `runtime_config.rs`, and inherit every non-overlapping protected path. Wholesale ours/theirs selection, force/rebase or dependent stack movement would discard valid authority and is forbidden.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness, ambiguous-COMMIT fail-closed handling, physical recovery drills, divergent-writer serialization and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and lifecycle buyer paths

Draft #127 owns the shipped server-rendered admin-console UI acceptance: real-browser loading/normal/permission-denied states, keyboard skip-link transfer, computed accessibility semantics, atomic status announcements and 375/768/1440 clipping/overflow bounds.

After reverse-direction restack #306, protected #155 changed the startup readiness line to append `auth_mode=<mode>`. Exact `20ace70dc3747b6e3dc0ab54c268f26b368fcaa7` then produced hosted CI RED `34569117311`: the browser fixture parsed the final whitespace token instead of the readiness URL. Concurrent `720e6d0602cf8ea3c7b10d475a626f4aa41c2b4f` was read and preserved but remained RED in CI `34571469777` because it constructed `http://auth_mode=production/`. Minimum causal repair `6c8494098dfe325a6b45922290b43f698931ea13` parses the first token after stable `listening on ` and does not alter production auth, route, network policy or test CSS.

On unchanged exact `6c8494098dfe325a6b45922290b43f698931ea13`, CI `34573088259`, Fuzz `34573088263`, Security Scan `34573088322`, and SAST Semgrep `34573088243` are terminal SUCCESS. Required CodeQL `34573088251` is terminal FAILURE at the delegated settlement boundary. The UI Delivery Gate is therefore functional/browser/accessibility/responsive GREEN but overall PARTIAL because a required central gate is RED; no source churn or bypass is justified.

Draft #245 carries the test-first Unix SIGINT graceful-shutdown repair. Current exact `ca499853b152f80f6bd642060f1b55c5e832e9c5` has CI `34565440911`, Fuzz `34565440918`, Security `34565440891`, and SAST `34565440879` SUCCESS; required CodeQL `34565440897` is FAILURE at the delegated settlement boundary.

Draft #134 has non-force adopted protected #155 through restack #314 and is current exact `b6c1f2cfb9d05f36b5ef14c7be6004c00af762d4`. Its unique delta remains the 38-line support-bundle count/secret-redaction regression. CI `34572688789`, Fuzz `34572688651`, Security `34572688686`, and SAST Semgrep `34572688741` are terminal SUCCESS; required CodeQL `34572688797` is terminal FAILURE at the delegated settlement boundary. Ready metadata was corrected back to Draft.

## Rust reproducibility and release evidence

#77 is the prerequisite Rust/reproducibility foundation for #164. Reverse-direction restack #307 adopted protected #155 normally, producing current exact #77 `1349b75b6e1441e531ebb443b32546ff707ac467`. CI `34569225425` and `34569276612`, Fuzz `34569276590`, Security `34569225343`, and SAST `34569225284` are SUCCESS. Required CodeQL `34569225318` is FAILURE at the delegated settlement boundary. Premature Ready metadata was corrected back to Draft.

Draft #164 owns the release-evidence/SBOM/provenance foundation only; it is not a release. Dependency-first restack #308 adopted exact current parent #77, producing current #164 `5f0be7710d3d36c4847e0c2f0a39de116dcf35e7`. Fresh exact CI `34569305587` is SUCCESS. Parent #77 is still non-integrated and CodeQL RED, so #164 must not outrun it.

The PR-executable release-evidence job remains read-only and may build/test/SBOM/upload evidence but cannot mint OIDC-backed attestations. Protected-main manual dispatch is the only attestation authority. Wardnet's GitHub Release inventory remains empty. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

## Release readiness and buyer gaps

Wardnet is not release-ready. Protected #155 materially improves the management-authentication baseline, but material production gaps remain: Runtime Configuration/Keyverse integration and separation-of-duties; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; current-head graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep #129 and #291 exact-source security lanes unchanged while `.github#1929` repairs required CodeQL settlement; their repository/security lanes are already exact-head GREEN and no-op churn is forbidden. #162 likewise keeps its current source while Security settles and required CodeQL remains RED.

For #127 and #134, the earlier queue snapshots are superseded: repository/security lanes are now terminal GREEN while required CodeQL is RED. For #181 and #77, repository/security lanes are also GREEN while required CodeQL is RED; do not bypass or rerun-storm. #164 remains correctly stacked behind #77.

Repair #310/#140 foundation-first by ordinary non-force semantic conflict integration, then restack dependent trusted-proxy/PostgreSQL lanes in dependency order and invalidate/reacquire their exact-head evidence. Continue central queue/materialization, delegated CodeQL, Dependency Review availability, Context Fabric branch topology and solo-maintainer governance through `.github#712`, `.github#1929`/live successor, `.github#810`, `.github#1137` and `.github#772` rather than leaf workarounds.

Only after protected prerequisites and all then-live gates are terminal-valid should Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL, mutable dependency authority or predecessor-evidence transfer.

## Current Runtime Configuration repair delta

Fresh protected-main comparison exposed an additional #140 restack defect not captured by the earlier conflict summary: protected #155 treats empty or whitespace-only `WAF_IDS_STATE_PATH` as unset, while #140's Runtime Configuration adapter converted such values directly into a `PathBuf`. Test-only hostile RED `87635bbee035e34c2a66c4fe63b66e3c35d99b3b` added `runtime_configuration_ignores_blank_state_path` for empty, space-only, and tab-only input without changing production behavior. A repository `pull_request` run did not materialize for that exact RED head; Required OpenCode run `34579885935` admitted the head but its review/coverage jobs remained queued without a runner, and the exact specimen with RED/GREEN acceptance criteria was handed to canonical runner owner `.github#712`.

Minimum causal repair `d72a67ab0ca9d1d43c26873840a2b7d5db46d250` now filters blank state-path input before `PathBuf` conversion and retains the hostile test. On this exact current #140 head, Required OpenCode run `34580235625` completed bootstrap/cancel/admission jobs on real runners, while `opencode-review` `103202071830`, `coverage-evidence` `103202071832`, and `coverage-source-tree` `103202071880` remain queued with `runner_id=0` and no steps; the current-head specimen was handed to `.github#712` as well. #140 therefore remains Draft, stale-base/conflicted through #310, and non-passing until exact-current semantic execution plus protected-base integration and the other required gates are terminal-valid. Historical GREEN is not reused.