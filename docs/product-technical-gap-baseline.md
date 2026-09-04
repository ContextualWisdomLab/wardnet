# Product and technical gap baseline

Snapshot date: 2026-09-04T18:50+09:00. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security results and releases before any merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger, not an archive of superseded run state.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane and the Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, Audit-Provenance and Agent Artifact Admission bounded contexts. `quarantine-sandbox-runtime` owns hostile execution isolation and cleanup; `contextual-orchestrator` owns Agent/LLM/provider routing; EgressWeave owns outbound HTTP-policy authority; `appguardrail` owns deterministic static security analysis and scan receipts. Wardnet consumes released/versioned ports or ACLs only: no source copy, cross-service SQL or mutable sibling dependency.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel. `enterprise-architecture-core` is the EA Decision Plane. Both remain read-only from this lane while their Context Fabric owner is active. Wardnet security findings/verdicts remain Wardnet evidence; EA may reference validated risk/remediation evidence but must not copy it as authoritative architecture truth.

Fresh release inventory on 2026-09-04 still finds no compatible immutable GitHub Release for Wardnet, Context Graph Contracts, EA Core, contextual-orchestrator, quarantine-sandbox-runtime, EgressWeave or appguardrail. Mutable sibling heads are non-authoritative.

## Protected truth and control plane

Protected/default Wardnet truth remains `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. Live organization ruleset `18156473` still applies to `~DEFAULT_BRANCH` with one generic approving review, no required reviewer/team, required review-thread resolution and central required workflows, deletion/non-fast-forward protection, plus `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval and bot/model-as-human approval remain forbidden. `.github#772` and its current owner-plane successor own the narrow ruleset reconciliation; deterministic workflow/security/coverage/SBOM/provenance/thread/branch-integrity controls must remain.

Runner/event/review materialization belongs to `.github#712` and related central lanes. Queued/pre-checkout jobs, missing workflow materialization, `runner_id=0`/null, empty steps, startup failures and model-review requests that never materialize a current-head verdict are non-passing. They do not justify no-op source churn, predecessor-evidence reuse or routine bypass. Current Wardnet #129 runner specimen is recorded on `.github#712` comment `5538701621`.

## Immediate protected-main security path

- **#155 management auth** — exact `e6f05d77858e91c176cff25c4b11e790bc5dcdd1`, mergeable but not merge-ready. Repository CI `33590350994`, Fuzz `33590350997`, Security Scan `33590350967` and SAST `33590350991` are terminal GREEN. Required OpenCode bootstrap/source-tree/coverage jobs also passed, but final review job `100659819151` acquired a hosted runner, successfully requested current-head review, then reached the central three-hour administrative boundary without a verdict and the run ended cancelled. `.github#712` comment `5535918616` owns verdict/timeout RCA. This is not a chicken-and-egg bypass case.
- **#77 Rust/deployment hardening** — exact `46fef54c9b5916eb77196fb515a8fabad13a05d1`. RED `43d2c874732063e418b3929e3435c388ccfa7c69` proved a first-match Kubernetes validator could hide a later duplicate target Deployment; GREEN `17a2a1e833e6c4cab6101ef6a534589d75a5920a` requires exactly one target identity and retains hostile duplicate-resource coverage. Fresh current-head CI `33807338426` and OSV `33807339076` are terminal success; Scorecard `33807338399`, Security Scan `33807338277` and SAST `33807338221` remain queued/non-passing, so no merge is authorized.
- **#136 Network-Egress** — exact `28e5776388b2fc31e1d0567382871a1f599aa3ed`, Draft/blocked. Runnable RED `3cb1047416c3aa7fa8eb352b842cc55ad8c21b19` / CI `33698726857` proved manual DNS lookup could outlive the operation budget. Production now carries one absolute Tokio deadline through DNS validation and remaining HTTP work; current head adds a pending-resolver cancellation regression. Exact-head CI/Fuzz/Security/SAST remain queued and the DNS review finding stays unresolved until unchanged-head hosted GREEN. Refresh against protected main after #155 integrates.

## Agent Artifact Admission

Draft #129 is now exact `c2ac4c2c0128e8875d8a45c857d3d771e96ca727`, mergeable on protected `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. It is the pre-execution structured artifact-install security-admission boundary; it does not fetch, decrypt, install or execute workloads and does not own Noema activation, quarantine execution, EgressWeave transport policy or AppGuardrail static analysis.

The branch fail-closes executable/ecosystem confusion, undeclared operands, indirect source/config/workspace/root authority, lifecycle-script/trust/integrity bypasses, Cargo build variants, OCI platform ambiguity and mutable tag-set expansion. Earlier Docker/Podman cardinality repair covers bare `-a`/`--all-tags`, Boolean assignments, bundled `-aq`/`-qa`, and pflag final-shorthand assignment semantics such as hostile `-aq=false` versus admissible `-qa=false`.

Fresh 2026-09-04 Podman primary-source review added two more authority repairs:

- registry-authentication RED `400c53265f21d684ab06232536b50341b5d524c0` proves attached `--authfile=...` and `--creds=...` could otherwise select authentication state/principal while an exact approved digest remained syntactically admissible; causal GREEN `3eade5d41c50d1ad4e48118014c50acf5d8f3793` rejects those options as `alternate_trust_root`;
- image-decryption RED `d7aa94fc3846e0ed189f90b5525df03d1a62e3ee` proves attached `--decryption-key=key:passphrase` could otherwise select secret-bearing decryption authority through untrusted argv; causal GREEN `261ecc20e280c3af45798cc396088260eb94ba50` rejects it at the same bounded authority predicate;
- doctoring `841abfd0a8494a2111afc8638ee6a863e1f75a18`, CHANGELOG `32c748e346f6dbe8b67514ffeb25dd19dfdbb531`, and current threat-model head `c2ac4c2c0128e8875d8a45c857d3d771e96ca727` keep the decision and downstream secret/runtime ownership code-current.

Wardnet never reads an authfile, credential, key, certificate or passphrase and does not authenticate to registries or decrypt images. Those authorities remain separately governed downstream secret/deployment/runtime boundaries.

Exact-head #129 CI `33860116349`, SAST `33860116392`, Security Scan `33860116481` and Fuzz `33860116659` are queued. CI job `100982384456` is pre-checkout with `steps=[]`, `runner_id=null`, no runner/group identity and exact `head_sha=c2ac4c2c...`. Returned inline review threads are resolved; review submissions remain COMMENTED rather than independent approval. `.github#712` comment `5538701621` carries exact current runner-admission RED/GREEN acceptance.

Context Fabric owner handoffs are current on `context-graph-contracts#27`: comment `5538703380` requires provider-neutral contracts to reject raw decryption keys/key paths/passphrases as artifact authority and to carry only bounded secret-policy/key-handle/profile references where needed. EA owner handoff `enterprise-architecture-core#45` comment `5538705406` requires architecture projections to retain only immutable provenance/authority/profile/evidence references, never raw secrets, Podman syntax or Wardnet verdicts as authoritative architecture facts.

## Release and repository supply chain

#164 is exact `1d3f5a4bd618084031f3e722804b7c61303baeb5`, Draft and stale on an older #77 parent. It separates PR build evidence from protected-main OIDC attestation authority, binds source/version/hashes and repairs a zero-job `runner.temp` workflow defect. Its release workflow materializes but the build remains runner-queued. After #77 reaches protected main, preserve the child delta in a non-force restack and reacquire exact-head evidence. #84 still requires immutable OCI identity/container-filesystem SBOM, admission-time verification, reproducibility, retention and tested migration/canary/rollback on one protected release candidate.

#160 is exact `962623884347ccd52e653fb59504a7b848292086`. The first merged central reusable Scorecard owner would regress protected Wardnet from Scorecard v2.4.4 to v2.4.3; `.github#1777` owns the non-regressing protected successor. Wardnet keeps a thin caller and will consume only the protected successor SHA.

#153 remains the clean explicit-hosted-runner root at `b663f9d200e5f385c7dd067d074940a02836c68e`; #156/#157/#158 remain Draft dependents. #159 retains PR-number cancellation for superseded PR runs while keeping push evidence unique per run.

## Context Fabric read-only inventory

Live metadata still reports `develop` as default for both Context Graph Contracts and EA Core while their accepted integration target is protected `main`; branch topology/protection reconciliation remains a Context Fabric/.github owner-path defect, not a user choice. Neither repository currently publishes a GitHub Release.

Context Graph Contracts keeps its stacked provider-neutral contract/release work open, with #27 owning the external-capability/security-artifact-admission grammar. No mutable CGC PR head is release authority. Enterprise Architecture Core keeps its projection stack open; projection receipt work remains Draft/unreleased and #45 owns Wardnet security-control projection acceptance. Missing or zero-tree re-dispatch workflow evidence remains a central control-plane defect rather than architecture evidence.

Canonical dependency lanes remain foreign-owner work and unreleased: quarantine-sandbox-runtime owns credential-free hostile execution evidence; EgressWeave owns exact external-extension/remote-MCP egress mediation; appguardrail owns static skill/plugin supply-chain detectors/receipts; contextual-orchestrator remains model/provider-routing authority. None is copied into Wardnet.

## Live Wardnet queue and order

Fresh open-PR inventory remains 27 lanes: `#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #153, #155, #156, #157, #158, #159, #160, #162, #164`.

Integration is prerequisite-driven: #155, then repaired #77; #136 after #155 truth; #164 only after #77 protected; #129 continues without absorbing quarantine/Noema/CO/EgressWeave/AppGuardrail; #153 before #156/#157/#158; #160 waits for the protected non-regressing central owner. #127 additionally requires real-browser current-head WCAG 2.2 AA evidence. #88 remains architecture-gated until contextual-orchestrator publishes a compatible immutable contract. Broad/stale #90/#95/#112/#114/#115 are repair/transfer lanes rather than Close candidates. #162 separately owns the 2B-KRW customer-readiness versus USD-20B product-quality authority split.

#130 is the sole writer for this file. Its GitHub PR metadata, not a self-referential SHA inside this ledger, is the authority for its current exact head. This refresh adopts the live #129 security/authentication/decryption delta, current runner evidence and owner handoffs instead of duplicating the baseline on another branch. #140's PR body is now code-current at `6b0219dad241cfea9969e7e05c11a9937131b36b`; the older ledger statement that its body still named `9389a2d...` is retired.

PR retirement requires protected merge, explicit user instruction, malicious/no-valid delta, or verified complete successor transfer of useful code/tests/fixtures/contracts/evidence.

## Open production gaps

Buyer-visible order remains: #78 management auth; #79 outbound policy/evidence/deadline; #11 real attack-path CI and #75 deployable public path; #128 Agent Artifact Admission; #80 PostgreSQL authority/tenant isolation then #81 transactional outbox; #82 Keyverse identity/approval and #83 distributed admission; #86 proven Coraza/CRS and Suricata detection; #84 immutable release evidence; #85 telemetry/SLO/incident/restore; #87 final readiness against one immutable protected release identity.

Root `src/lib.rs` remains a modularity pressure point, not evidence by itself for a service split. Prefer a modular monolith until transaction, isolation, scale, deployment or reuse evidence pays for another deployable boundary.

## Standards and release gate

Implementation evidence remains grounded in NIST SP 800-207, NIST SP 800-218/SSDF 1.1, OWASP ASVS 5.0.0 and relevant primary/peer-reviewed work. Citations constrain design but do not prove a control is shipped. Wardnet-owned production code targets 100% statement/branch/edge-case coverage and complete public rustdoc/docstrings; realistic bypass/replay/race/DoS/network/cleanup cases are required where applicable.

No release is authorized at this snapshot. Release requires one exact integrated protected head with current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence, immutable artifact identity and a verified publication path. Feature-branch artifacts or attestations remain branch evidence only.
