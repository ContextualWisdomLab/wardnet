# Product and technical gap baseline

Snapshot date: 2026-09-04T16:45+09:00. Re-read live refs, PRs,
reviews/threads, exact-head checks, rulesets, security results and releases
before any merge, release, restack or foreign-owner handoff. This is the
Wardnet-owned current-state ledger, not an archive of superseded run state.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane and the Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, Audit-Provenance and Agent Artifact Admission bounded contexts. It does not own hostile execution or Agent/LLM orchestration.

`quarantine-sandbox-runtime` owns hostile execution isolation and cleanup; `contextual-orchestrator` owns Agent/LLM/provider routing; EgressWeave is the canonical outbound HTTP-policy candidate; `appguardrail` retains application-guardrail authority. Wardnet consumes released/versioned ports or ACLs only: no source copy, cross-service SQL or mutable sibling dependency.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel. `enterprise-architecture-core` is the EA Decision Plane. Both remain read-only from this lane while their Context Fabric owner is active. Wardnet findings/verdicts stay Wardnet evidence; EA may reference validated risk/remediation evidence but must not copy it as authoritative architecture truth.

No compatible immutable GitHub Release currently exists for Wardnet, Context Graph Contracts, EA Core, contextual-orchestrator, quarantine-sandbox-runtime, EgressWeave or appguardrail. Mutable heads are non-authoritative.

## Protected truth and control plane

Protected/default Wardnet truth is `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. Live organization ruleset `18156473` still applies to `~DEFAULT_BRANCH` with one generic approving review, no required reviewer/team, required thread resolution and central workflows, deletion/non-fast-forward protection, plus routine `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval and model/bot-as-human approval remain forbidden. `.github#772` owns the narrow ruleset reconciliation; deterministic workflow/security/coverage/SBOM/provenance/thread/branch-integrity controls must remain.

Runner/event/review materialization belongs to `.github#712` and related central lanes. Queued/pre-checkout jobs, `runner_id=0`, empty steps, startup failures and model-review requests that never materialize a current-head verdict are non-passing. They do not justify no-op source churn, predecessor-evidence reuse or routine bypass.

## Immediate protected-main security path

- **#155 auth** — exact `e6f05d77858e91c176cff25c4b11e790bc5dcdd1`,
  Blocked on live governance, not source correctness. Repository
  CI/Fuzz/Security/SAST are terminal GREEN and returned inline threads are
  resolved. Required OpenCode bootstrap/source-tree/coverage passed, but final
  current-head review job `100659819151` acquired runner `1001655142`, issued
  the authenticated review request, then reached the three-hour administrative
  boundary without a verdict and ended cancelled. Required Noema Review is also
  failing on the exact head, and GitHub still records
  `mergeStateStatus=BLOCKED` / `reviewDecision=REVIEW_REQUIRED`. `.github#712`
  comment `5535918616` owns verdict/timeout RCA. #78 closes only after this
  delta reaches protected main through satisfiable ordinary governance.
- **#77 Rust/deployment hardening** — exact
  `46fef54c9b5916eb77196fb515a8fabad13a05d1`, Blocked. RED
  `43d2c874732063e418b3929e3435c388ccfa7c69` proved a first-match Kubernetes
  manifest validator could hide a later duplicate target Deployment. GREEN
  `17a2a1e833e6c4cab6101ef6a534589d75a5920a` requires exactly one target
  identity and keeps the hostile duplicate-resource regression. On the live
  head, Required Noema Review is failing, Required OpenCode Review has
  cancelled review-bootstrap attempts, and SAST/Scorecard/Security subchecks
  remain queued.
- **#136 Network-Egress** — exact
  `28e5776388b2fc31e1d0567382871a1f599aa3ed`, Draft/blocked. Runnable RED
  `3cb1047416c3aa7fa8eb352b842cc55ad8c21b19` / CI `33698726857` proved manual
  DNS lookup could outlive the operation budget. Production now carries one
  absolute Tokio deadline through `lookup_host` and remaining HTTP work;
  current head adds a forever-pending resolver cancellation regression.
  Exact-head CI/Fuzz/Security/SAST/Noema/OpenCode/Strix remain queued, and the
  DNS review thread stays unresolved until unchanged-head hosted GREEN.
  Refresh against protected main after #155 integrates.

## Agent Artifact Admission

Draft #129 is exact `6dfd777e1e9ce8b42c87c3311911a35f64f97190`, mergeable on protected `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. It is the pre-execution structured artifact-install security-admission boundary; it does not fetch or execute workloads.

The lineage fail-closes executable/ecosystem confusion, undeclared operands, indirect source/config/workspace/root authority, lifecycle-script/trust/integrity bypasses, Cargo build variants, OCI platform ambiguity, Podman registry trust weakening and repository-wide mutable OCI tag expansion. Bare Docker/Podman `-a` / `--all-tags` was already blocked by RED `d7f429c37a3bd26ea746254defc5d65f33ef71f2` -> GREEN `7f06137453dc2296e4c4ac8c439777bf19ba7244`.

Fresh hostile review found the equivalent Boolean-assignment bypass. RED `883d1d37e05b0ccd9d30b2c1b25fd7d53c6fc8d8` covers `--all-tags=true` / `-a=true`; causal GREEN `e9e07e696c013dab88df6a5a6dc1be8306b9b688` classifies true assignments as `artifact_not_approved`; coverage `2207a6f79522dc8b6cb95e817be648bb6ef9a7f3` adds long/short true forms and explicit-false non-regression. Exact `6dfd777e...` records Docker/Podman/NIST traceability.

Exact-head CI `33848015533`, SAST `33848015479`, Security `33848015485` and Fuzz `33848015550` remain queued; `.github#712` comment `5537096153` owns runner-acquisition acceptance. Returned inline threads are resolved. Context Fabric/EA owner handoffs remain on `context-graph-contracts#27` and `enterprise-architecture-core#45`: Wardnet security-artifact admission and Noema governed activation/orchestration are separate authorities; neither receipt may substitute for the other.

## Release and repository supply chain

#164 is exact `1d3f5a4bd618084031f3e722804b7c61303baeb5`, Draft and stale on an older #77 parent. It separates PR build evidence from protected-main OIDC attestation authority, binds source/version/hashes and repairs a zero-job `runner.temp` workflow defect. Its release workflow materializes but the build remains runner-queued. After #77 reaches protected main, preserve the child delta in a non-force restack and reacquire exact-head evidence. #84 still requires immutable OCI identity/container-filesystem SBOM, admission-time verification, reproducibility, retention and tested migration/canary/rollback on one protected release candidate.

#160 is exact `962623884347ccd52e653fb59504a7b848292086`. The first merged central reusable Scorecard owner would regress protected Wardnet from v2.4.4 to v2.4.3; `.github#1777` owns the non-regressing protected successor. Wardnet keeps a thin caller and will consume only the protected successor SHA.

#153 remains the clean explicit-hosted-runner root at `b663f9d200e5f385c7dd067d074940a02836c68e`; #156/#157/#158 remain Draft dependents. #159 retains PR-number cancellation for superseded PR runs while keeping push evidence unique per run.

## Context Fabric read-only inventory

Live metadata still reports `develop` as default for both Context Graph Contracts and EA Core; accepted integration/default is protected `main`, so branch topology/protection repair remains the Context Fabric/.github owner path.

For `context-graph-contracts`, dependency order remains `#4 -> #6 -> #7 -> #8 -> #12 -> #13 -> #14 -> #16 -> #17 -> #18 -> #19 -> #25 -> #20 -> #21`. #25 is exact `187f45927e697cfad9ac5b2523dfd86b695aa072` with current package/reproducibility/supply-chain workflows terminal GREEN on its recorded ancestry. #20 is exact `475ce14185db697940e8219c3cda7f24d66f3ed7`. #21 is exact `5cfab7d4819b94f3679d649367868e60f9c0d55a`, Draft/non-mergeable on stale ancestry with zero current PR workflows. #27 owns the external-capability/admission grammar repair. No mutable PR head is release authority.

For `enterprise-architecture-core`, parent #39 remains exact `c063570bd9177578fa75be69defd81c99e6ba2f3` with terminal-success repository workflows on its recorded ancestry. Projection child #40 advanced linearly to exact `8266a7841550963072ec00a4be05eac41e894b59`, remains Draft/non-mergeable on obsolete #39 ancestry and currently has zero PR workflow runs. Its one new owner commit, `test: require projection semantic profile identity`, adds `profile_id` to required projection-receipt semantics and rejects a quarantine connector receipt that keeps only a version while dropping its profile identity. Preserve that read-only owner progress; it is source/test evidence, not hosted GREEN. The separate Wardnet-security-admission versus Noema-activation architecture acceptance remains open on #45.

## Live Wardnet queue and order

Fresh open-PR inventory contains 27 lanes: `#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #153, #155, #156, #157, #158, #159, #160, #162, #164`.

Integration is prerequisite-driven: #155, then repaired #77; #136 after #155
truth; #164 only after #77 protected; #129 continues without absorbing
quarantine/Noema/CO; #153 before #156/#157/#158; #160 waits for the protected
non-regressing central owner. #127 additionally requires real-browser
current-head WCAG 2.2 AA evidence. #88 remains architecture-gated until CO
publishes a compatible immutable contract. Broad/stale
#90/#95/#112/#114/#115 are repair/transfer lanes, not Close candidates. #130 is
the sole writer for this file and is itself Draft/blocked with fresh exact-head
CI/CodeQL/OpenCode/Noema/Security/SAST/Strix runs queued on
`codex/main-gap-followup@c03fad0`. #140 is non-draft but equally blocked until
its fresh exact-head CI/Fuzz/CodeQL/OpenCode/Noema/Security/SAST/Strix results
land on `feat/runtime-config-bootstrap-snapshot@6b0219d`. #162 separately owns
the 2B-KRW customer-readiness versus USD-20B product-quality authority split.

PR retirement requires protected merge, explicit user instruction, malicious/no-valid delta, or verified complete successor transfer of useful code/tests/fixtures/contracts/evidence.

## Open production gaps

Buyer-visible order remains: #78 management auth; #79 outbound policy/evidence/deadline; #11 real attack-path CI and #75 deployable public path; #128 Agent Artifact Admission; #80 PostgreSQL authority/tenant isolation then #81 transactional outbox; #82 Keyverse identity/approval and #83 distributed admission; #86 proven Coraza/CRS and Suricata detection; #84 immutable release evidence; #85 telemetry/SLO/incident/restore; #87 final readiness against one immutable protected release identity.

Root `src/lib.rs` remains a modularity pressure point, not evidence by itself for a service split. Prefer a modular monolith until transaction, isolation, scale, deployment or reuse evidence pays for another deployable boundary.

## Standards and release gate

Implementation evidence remains grounded in NIST SP 800-207, NIST SP 800-218/SSDF 1.1, OWASP ASVS 5.0.0 and relevant primary/peer-reviewed work. Citations constrain design but do not prove a control is shipped. Wardnet-owned production code targets 100% statement/branch/edge-case coverage and complete public rustdoc/docstrings; realistic bypass/replay/race/DoS/network/cleanup cases are required where applicable.

No release is authorized at this snapshot. Release requires one exact integrated protected head with current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence, immutable artifact identity and a verified publication path. Feature-branch artifacts or attestations remain branch evidence only.
