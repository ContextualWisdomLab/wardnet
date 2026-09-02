# Product and technical gap baseline

Snapshot date: 2026-09-02. This is a dated GitHub inventory for `ContextualWisdomLab/wardnet`; every later execution must refetch live heads, bases, checks, rules, releases, and foreign-owner state instead of treating this file as scheduler state.

## Product boundary

Wardnet is the Rust-first gateway/SOC control plane and owns Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, and Audit-Provenance responsibilities. The Agent Artifact Admission Controller is a separate bounded context inside Wardnet's Security Admission subdomain.

Quarantine Sandbox Runtime owns hostile-workload execution isolation. `contextual-orchestrator` owns Agent/LLM orchestration. EgressWeave is the outbound HTTP-policy candidate. Wardnet consumes those capabilities through versioned ports and Anti-Corruption Layers; it must not copy their implementations or access their application databases.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical references, authority, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents/schema/conformance/admission. `enterprise-architecture-core` is the Enterprise Architecture Decision Plane. While the dedicated Context Fabric writer is active, Wardnet treats both repositories as read-only source dependencies and forwards exact architecture/contract evidence through their owner path. Security findings, alerts, malware verdicts, artifact risk scores, prompts, and customer/runtime data do not become authoritative EA facts.

## Protected truth and governance

Protected/default `main` is `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128` at this snapshot. That head contains PR #137's externally provisioned, non-optional administrator Secret boundary. Wardnet still has no GitHub release.

Organization ruleset `18156473` targets `~DEFAULT_BRANCH`. Its pull-request rule currently requires one approving review, dismisses stale approvals, requires review-thread resolution, has no named required reviewer/team, no code-owner review requirement, and no last-push approval requirement. It also requires central workflow evidence for review, scheduling, security, Strix, Semgrep, and Noema plus deletion/non-fast-forward protection.

The bare approval-count requirement is structurally inconsistent with the declared solo-maintainer operating model when no eligible independent human exists. That is a central `.github` governance defect, not a Wardnet product gap and not a request to invent a reviewer. Self-approval and bot/model-as-human approval remain forbidden. `.github#772` owns the minimum repair while preserving deterministic workflow/security/coverage/package/SBOM/provenance/thread/branch-integrity controls.

Runner acquisition has a Wardnet-owned selector repair and independent central/control-plane lanes. Clean runner root PR #149 pins every Wardnet CI/Fuzz/Scorecard `runs-on:` declaration to explicit `ubuntu-24.04` and carries a regression that rejects any other runner value. Its exact head is `b663f9d200e5f385c7dd067d074940a02836c68e`. On that same source revision, repository-owned CI/Fuzz/Security/SAST has previously completed successfully, proving the explicit label itself is supported; fresh #149-triggered runs are again queued and therefore non-passing.

A central Required OpenCode Review run narrowed one remaining acquisition defect. In run `33550235908`, `cancel-superseded-opencode-review-runs` job `99997591272` and `required-workflow-bootstrap` job `99997591649` both acquired `ubuntu-24.04` hosted runners and completed, while downstream `coverage-source-tree` job `100011182700` remained queued with `runner_id=0`, an empty runner name/group, and zero steps. This is lane-specific central scheduling/control-plane evidence, not a Wardnet source failure. `.github#712` owns that causal repair.

A separate exact-head Required Noema Review run on #149 proves that runner acquisition can succeed while the semantic-review control path still fails. Run `33550235981`, job `99997877526`, acquired a hosted runner, validated `wardnet#149@b663f9d200e5f385c7dd067d074940a02836c68e`, minted the repository-scoped Noema token, booted `contextual-orchestrator`, and passed the `orchestrator/free` preflight. The model then cited line 2 even though it was not an exact changed-side line; deterministic validation correctly rejected that citation, but bounded repair exhausted a 900-second absolute deadline. `.github#1613` owns the causal repair: invalid changed-line identity must terminate as bounded `MODEL_OUTPUT_INVALID`/review-unavailable evidence unless an independently valid source-backed finding exists. Wardnet must not mutate a clean leaf to work around that central defect.

An intermediate stack repair exposed an unsafe interaction between PR base retargeting and previously enabled auto-merge. Former support PR #146 was retargeted from `main` to the then-runner feature branch; its existing auto-merge immediately merged the support delta into that feature branch, closing #146 and contaminating former runner PR #147. Protected `main` was not modified. Recovery was non-destructive: #147 was closed; #149 preserves the exact runner-only head, #150 preserves the support-bundle delta as a child of #149, #151 preserves trusted-proxy work on clean #149, and #152 reconstructs readiness metrics on clean #149. Future base retargets must inspect auto-merge state first and must never use an unprotected feature branch as final integration truth.

## Live delivery queue

The fresh inventory contains 23 open PRs including this baseline PR:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #138, #140, #141, #144, #149, #150, #151, #152`.

PR #126 is closed and superseded by #141. PR #137 is merged into protected `main`. PRs #131, #142, #145, #146, #147, and #148 are closed/superseded; their unique semantic deltas are preserved by the live replacements named below. No closed/predecessor check or review evidence transfers to a replacement PR.

Key exact-current candidates verified during this refresh:

| PR | Exact head | Current classification | Evidence / next causal action |
| --- | --- | --- | --- |
| #129 Agent Artifact Admission | `03ee83463604a1eafb13a69f4d34a5a21daed82d` | Draft | Fresh hostile-case TDD closes an explicit install-root capability escape: reviewed artifacts can no longer add global/user/prefix/target/root destination overrides and still receive `allow`. OpenAPI/threat-model contracts include stable `alternate_install_root`; exact-head CI `33580275993`, Fuzz `33580275997`, Security `33580276006`, and SAST `33580275992` are queued/pending and therefore non-passing. Keep Draft until all current repository/security/coverage/package/review-policy gates are terminal clean. |
| #136 outbound destination hardening | `edf5e88d84475ce3694e1cc206605a322ba53016` | Ready | Shared URL validation, resolved-address validation/pinning, no ambient proxy, no automatic redirects, bounded pinned-client lifecycle, safe first-hop response filtering, and executable outbound-policy architecture fitness are present. All current review threads are resolved. Fresh exact-head CI `33578188860`, Fuzz `33578188853`, Security `33578188827`, and SAST `33578188887` are queued; explicit versioned allowlist/deny precedence and complete decision-evidence/operator migration work remain open in #79. |
| #138 fail-closed management auth | `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` | Ready | Repository CI/Fuzz/Security/SAST are terminal GREEN on this exact head and review threads are resolved; central exact-head coverage/review-policy evidence remains independently non-passing until the central control-plane/governance repairs land. |
| #140 runtime configuration snapshot | `43d1b6e9122d8bb5cb882f8fc6e066c63b39ae45` | Ready | Runtime Configuration remains a supporting bootstrap boundary distinct from secret-bearing Credential Registry. Current review threads are resolved; fresh exact-head evidence is required after the latest configuration-seam adjustment. |
| #144 Kubernetes manifest path + public docs | `4b9869f015e552fe5c05c740162466b8d0539f88` | Ready, main-based | Repository-path migration preserves #137's hardened Secret contract and live Kubernetes identities; exact-head review thread is resolved. Keep main-based because auto-merge is enabled; never retarget to an unprotected feature branch. |
| #149 explicit hosted runner | `b663f9d200e5f385c7dd067d074940a02836c68e` | Ready, clean stack root | Exact four-file runner-only replacement. Repository-owned exact-SHA success proves `ubuntu-24.04` support, but fresh PR-specific central evidence remains non-passing. `.github#712` owns downstream runner acquisition, `.github#1613` owns bounded invalid-model-line handling, and `.github#772` owns the solo-maintainer approval-rule mismatch. |
| #150 support-bundle operability evidence | `76037b8ae206ace8dab0e6622dfc9fc88c57deb3` | Ready, stacked on #149 | Preserves former #146's six-file support/readiness/metrics delta on #149. Current-head review repaired the documentation contract: live `/readyz` and `/metrics` snapshots are in the support bundle, while the evidence manifest lists endpoint metadata. After #149 reaches protected `main`, retarget to fresh `main` and reacquire all base-sensitive evidence. |
| #151 trusted proxy attribution | `65a2b7fbf2827f69ae1aa288696b6c5630af28c4` | Ready, stacked on #149 | Clean replacement for stale-base #148. Direct-router and malformed-forwarded-chain defects are repaired; all current review threads are resolved and fresh exact-head CI/Fuzz remain queued/non-passing. |
| #152 readiness metrics | `387a447f856093d02116dfadcf2c4a4a63c6d3ba` | Ready, stacked on #149 | Non-destructive reconstruction of reviewed #142 semantics on final clean runner head. Fresh comparison reports `behind_by=0` and exactly four observability files; all new PR evidence must be regenerated. |

Do not transfer checks, reviews, approvals, artifacts, or source-review conclusions across a head, base, retarget, restack, replacement PR, or protected-base movement. `queued`, `pending`, `skipped`, `cancelled`, `absent`, stale, predecessor-head, status-only, model-only, or synthetic evidence is non-passing.

## Open issues and production order

There are 17 open issues at this snapshot: `#11, #38, #74, #75, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #89, #128, #139`.

1. **Immediate exposure controls:** #78 fail-closed management auth, #79 fail-closed destination policy, #11 real attack-path CI, and #75's repository-path migration implemented by #144 on protected #137 truth.
2. **Security admission:** #128 Agent Artifact Admission; protected `main` cannot claim this control until #129 integrates. The current candidate additionally blocks package-manager destination overrides that would widen a reviewed workspace install into a global/user/alternate-root mutation.
3. **Durable authority and effects:** #80 PostgreSQL production authority and tenant isolation, then #81 transactional outbox/leased workers.
4. **Identity and overload:** #82 Keyverse-backed identity/authorization/approval and #83 distributed/global admission authority with bounded local protection. #151 is the current trusted-network-identity slice of #83; it does not close distributed admission.
5. **Proven security engines:** #86 Coraza/CRS and Suricata production enforcement with reproducible detection/false-positive evidence.
6. **Immutable delivery and operation:** #84 signed/SBOM/provenance release promotion and rollback, then #85 OpenTelemetry/SLO/incident/restore evidence.
7. **Supporting correctness:** #74 deterministic persistence-failure testing, #77 pinned compiler, #139 coherent runtime configuration, #75 post-hardening Kubernetes filename migration, and #149 deterministic hosted-runner selection.

Do not close an issue from predecessor evidence. Close only after the owning protected merge satisfies the issue acceptance contract.

## DDD and implementation gaps

Agent Artifact Admission has a responsibility-aligned crate under `crates/agent-artifact-admission` on #129 with domain-policy independence tests. Protected `main` does not yet contain that control. The latest candidate treats package-manager destination selection as part of the reviewed command capability: explicit global/user/prefix/target/root overrides fail closed at admission, while actual filesystem/mount/process isolation remains owned by the downstream execution broker/quarantine runtime. This preserves the bounded-context boundary instead of moving hostile execution into Wardnet.

The legacy gateway remains concentrated in root `src/lib.rs`; file size alone is not a service boundary, but repeated changes to client attribution, outbound policy, runtime configuration, proxying, SOC integration, rate limiting, support evidence, and management APIs show genuine responsibility-convergence pressure. Structural work must add responsibility/dependency fitness before moving code and should favor a modular monolith until transaction, deployment, scaling, or reuse evidence justifies another deployable.

#140 is the coherent Runtime Configuration migration. `CredentialRegistry` remains the secret-bearing bootstrap owner. New direct process-environment reads outside approved bootstrap adapters are architecture defects.

Network-Egress remains incomplete after #136. Issue #79 still requires reusable versioned hostname/suffix/IP/CIDR/scheme/port policy, deterministic deny-overrides precedence, complete connector parity, decision evidence, and operator migration/rollback/diagnostics.

The old #95 branch is not an acceptable production-integration vehicle. It is a large, diverged, non-mergeable branch that combines Coraza, PostgreSQL, outbox, egress and release responsibilities. Its unique tested deltas are preservation evidence for bounded successor work, not permission to merge a cross-context god-PR. #80, #81 and #86 remain unshipped on protected `main` and should be reconstructed/decomposed responsibility-first without losing unique tests or evidence.

Context Fabric integration remains release-gated. `context-graph-contracts` and `enterprise-architecture-core` are read-only from Wardnet while their dedicated writer is active. At this snapshot both repositories still have no GitHub release, so Wardnet consumes no sibling PR head as a production Context Graph contract. EA projections may carry application/service/API/runtime technology identity, lifecycle, ownership, risk, remediation and transformation references, but not malware verdicts, artifact risk scores, prompts, or customer/runtime truth as authoritative architecture facts.

## Research and standards grounding

This baseline uses external standards and research as constraints and rationale, not as proof that Wardnet currently implements every control.

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207.
- Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218.
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/.
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082.

The standards constrain trust, secure-development, verification and deployment decisions. The microservices evidence is used narrowly to prevent decomposition-by-file-size: split deployables only when responsibility, scaling, transaction, isolation, or reuse evidence justifies the operational cost.

## Quality, security, and release gates

Wardnet-owned production code targets 100% statement and branch coverage and complete public rustdoc/docstrings. Security-critical changes require hostile/bypass/replay/race/DoS/network/cleanup tests and current-source verification of every review finding. Coverage exclusions, source rewriting, skipped required paths, or green statuses bound to a different revision are not acceptable evidence.

A release is not authorized. Wardnet has no GitHub release at this snapshot and production gate issue #87 remains open. Release requires one exact integrated protected head with required CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence and immutable artifact identity. No active PR stack or readiness document substitutes for that evidence.

## Next execution order

1. Drive clean runner root #149 through fresh exact-head repository and central evidence while `.github#712`, `.github#1613`, and `.github#772` repair their respective runner/review/governance control-plane defects.
2. Keep independent work moving while #149 waits. #150, #151, and #152 preserve support, trusted-proxy, and readiness-metrics deltas on clean #149 without predecessor-evidence reuse.
3. Integrate immediate security roots as exact gates become valid: #138 fail-closed runtime authentication and #136 destination-policy slice. Keep #144 main-based so its enabled auto-merge cannot accidentally integrate into a feature branch.
4. Finish #129 as one Agent Artifact Admission bounded context, including the current alternate-install-root hostile-case repair, without absorbing hostile execution isolation or Agent/LLM orchestration.
5. Drain clean supporting work such as #77, #90, #93, #134, #135, #140, #141, #150, #151, and #152 when live exact evidence permits.
6. Decompose/reconstruct #95's still-valuable PostgreSQL/outbox/Coraza evidence into bounded #80/#81/#86 successor lanes rather than merging the combined stale branch.
7. Continue #82/#83/#84/#85 production-readiness work only after their declared dependencies are protected truth.
8. Keep this baseline current whenever protected truth, queue topology, release state, or responsibility boundaries materially change.
