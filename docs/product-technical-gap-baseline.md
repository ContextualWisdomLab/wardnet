# Product and technical gap baseline

Snapshot date: 2026-09-02. This is a dated GitHub inventory for `ContextualWisdomLab/wardnet`; every later execution must refetch live heads, bases, checks, rules, releases, and foreign-owner state instead of treating this file as scheduler state.

## Product boundary

Wardnet is the Rust-first gateway/SOC control plane and owns Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, and Audit-Provenance responsibilities. The Agent Artifact Admission Controller is a separate bounded context inside Wardnet's Security Admission subdomain.

Quarantine Sandbox Runtime owns hostile-workload execution isolation. `contextual-orchestrator` owns Agent/LLM orchestration. EgressWeave is the outbound HTTP-policy candidate. Wardnet consumes those capabilities through versioned ports and Anti-Corruption Layers; it must not copy their implementations or access their application databases.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical references, authority, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents/schema/conformance/admission. `enterprise-architecture-core` is the Enterprise Architecture Decision Plane. While the dedicated Context Fabric writer is active, Wardnet treats both repositories as read-only source dependencies and forwards exact architecture/contract evidence through their owner path. Security findings, alerts, malware verdicts, artifact risk scores, prompts, and customer/runtime data do not become authoritative EA facts.

## Protected truth and governance

Protected/default `main` is `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128` at this snapshot. That head contains PR #137's externally provisioned, non-optional administrator Secret boundary. Wardnet still has no GitHub release.

Organization ruleset `18156473` targets `~DEFAULT_BRANCH`. Its pull-request rule currently requires one approving review, dismisses stale approvals, requires review-thread resolution, has no named required reviewer/team, no code-owner review requirement, and no last-push approval requirement. It also requires central workflow evidence for review, scheduling, security, Strix, Semgrep, and Noema plus deletion/non-fast-forward protection.

The bare approval-count requirement is structurally inconsistent with the declared solo-maintainer operating model when no eligible independent human exists. That is a central `.github` governance defect, not a Wardnet product gap and not a request to invent a reviewer. Self-approval and bot/model-as-human approval remain forbidden. `.github#772` and its executable governance PR own the minimum repair while preserving deterministic workflow/security/coverage/package/SBOM/provenance/thread/branch-integrity controls.

Runner acquisition has both a Wardnet-owned deterministic selector repair and an independent central/provider lane. Clean replacement PR #147 pins Wardnet runner-backed CI, Fuzz, and Scorecard jobs to explicit `ubuntu-24.04` and carries the permanent regression that rejects `ubuntu-latest`. Its exact head is `2d41c4079f9a4465c3142a0aa2dd5895cb11f793`. Earlier repository-owned runs on this exact commit proved that the explicit selector can acquire a real hosted runner and complete CI/Fuzz/Security/SAST, but fresh PR #147 runs are again queued and therefore non-passing. This does not establish the former floating alias as the sole cause; `.github#712` retains the central/provider runner-capacity and dispatch defect class.

The original runner PR #145 is closed and superseded. Its source branch was accidentally used as a feature-stack integration target, which expanded the branch beyond the four runner-control files. No protected-main merge occurred. The bounded runner delta is preserved by #147.

## Live delivery queue

The fresh inventory contains 23 open PRs including this baseline PR:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #138, #140, #141, #142, #144, #146, #147, #148`.

PR #126 is closed and superseded by #141. PR #137 is merged into protected `main`. PR #131 is closed after its trusted-proxy delta was integrated only into the obsolete #145 feature branch; it did not reach protected `main`. Canonical trusted-proxy delivery is replacement PR #148. PR #145 is closed as superseded by clean replacement #147.

Key exact-current candidates verified during this refresh:

| PR | Exact head | Current classification | Evidence / next causal action |
| --- | --- | --- | --- |
| #129 Agent Artifact Admission | `704e222a5d0e3f2951486eda46fa1ae6b5b0e9e6` | Draft | Feature branch is synchronized with protected `main`; keep Draft until every applicable exact-head repository/security/coverage/package/review-policy gate is terminal and current. |
| #136 outbound destination hardening | `b07d0d734fc41ec9f38beec7834bea78fa70cd6a` | Ready | Shared URL validation, DNS-address validation/pinning, no ambient proxy, no automatic redirects, and bounded pinned-client lifecycle remain partial progress toward #79; versioned allowlist/deny precedence and complete connector parity remain open. |
| #138 fail-closed management auth | `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` | Ready | Review findings are resolved; regenerate exact-head evidence under current runner/governance truth before merge. |
| #140 runtime configuration snapshot | `492fba145b2b501b3fffcf9e664f40d3ae9c12fa` | Ready | Runtime Configuration remains a supporting bootstrap boundary distinct from secret-bearing Credential Registry; fresh exact-head evidence remains required. |
| #142 readiness metrics | `e7ef34d9f2c5d31873d7c09889b302279e8a4162` | Ready, stacked on #147 | The Prometheus HELP-text defect is resolved: `0` means no write-capable credential is configured while readonly auth may still exist. The branch non-destructively incorporates #147's runner prerequisite; fresh exact-head CI/Fuzz/Security/SAST are non-passing while queued. |
| #144 Kubernetes manifest path | `6cd0b16052fb8c35487c9da8ce96a3d17462371b` | Ready, main-based | Repository-path-only migration preserves #137's hardened Secret contract and live Kubernetes identities. Auto-merge is enabled, so keep this PR on protected `main`; do not retarget it to an unprotected feature base. |
| #146 support-bundle operability evidence | `28606b28b01df900d03ddeb3df7cb037fb3804da` | Ready | Adds readiness/metrics evidence to support-bundle and buyer-evidence surfaces. Treat as an independent concurrent lane and revalidate overlap before mutation. |
| #147 explicit hosted runner | `2d41c4079f9a4465c3142a0aa2dd5895cb11f793` | Ready, replacement root | Clean four-file runner-only replacement for superseded #145. Fresh PR-triggered CI/Fuzz/Security/SAST runs are queued; earlier same-commit successes are provenance, not substitute for current required evidence. |
| #148 trusted proxy attribution | `72ac1a2a2902a10aabc6e20169b9ae89adb5f9c8` | Ready, stacked on #147 | Replacement for #131. The merged tree preserves explicit `ubuntu-24.04` and the trusted-proxy fuzz target. Fresh replacement-PR evidence is required; predecessor #131 review/check results do not transfer. |

Do not transfer checks, reviews, approvals, artifacts, or source-review conclusions across a head, base, retarget, restack, replacement PR, or protected-base movement. `queued`, `pending`, `skipped`, `cancelled`, `absent`, stale, predecessor-head, status-only, model-only, or synthetic evidence is non-passing.

## Open issues and production order

There are 17 open issues at this snapshot: `#11, #38, #74, #75, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #89, #128, #139`.

1. **Immediate exposure controls:** #78 fail-closed management auth, #79 fail-closed destination policy, #11 real attack-path CI, and #75's repository-path migration implemented by #144 on protected #137 truth.
2. **Security admission:** #128 Agent Artifact Admission; protected `main` cannot claim this control until #129 integrates.
3. **Durable authority and effects:** #80 PostgreSQL production authority and tenant isolation, then #81 transactional outbox/leased workers.
4. **Identity and overload:** #82 Keyverse-backed identity/authorization/approval and #83 distributed/global admission authority with bounded local protection. #148 is the current trusted-network-identity slice of #83; it does not close distributed admission.
5. **Proven security engines:** #86 Coraza/CRS and Suricata production enforcement with reproducible detection/false-positive evidence.
6. **Immutable delivery and operation:** #84 signed/SBOM/provenance release promotion and rollback, then #85 OpenTelemetry/SLO/incident/restore evidence.
7. **Supporting correctness:** #74 deterministic persistence-failure testing, #77 pinned compiler, #139 coherent runtime configuration, #75 post-hardening Kubernetes filename migration, and #147 deterministic hosted-runner selection.

Do not close an issue from predecessor evidence. Close only after the owning protected merge satisfies the issue acceptance contract.

## DDD and implementation gaps

Agent Artifact Admission has a responsibility-aligned crate under `crates/agent-artifact-admission` on #129 with domain-policy independence tests. Protected `main` does not yet contain that control. The legacy gateway remains concentrated in root `src/lib.rs`; file size alone is not a service boundary, but repeated changes to client attribution, outbound policy, runtime configuration, proxying, SOC integration, rate limiting, support evidence, and management APIs show genuine responsibility-convergence pressure. Structural work must add responsibility/dependency fitness before moving code and should favor a modular monolith until transaction, deployment, scaling, or reuse evidence justifies another deployable.

#140 is the coherent Runtime Configuration migration. `CredentialRegistry` remains the secret-bearing bootstrap owner. New direct process-environment reads outside approved bootstrap adapters are architecture defects.

Network-Egress remains incomplete after #136. Issue #79 still requires reusable versioned hostname/suffix/IP/CIDR/scheme/port policy, deterministic deny-overrides precedence, complete connector parity, decision evidence, and operator migration/rollback/diagnostics.

The old #95 branch is not an acceptable production-integration vehicle. It is a large, diverged, non-mergeable branch that combines Coraza, PostgreSQL, outbox, egress and release responsibilities. Its unique tested deltas are preservation evidence for bounded successor work, not permission to merge a cross-context god-PR. #80, #81 and #86 remain unshipped on protected `main` and should be reconstructed/decomposed responsibility-first without losing unique tests or evidence.

Context Fabric integration remains release-gated. `context-graph-contracts` and `enterprise-architecture-core` are read-only from Wardnet while their dedicated writer is active, and neither currently has a release. Wardnet consumes only released compatible Context Graph contracts with conformance/admission evidence; sibling PR heads are candidate evidence, never production authority. EA projections may carry application/service/API/runtime technology identity, lifecycle, ownership, risk, remediation and transformation references, but not malware verdicts, artifact risk scores, prompts, or customer/runtime truth as authoritative architecture facts.

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

1. Drive clean runner root #147 through fresh exact-head repository and central evidence while `.github#712` continues the independent central/provider acquisition repair and `.github#772` repairs solo-maintainer governance.
2. Keep working independent security/product lanes during queue waits. #142's HELP-text defect is fixed on `e7ef34d…`; #148 preserves the trusted-proxy security delta on top of #147; both require fresh replacement-head evidence.
3. Integrate immediate security roots as exact gates become valid: #138 fail-closed runtime authentication and #136 destination-policy slice. Keep #144 main-based so its enabled auto-merge cannot accidentally integrate into a feature branch.
4. Finish #129 as one Agent Artifact Admission bounded context without absorbing hostile execution isolation or Agent/LLM orchestration.
5. Drain clean supporting work such as #77, #90, #93, #134, #135, #140, #141 and #146 when live exact evidence permits.
6. Decompose/reconstruct #95's still-valuable PostgreSQL/outbox/Coraza evidence into bounded #80/#81/#86 successor lanes rather than merging the combined stale branch.
7. Continue #82/#83/#84/#85 production-readiness work only after their declared dependencies are protected truth.
8. Keep this baseline current whenever protected truth, queue topology, release state, or responsibility boundaries materially change.
