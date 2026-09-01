# Product and technical gap baseline

Snapshot date: 2026-09-02. This is a dated GitHub inventory for `ContextualWisdomLab/wardnet`; every later execution must refetch live heads, bases, checks, rules, releases, and foreign-owner state instead of treating this file as scheduler state.

## Product boundary

Wardnet is the Rust-first gateway/SOC control plane and owns Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, and Audit-Provenance responsibilities. The Agent Artifact Admission Controller is a separate bounded context inside Wardnet's Security Admission subdomain.

Quarantine Sandbox Runtime owns hostile-workload execution isolation. `contextual-orchestrator` owns Agent/LLM orchestration. EgressWeave is the outbound HTTP-policy candidate. Wardnet consumes those capabilities through versioned ports and Anti-Corruption Layers; it must not copy their implementations or access their application databases.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical references, authority, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents/schema/conformance/admission. `enterprise-architecture-core` is the Enterprise Architecture Decision Plane. While the dedicated Context Fabric writer is active, Wardnet treats both repositories as read-only source dependencies and forwards exact architecture/contract evidence through their owner path. Security findings, alerts, malware verdicts, artifact risk scores, prompts, and customer/runtime data do not become authoritative EA facts.

## Protected truth and governance

Protected/default `main` is `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128` at this snapshot. That protected head includes PR #137's external, non-optional administrator Secret boundary. Wardnet still has no GitHub release.

Organization ruleset `18156473` targets `~DEFAULT_BRANCH`. Its pull-request rule currently requires one approving review, dismisses stale approvals, requires conversation resolution, has no named required reviewer/team, no code-owner review requirement, and no last-push approval requirement. It also requires central workflow evidence for review, scheduling, security, Strix, Semgrep, and Noema plus deletion/non-fast-forward protection.

The bare approval-count requirement is structurally inconsistent with the declared solo-maintainer operating model when no eligible independent human exists. That is a central `.github` governance defect, not a Wardnet product gap and not a request to invent a human reviewer. Self-approval and bot/model-as-human approval remain forbidden. Central owner path `.github#772` owns the minimum repair of the unsatisfiable approval-count condition while preserving deterministic workflow/security/coverage/package/SBOM/provenance/thread/branch-integrity gates.

Required jobs that remain queued before any runner step are central control-plane evidence rather than Wardnet source failures. `.github#712` has fresh Wardnet reproductions where `ubuntu-latest` jobs remain `runner_id: 0` with no executed steps; the latest exact reproduction is PR #144 head `57386f0ef5ee5beeb8995003fdbfd584eb6ce950`, CI run `33526583284`, job `99918865509`. Queue starvation is non-passing evidence, but it is not a reason to mutate a clean Wardnet head or stop independent Wardnet work.

## Live delivery queue

The fresh inventory contains 21 open PRs including this baseline PR:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #131, #134, #135, #136, #138, #140, #141, #142, #144`.

PR #126 is closed and superseded by #141's current CodeQL SARIF uploader update. PR #137 is merged into protected `main`. PR #94 was previously closed as superseded after its unique issue-#78 doctoring artifact was preserved on successor work.

Key exact-current candidates verified during this refresh:

| PR | Exact head | Current classification | Evidence / next causal action |
| --- | --- | --- | --- |
| #129 Agent Artifact Admission | `704e222a5d0e3f2951486eda46fa1ae6b5b0e9e6` | Draft | Feature branch is synchronized with protected `main`; regenerate every applicable exact-head repository/security/coverage/package/review-policy gate and keep Draft until terminal evidence is clean. |
| #131 trusted proxy attribution | `97d9c4b93ecc478c12c6529eae2366831d5ff9e5` | Ready, mergeable | Current review threads are resolved. CI/Fuzz/Security/SAST remain queued, so the candidate is non-passing until exact-head execution evidence terminates. |
| #134 support-bundle regression | `2b236057d6811cb7ca2ff4f01038796128f4fb6a` | Ready, mergeable | Unique delta is a test-only support-evidence consistency/secret-redaction contract; fresh exact-head gates remain required. |
| #136 outbound destination hardening | `b07d0d734fc41ec9f38beec7834bea78fa70cd6a` | Ready, mergeable | Shared URL validation, DNS-address validation/pinning, no ambient proxy, no automatic redirects, and bounded pinned-client lifecycle remain partial progress toward #79; explicit versioned allowlist/deny-precedence and complete connector parity remain open. |
| #138 fail-closed management auth | `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` | Ready, mergeable | Review findings are resolved; exact-head CI/Fuzz/Security/SAST are queued and remain non-passing pending runner acquisition. |
| #140 runtime configuration snapshot | `492fba145b2b501b3fffcf9e664f40d3ae9c12fa` | Ready, mergeable | Current review threads are resolved; exact-head repository workflows remain queued. |
| #141 CodeQL SARIF uploader | `fea3796a723080068cdc02e064065d6d53eeb3e0` | Ready, mergeable | Replaces stale #126 with the v4.37.9 immutable action pin; exact-head repository and central gates remain required. |
| #142 readiness metrics | `021d51dc18448964fb4aab8ea119bf37825af036` | Ready, mergeable | One current review finding remains: the Prometheus HELP text says `0=auth disabled` even though readonly-only authentication can be enabled while no write-capable credential exists. The owning review path has been asked for the minimal wording/test repair; do not classify merge-ready until the exact head moves or the thread is resolved. |
| #144 Kubernetes manifest path | `57386f0ef5ee5beeb8995003fdbfd584eb6ce950` | Ready, mergeable | The repository path migration preserves #137's hardened manifest. A newly added path-regression false positive was repaired by excluding only migration-history/negative-fixture files while retaining fail-closed scans for operational stale references. Fresh CI/Fuzz/Security/SAST are queued before runner assignment. |

Do not transfer checks, reviews, approvals, artifacts, or source-review conclusions across a head, base, retarget, restack, replacement PR, or protected-base movement. `queued`, `pending`, `skipped`, `cancelled`, `absent`, stale, predecessor-head, status-only, model-only, or synthetic evidence is non-passing.

## Open issues

There are 17 open issues at this snapshot: `#11, #38, #74, #75, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #89, #128, #139`.

The production-risk order remains:

1. **Immediate exposure controls:** #78 fail-closed management auth, #79 fail-closed destination policy, #11 real attack-path CI, and #75's repository-path migration now implemented by #144 on top of protected #137.
2. **Security admission:** #128 Agent Artifact Admission; protected `main` cannot claim this control until #129 integrates.
3. **Durable authority and effects:** #80 PostgreSQL production authority and tenant isolation, then #81 transactional outbox/leased workers.
4. **Identity and overload:** #82 Keyverse-backed identity/authorization/approval and #83 distributed/global admission authority with bounded local protection.
5. **Proven security engines:** #86 Coraza/CRS and Suricata production enforcement with reproducible false-positive/detection evidence.
6. **Immutable delivery and operation:** #84 signed/SBOM/provenance release promotion and rollback, then #85 OpenTelemetry/SLO/incident/restore evidence.
7. **Supporting correctness:** #74 deterministic persistence-failure testing, #77 pinned compiler, #139 coherent runtime configuration boundary, and #75 post-hardening Kubernetes filename migration.

Do not close an issue from predecessor evidence. Close only after the owning protected merge satisfies the issue acceptance contract.

## DDD and implementation gaps

Agent Artifact Admission has a responsibility-aligned crate under `crates/agent-artifact-admission` on PR #129 with domain-policy independence tests. Protected `main` does not yet contain that control. The legacy gateway remains concentrated in root `src/lib.rs`; file size alone is not a service boundary, but repeated changes to client attribution, outbound policy, runtime configuration, proxying, SOC integration, rate limiting, support evidence, and management APIs show a real responsibility-convergence pressure. Structural work must add responsibility/dependency fitness before moving code and should favor a modular monolith until transaction, deployment, scaling, or reuse evidence justifies another deployable.

PR #140 is the current coherent migration for the non-secret Runtime Configuration supporting subdomain. `CredentialRegistry` remains the secret-bearing bootstrap owner. New direct process-environment reads outside approved bootstrap adapters are architectural defects.

Network-Egress remains incomplete even after #136. The current slice closes literal/private/reserved destinations, ambient proxies, redirects, DNS rebinding through validated-address pinning, and related parsing bypasses. Issue #79 still requires a reusable versioned policy with hostname/suffix/IP/CIDR/scheme/port allowlists, deterministic deny-overrides precedence, complete connector parity, decision evidence, and operator migration/rollback/diagnostics. Do not claim #79 closed from #136 alone.

Context Fabric integration remains release-gated. `context-graph-contracts` and `enterprise-architecture-core` are read-only from Wardnet while their dedicated writer is active. Wardnet consumes only released compatible Context Graph contracts with conformance/admission evidence; sibling PR heads are candidate evidence, never production authority. EA projections may carry application/service/API/runtime technology identity, lifecycle, ownership, risk, remediation and transformation references, but not malware verdicts, artifact risk scores, prompts, or customer/runtime truth as authoritative architecture facts.

## Research and standards grounding

This baseline uses external standards and research as constraints and rationale, not as proof that Wardnet currently implements every control.

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207 — supports explicit resource/identity trust decisions rather than implicit trust from network placement, which is consistent with Wardnet's fail-closed authentication, trusted-proxy, and bounded authority direction.
- Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218 — supports integrating secure-development practices, root-cause prevention, and evidence into the SDLC rather than treating scanning as a substitute for engineering controls.
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/ — the current stable ASVS release provides the application/API verification baseline used for authentication, input, API, and security-control acceptance. Its repository is CC BY-SA 4.0; no additional copy is required in this baseline.
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082 — used only to constrain decomposition claims: independent deployment can add operational and organizational costs, so Wardnet should split deployables only when responsibility, scaling, transaction, or reuse evidence justifies it rather than treating file size as an architectural mandate.

The NIST publications are publicly distributed government standards and the OWASP ASVS project publishes redistributable CC BY-SA artifacts. The Elsevier article is linked by DOI rather than copied because repository redistribution rights are not established here.

## Quality, security, and release gates

Wardnet-owned production code targets 100% statement and branch coverage and complete public rustdoc/docstrings. Security-critical changes require hostile/bypass/replay/race/DoS/network/cleanup tests and current-source verification of every review finding. Coverage exclusions, source rewriting, skipped required paths, or green statuses bound to a different revision are not acceptable evidence.

Material architecture/security decisions must retain current NIST/OWASP/CWE/OCI/Linux/IETF or other authoritative primary standards and relevant peer-reviewed research in APA 7 traceability. Provider/vendor schemas stay behind adapters; research or scanner output does not become domain authority.

A release is not authorized. Wardnet has no GitHub release at this snapshot and production gate issue #87 remains open. Release requires one exact integrated protected head with required CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence and immutable artifact identity. No active PR stack or readiness document substitutes for that evidence.

## Next execution order

1. Continue exact-current-head repair before waiting on central provider lanes; #142's HELP-text correctness finding is the immediate current review defect, while #144's repository-owned regression false positive is already repaired on its latest head.
2. Let `.github` repair runner acquisition through #712 and the structurally impossible solo-maintainer approval count through #772. Revalidate unchanged Wardnet heads afterward rather than changing source merely to retrigger infrastructure.
3. Integrate immediate security roots in dependency-safe order as their exact gates become valid: #138 fail-closed runtime authentication and #136 destination-policy slice, while #144 completes the already-hardened #75 path migration. #137 is protected truth and is no longer an open dependency.
4. Finish #129 as one Agent Artifact Admission bounded context without absorbing hostile execution isolation or Agent/LLM orchestration.
5. Drain clean supporting PRs such as #77, #90, #93, #131, #134, #135, #140, and #141 when normal protected merge becomes available under current exact evidence.
6. Continue production-readiness work through #80/#81/#82/#83/#86/#84/#85 rather than widening unrelated feature scope.
7. Keep this baseline current when live queue topology, protected truth, release state, or responsibility boundaries materially change.
