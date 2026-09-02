# Product and technical gap baseline

Snapshot date: 2026-09-02. This file is a dated repository snapshot, not scheduler memory. Every later run must refetch live heads, bases, checks, review state, rulesets, releases, and foreign-owner state before acting.

## Product boundary

Wardnet is the Rust-first gateway/SOC control plane. Its owned responsibilities are Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, and Audit-Provenance. The Agent Artifact Admission Controller is a separate bounded context inside Wardnet's Security Admission subdomain.

Quarantine Sandbox Runtime owns hostile-workload execution isolation. `contextual-orchestrator` owns Agent/LLM orchestration. EgressWeave is the outbound HTTP-policy candidate. Wardnet consumes those capabilities through versioned ports and Anti-Corruption Layers; it does not copy their implementations or access their application databases.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical references, authority, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents/schema/conformance/admission. `enterprise-architecture-core` is the Enterprise Architecture Decision Plane. While the dedicated Context Fabric writer is active, both repositories are read-only source dependencies from Wardnet. Security findings, alerts, malware verdicts, artifact risk scores, prompts, and customer/runtime data do not become authoritative EA facts.

## Protected truth and governance

Protected/default Wardnet `main` is `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. It contains PR #137's externally provisioned, non-optional administrator Secret boundary. Wardnet currently has no GitHub Release.

Organization ruleset `18156473` targets `~DEFAULT_BRANCH`. It requires one approving review, dismisses stale approvals, requires review-thread resolution, names no required reviewer/team, does not require code-owner or last-push approval, and also requires central review/security workflow evidence plus deletion/non-fast-forward protection.

The bare approval-count requirement is structurally inconsistent with the declared solo-maintainer operating model when no eligible independent human exists. This is a central `.github` governance defect, not a Wardnet staffing/product defect. Self-approval and bot/model-as-human approval remain forbidden. `.github#772` owns the minimum repair while deterministic workflow/security/coverage/package/SBOM/provenance/thread/branch-integrity controls stay enforced.

Runner/control-plane work is split by ownership. Clean replacement PR #153 pins every repository-owned CI/Fuzz/Scorecard `runs-on:` declaration to explicit `ubuntu-24.04` and rejects drift with a contract test. Its exact head `b663f9d200e5f385c7dd067d074940a02836c68e` has terminal-success repository CI/Fuzz/Security/SAST on the same SHA, proving the explicit hosted label works. The newest replacement-PR workflow wave and current central coverage/OpenCode lanes remain queued/non-passing, so `.github#712` remains the central acquisition/control-plane owner. Closed PR #149 is superseded branch-history evidence only.

Exact-head central review failures are tracked separately from source findings. Historical Noema evidence on clean runner head `b663f9d…` acquired `ubuntu-24.04`, completed exact-head/app-token/orchestrator preflight, then failed because the initial model verdict was malformed JSON and bounded repair exceeded its 900-second absolute deadline; `.github#1637` owns typed fail-closed handling for that class. Historical Strix evidence on auth source head `e6f05d7…` materialized the exact head and passed gateway preflight but all bounded scanner LLM attempts were provider-unavailable, so no authoritative scan evidence existed; `.github#891` owns the scanner/readiness recovery contract. Wardnet must not mutate clean product source to satisfy either infrastructure failure.

A prior base-retarget incident showed that enabled auto-merge can immediately integrate a child into a temporary feature-branch base. Recovery was non-destructive: #153 is now the clean runner root; #156 preserves support-bundle work, #157 trusted-proxy work, and #158 readiness-metrics work as clean Draft descendants. Future retargets must inspect auto-merge state first and must not use an unprotected feature branch as final integration truth.

## Context Fabric live boundary

Fresh repository metadata still reports `develop` as the default branch for both `ContextualWisdomLab/context-graph-contracts` and `ContextualWisdomLab/enterprise-architecture-core`. Both currently expose zero GitHub Releases. Context Graph Contracts PR #21 remains a Draft, non-mergeable child on an obsolete #20 base while its current parent is non-terminal; Enterprise Architecture Core PR #40 likewise remains a Draft, non-mergeable child on an obsolete #39 predecessor. The accepted protected-`main` transition, runner acquisition, and solo-maintainer ruleset repair are Context Fabric/central `.github` owner work, not Wardnet source mutations.

Quarantine Sandbox Runtime also exposes no GitHub Release. Foundation PR #1 remains Draft at `57a54dbe3a01f623c0e47301af2fd36568de21e7`; caller-scoped application-service child #6 is a coherent descendant at `949b0f71a1e022eb0ea48df93ffa7bbbfd1eb259`. Both remain development evidence with current pre-checkout/runner-acquisition gates non-passing. EgressWeave currently exposes no GitHub Release either. Wardnet issue #38 therefore remains release-gated rather than consuming sibling source.

Wardnet must not consume an open Context Fabric, quarantine, or EgressWeave PR head as a production dependency. Deployable application/service/API/runtime technology identity, lifecycle, ownership, risk, remediation, and transformation may be projected only through a released compatible Context Assertion/CloudEvent/API contract with provenance. Individual security findings and artifact verdicts remain Wardnet security evidence.

## Live delivery queue

Fresh inventory contains 24 open PRs:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #153, #154, #155, #156, #157, #158`.

PR #137 is protected-main truth. Closed/superseded predecessor checks, reviews, approvals, and artifacts do not transfer to replacements or moved heads.

| PR | Exact head | Classification | Current evidence / next action |
| --- | --- | --- | --- |
| #129 Agent Artifact Admission | `ffe89e3caa7c88a925b6cae36fec475e2910af47` | Draft | Exact artifact/policy admission rejects alternate install/trust roots including attached pip short-option forms (`-t/path`, `-iURL`, `-fURL`) and ambiguous npm script-suppression forms. Current repository gates are queued/non-passing and current-head independent review evidence must be reacquired before Ready. |
| #136 Network-Egress | `edf5e88d84475ce3694e1cc206605a322ba53016` | Ready | Shared URL/resolved-address validation, DNS pinning, no ambient proxy/redirect, bounded client cache, hop-by-hop response filtering, and architecture fitness are present. CI `33578188860`, Fuzz `33578188853`, Security `33578188827`, and SAST `33578188887` are queued/non-passing. #79 still owns explicit allowlist/deny-precedence, decision-evidence completion, and any remaining unrepresented outbound surface. |
| #140 Runtime Configuration | `43d1b6e9122d8bb5cb882f8fc6e066c63b39ae45` | Ready | Security `33556345110` and SAST `33556345038` are GREEN; current CI/Fuzz are queued. Runtime Configuration remains a supporting bootstrap boundary distinct from secret-bearing Credential Registry. |
| #144 Kubernetes manifest path + public docs | `4b9869f015e552fe5c05c740162466b8d0539f88` | Ready, main-based | Repository-path migration preserves #137's hardened Secret contract and live Kubernetes identities. Security/SAST are GREEN while current CI/Fuzz remain queued; keep main-based and reacquire every exact-head gate before merge. |
| #153 explicit hosted runner | `b663f9d200e5f385c7dd067d074940a02836c68e` | Ready, clean stack root | Repository-owned exact-SHA CI/Fuzz/Security/SAST have previously completed GREEN on this unchanged source. Current replacement-PR repository/central evidence is again queued/non-passing; `.github#712`, `.github#1637`, and `.github#772` own the remaining control-plane/governance classes. |
| #155 fail-closed management auth | `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` | Ready, clean main-based replacement | Restores the exact reviewed auth delta to protected-main lineage after predecessor #138 was absorbed into a temporary feature branch. Prior same-source repository CI/Fuzz/Security/SAST are GREEN, but the new #155 workflow wave and central review/security/governance evidence must terminate on this replacement PR. Devin's current comments are informational rather than source defects. |
| #156 support-bundle operability evidence | `76037b8ae206ace8dab0e6622dfc9fc88c57deb3` | Draft, stacked on #153 | Clean replacement for contaminated #150. After #153 reaches protected `main`, retarget/reconstruct on fresh main and regenerate all base-sensitive evidence. |
| #157 trusted proxy attribution | `65a2b7fbf2827f69ae1aa288696b6c5630af28c4` | Draft, stacked on #153 | Clean replacement for contaminated #151; forwarded identity is trusted only from configured proxy CIDRs. Revalidate after parent integration. |
| #158 readiness metrics | `387a447f856093d02116dfadcf2c4a4a63c6d3ba` | Draft, stacked on #153 | Clean replacement for contaminated #152; readiness gauges reuse existing authority and require fresh evidence after parent integration. |

`queued`, `pending`, `skipped`, `cancelled`, `absent`, stale, predecessor-head, status-only, model-only, or synthetic evidence is non-passing. Do not transfer evidence after head/base movement.

## Open issues and production order

Fresh inventory contains 17 open issues: `#11, #38, #74, #75, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #89, #128, #139`.

1. **Immediate exposure controls:** #78 fail-closed management auth through clean PR #155, #79 fail-closed destination policy through #136 plus its remaining allowlist/evidence work, #11 real attack-path CI, and #75 repository-path migration through #144.
2. **Security admission:** #128 Agent Artifact Admission through #129. Hostile execution remains quarantine-owned.
3. **Durable authority and effects:** #80 PostgreSQL production authority/tenant isolation, then #81 transactional outbox and leased workers.
4. **Identity and overload:** #82 Keyverse-backed identity/authorization/approval and #83 distributed/global admission. #157 is only the trusted-network-identity slice and remains parent-gated on #153.
5. **Proven security engines:** #86 Coraza/CRS and Suricata production enforcement with detection/false-positive evidence.
6. **Immutable delivery and operation:** #84 signed/SBOM/provenance release promotion/rollback, then #85 OpenTelemetry/SLO/incident/restore evidence.
7. **Supporting correctness:** #74 deterministic persistence fault testing, #77 pinned compiler, #139 coherent runtime configuration, #75 manifest filename migration, and #153 deterministic hosted-runner selection.

Close an issue only after its owning protected merge satisfies the issue acceptance contract on current evidence.

## DDD and implementation gaps

Agent Artifact Admission has a responsibility-aligned crate under `crates/agent-artifact-admission` on #129 with domain-policy independence tests. The candidate now treats package-manager destination selection, attached short-option capability spellings, and script-suppression ambiguity as admitted capabilities. Actual filesystem/mount/process isolation remains downstream quarantine/executor responsibility.

The legacy gateway remains concentrated in root `src/lib.rs`. File size alone does not justify a deployable split, but repeated changes to client attribution, outbound policy, runtime configuration, proxying, SOC integration, rate limiting, support evidence, and management APIs show genuine responsibility-convergence pressure. Structural work should add dependency/ownership fitness first and prefer a modular monolith until transaction, deployment, scaling, or reuse evidence justifies another deployable.

#140 is the coherent Runtime Configuration migration. `CredentialRegistry` remains the secret-bearing bootstrap owner. New direct process-environment reads outside approved bootstrap adapters are architecture defects.

Network-Egress remains incomplete after #136. Issue #79 still requires versioned hostname/suffix/IP/CIDR/scheme/port allowlists, deterministic deny-overrides precedence, connector parity, minimized decision evidence, and operator migration/rollback/diagnostics.

PR #95 is not an acceptable production integration vehicle. It is a large diverged cross-context branch combining Coraza, PostgreSQL, outbox, egress, and release responsibilities. Preserve its unique tests/evidence while reconstructing bounded #80/#81/#86 successor work rather than merging a god-PR.

## Research and standards grounding

External standards constrain design and verification; they do not prove Wardnet currently implements every control.

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207.
- Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218.
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/.
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082.

The microservices evidence is used narrowly to avoid decomposition-by-file-size: split deployables only when responsibility, scaling, transaction, isolation, or reuse evidence justifies the operating cost.

## Quality, security, and release gates

Wardnet-owned production code targets 100% statement and branch coverage and complete public rustdoc/docstrings. Security-critical changes require hostile/bypass/replay/race/DoS/network/cleanup tests and current-source verification of review findings. Coverage exclusions, source rewriting, skipped required paths, or green statuses bound to another revision are not acceptable evidence.

A release is not authorized. Wardnet, Quarantine Sandbox Runtime, EgressWeave, `context-graph-contracts`, and `enterprise-architecture-core` expose no GitHub Release at this snapshot, and Wardnet production gate #87 remains open. Release requires one exact integrated protected head with CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence and immutable artifact identity.

## Next execution order

1. Drive clean runner root #153 through current central evidence while `.github#712`, `.github#1637`, and `.github#772` repair acquisition/model-review/governance defects; keep scanner availability/evidence handling in `.github#891`.
2. Keep independent work moving while #153 waits. Preserve #156/#157/#158 on clean #153 without predecessor-evidence reuse.
3. Integrate immediate security roots as exact gates become valid: #155 runtime authentication and #136 destination-policy slice. Keep #144 main-based.
4. Finish #129 as one Agent Artifact Admission bounded context without absorbing quarantine or Agent/LLM orchestration.
5. Drain clean supporting work such as #77, #90, #93, #134, #135, #140, #141, and #154 when exact evidence permits.
6. Reconstruct #95's still-valuable PostgreSQL/outbox/Coraza evidence into bounded #80/#81/#86 lanes.
7. Continue #82/#83/#84/#85 only after their declared dependencies become protected truth.
8. Refresh this baseline whenever protected truth, queue topology, release state, or responsibility boundaries materially change.
