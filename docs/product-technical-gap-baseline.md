# Product and technical gap baseline

Snapshot date: 2026-09-01. This is a dated GitHub inventory for `ContextualWisdomLab/wardnet`; every later execution must refetch live heads, bases, checks, rules, releases, and foreign owner state instead of treating this file as a scheduler cache.

## Product boundary

Wardnet is the Rust-first gateway/SOC control plane and owns Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, and Audit-Provenance responsibilities. The Agent Artifact Admission Controller is a separate bounded context inside Wardnet's Security Admission subdomain.

Quarantine Sandbox Runtime owns hostile-workload execution isolation. `contextual-orchestrator` owns Agent/LLM orchestration. EgressWeave is the outbound HTTP-policy candidate. Wardnet consumes those capabilities through versioned ports and Anti-Corruption Layers; it must not copy their implementations or access their application databases.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical references, authority, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents/schema/conformance/admission. `enterprise-architecture-core` is the Enterprise Architecture Decision Plane. While the dedicated Context Fabric writer is active, Wardnet treats both repositories as read-only source dependencies and forwards exact architecture/contract evidence through their owner path. Security findings, alerts, malware verdicts, artifact risk scores, prompts, and customer/runtime data do not become authoritative EA facts.

## Protected truth and governance

Protected/default `main` is `b2bcee3bf2c63f26c48e3be879e5349ef23fafcd` at this snapshot. There are no Wardnet GitHub releases.

Organization ruleset `18156473` targets `~DEFAULT_BRANCH`. Its pull-request rule currently requires one approving review, dismisses stale approvals, requires conversation resolution, has no named required reviewer/team, no code-owner review requirement, and no last-push approval requirement. It also requires central workflow evidence for review, scheduling, security, Strix, Semgrep, and Noema plus deletion/non-fast-forward protection.

The bare approval-count requirement is structurally inconsistent with the declared solo-maintainer operating model when no eligible independent human exists. That is a central `.github` governance defect, not a Wardnet product gap and not a request to invent a human reviewer. Self-approval and bot/model-as-human approval remain forbidden. Central owner path `.github#772` has fresh Wardnet evidence and must repair only the unsatisfiable approval-count condition while preserving deterministic workflow/security/coverage/package/SBOM/provenance/thread/branch-integrity gates.

Required jobs that remain queued before any runner step are likewise central control-plane evidence rather than Wardnet source failures. `.github#712` has fresh Wardnet reproduction from #136: the repository-owned CI/Fuzz/Security/SAST lanes are terminal GREEN on exact head `0af75ab614442cba43782d5e9edcd1ee9606a4a8`, while central OpenCode job `99791887036` remains queued without executed steps. Queue starvation is non-passing evidence, but it is not a reason to mutate a clean Wardnet head or stop independent Wardnet work.

## Live delivery queue

The fresh inventory contains 19 open PRs including this baseline PR:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #131, #134, #135, #136, #137, #138, #140`.

PR #126 is no longer open and must not remain in the active queue. PR #94 was previously closed as superseded after its unique issue-#78 doctoring artifact was preserved on the clean successor #138.

Key exact-current candidates verified during this refresh:

| PR | Exact head | Current classification | Evidence / next causal action |
| --- | --- | --- | --- |
| #129 Agent Artifact Admission | `3a23772b3ae56097d0e9d78333a1ceeaeb21a104` | Draft | The predecessor formatting failure was repaired. Fresh exact-head gates remain required; keep Draft until unchanged-head CI/Fuzz/Security/SAST and applicable central gates terminate successfully. |
| #138 fail-closed management auth | `78b21b9dad892e07cc454a150b7c84156ab57d20` | Ready, mergeable | Current-head review found that the smoke regression did not prove the generated administrator credential actually flows into `ADMIN_TOKEN`. The test now binds the exact `secrets.token_hex(16)` generator to forwarding, requires generation before use, and rejects a second `ADMIN_TOKEN=` fallback. That thread is resolved. CI/Fuzz/Security/SAST for this new head are queued and non-passing. A separate documentation/research-artifact review still requires a lawful redistributable ASVS/NIST artifact or equivalent verified resolution. |
| #140 runtime configuration snapshot | `7a5b41006b75485f0d09307be5697ed3501e856d` | Ready, mergeable | Current review threads are resolved, including secret/non-secret configuration ownership. Exact-current-head repository workflows were queued at the latest read. |
| #137 external administrator Secret boundary | `60805269e0a7406f5d32ad65a09b2f0c31027196` | Ready, mergeable | Repository CI/Security/SAST jobs were still queued before execution at the latest read. |
| #136 outbound destination hardening | `0af75ab614442cba43782d5e9edcd1ee9606a4a8` | Ready, mergeable | Repository CI/Fuzz/Security/SAST are terminal GREEN and inline findings are resolved. Central required OpenCode remains queued before execution. #79 remains partial because the versioned allowlist/deny-precedence policy and full connector-policy acceptance are still open. |
| #135 bounded local limiter | `49abdd807aed0fd21310424ddfcb8200ec1dfd34` | Ready, mergeable | Repository CI/Fuzz/Security/SAST are terminal GREEN and current inline threads are resolved. Central governance/review evidence remains separate. |
| #134 support-bundle regression | `2193bfda7601eba9754b1783a7669077bb7efbc2` | Ready, mergeable | The actual delta binds support-bundle counts to KPI/evidence-manifest counts and asserts the administrator secret is absent. Repository CI/Fuzz/Security/SAST are GREEN; central gates remain. |
| #90 SIEM/OpenTelemetry export | `2d251183c41f49b07d443ff15fe9e54472d90f63` | Ready, mergeable | The last current review thread was informational and is now resolved. Exact-head CI/Fuzz/Security/SAST are queued, so this candidate is not yet merge-passing. |
| #77 pinned Rust toolchain | `d30de04d717204373c643a1dd209cdcccc707391` | Ready, mergeable | Repository CI/Security/SAST are GREEN and inline findings are resolved. Normal merge remains subject to the repaired live organization policy and current central required workflows. |

Do not transfer checks, reviews, approvals, artifacts, or source-review conclusions across a head, base, retarget, restack, replacement PR, or protected-base movement. `queued`, `pending`, `skipped`, `cancelled`, `absent`, stale, predecessor-head, status-only, model-only, or synthetic evidence is non-passing.

## Open issues

There are 17 open issues at this snapshot: `#11, #38, #74, #75, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #89, #128, #139`.

The production-risk order remains:

1. **Immediate exposure controls:** #78 fail-closed management auth, #79 fail-closed destination policy, #11 real attack-path CI, and the deployment credential boundary represented by #137/#75.
2. **Security admission:** #128 Agent Artifact Admission; protected `main` cannot claim this control until #129 integrates.
3. **Durable authority and effects:** #80 PostgreSQL production authority and tenant isolation, then #81 transactional outbox/leased workers.
4. **Identity and overload:** #82 Keyverse-backed identity/authorization/approval and #83 distributed/global admission authority with bounded local protection.
5. **Proven security engines:** #86 Coraza/CRS and Suricata production enforcement with reproducible false-positive/detection evidence.
6. **Immutable delivery and operation:** #84 signed/SBOM/provenance release promotion and rollback, then #85 OpenTelemetry/SLO/incident/restore evidence.
7. **Supporting correctness:** #74 deterministic persistence-failure testing, #77 pinned compiler, #139 coherent runtime configuration boundary, and #75 post-hardening Kubernetes filename migration.

Issues #78, #74, #89, #128, and #139 have active implementation PRs. Do not close them from predecessor evidence; close only after the owning protected merge satisfies the issue acceptance contract.

## DDD and implementation gaps

Agent Artifact Admission has a responsibility-aligned crate under `crates/agent-artifact-admission` with domain-policy independence tests. The legacy gateway remains concentrated in the root `src/lib.rs`. File size alone is not a service boundary, but current work repeatedly touches client attribution, outbound policy, runtime configuration, proxying, SOC integration, rate limiting, support evidence, and management APIs in the same module. Structural work must add responsibility/dependency fitness before moving code and should favor a modular monolith until transaction, deployment, scaling, or reuse evidence justifies another deployable.

PR #140 is the current coherent migration for the non-secret Runtime Configuration supporting subdomain. `CredentialRegistry` remains the secret-bearing bootstrap owner. New direct process-environment reads outside approved bootstrap adapters are architectural defects.

Network-Egress remains incomplete even after #136. The current slice closes literal/private/reserved destinations, ambient proxies, redirects, DNS rebinding through validated-address pinning, and related parsing bypasses. Issue #79 still requires a reusable versioned policy with hostname/suffix/IP/CIDR/scheme/port allowlists, deterministic deny-overrides precedence, complete connector parity, decision evidence, and operator migration/rollback/diagnostics. Do not claim #79 closed from #136 alone.

The current Context Fabric owner state remains provisional. `context-graph-contracts` still reports live default `develop`; its latest Context Assertion/CloudEvent work remains on a Draft stack with queued exact-head conformance/package lanes and no immutable release. `enterprise-architecture-core` likewise still reports live default `develop`; its current Context Fabric projection Draft explicitly preserves the Quarantine Sandbox Runtime/Wardnet/contextual-orchestrator authority split and forbids malware verdict or artifact risk score as authoritative EA facts. Wardnet must consume only a released compatible Context Graph contract, never a sibling PR head.

## Quality, security, and release gates

Wardnet-owned production code targets 100% statement and branch coverage and complete public rustdoc/docstrings. Security-critical changes require hostile/bypass/replay/race/DoS/network/cleanup tests and current-source verification of every review finding. Coverage exclusions, source rewriting, skipped required paths, or green statuses bound to a different revision are not acceptable evidence.

Material architecture/security decisions must retain current NIST/OWASP/CWE/OCI/Linux/IETF or other authoritative primary standards and relevant peer-reviewed research in APA 7 traceability. Provider/vendor schemas stay behind adapters; research or scanner output does not become domain authority.

A release is not authorized. Wardnet has no GitHub release at this snapshot and production gate issue #87 remains open. Release requires one exact integrated protected head with required CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence and immutable artifact identity. No active PR stack or readiness document substitutes for that evidence.

## Next execution order

1. Repair exact-current-head source/review defects before waiting on central provider lanes; #138's smoke credential-flow regression is repaired and now requires fresh exact-head execution evidence plus the remaining research-artifact review resolution.
2. Let `.github` repair runner acquisition through #712 and the structurally impossible solo-maintainer approval count through #772. Revalidate unchanged Wardnet heads afterward rather than changing source merely to retrigger infrastructure.
3. Integrate immediate security roots in dependency-safe order as their exact gates become valid: #137 deployment credential hardening, #138 fail-closed runtime authentication, #136 destination-policy slice, then the remaining #79 policy work.
4. Finish #129 as one Agent Artifact Admission bounded context without absorbing hostile execution isolation or Agent/LLM orchestration.
5. Drain clean supporting PRs such as #77, #90, #134, #135, and #140 when normal protected merge becomes available under current exact evidence.
6. Continue production-readiness work through #80/#81/#82/#83/#86/#84/#85 rather than widening unrelated feature scope.
7. Keep this baseline current when live queue topology, protected truth, release state, or responsibility boundaries materially change.
