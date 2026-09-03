# Product and technical gap baseline

Snapshot date: 2026-09-04. This file records the current commercial/security integration baseline, not a substitute for live GitHub state. Before merge, release, restack, or foreign-owner handoff, re-read exact heads/bases, reviews/threads, checks, rulesets, releases, and branch protection.

## Product and authority boundary

Wardnet is the Rust-first gateway/SOC control plane. Its owned bounded contexts are Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, Audit-Provenance, and Agent Artifact Admission. Wardnet does not execute hostile workloads and does not own model/provider routing.

`quarantine-sandbox-runtime` owns hostile execution isolation/lifecycle/cleanup. `contextual-orchestrator` owns Agent/LLM orchestration, provider/model/key discovery and routing. EgressWeave is the outbound HTTP-policy candidate. `appguardrail` retains its own application-guardrail authority. Wardnet consumes only released/versioned ports or Anti-Corruption Layers and does not copy foreign source or use cross-service SQL.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical object/authority references, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents/schema/conformance/admission. `enterprise-architecture-core` is the EA Decision Plane. Both repositories are read-only dependencies from this Wardnet writer while the Context Fabric owner loop is active; security findings/verdicts are not copied into EA as authoritative facts.

The optional SOC LLM seam in protected Wardnet still has ownership debt: provider/model selection must ultimately disappear behind a released contextual-orchestrator contract. No mutable CO branch may be promoted as production authority while CO has no compatible immutable release.

## Protected truth and central governance

Protected/default Wardnet `main` remains `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. It contains the externally provisioned, non-optional Kubernetes administrator Secret boundary from protected PR #137. Wardnet still has no GitHub Release.

Live organization ruleset `18156473` remains active on `~DEFAULT_BRANCH` with `required_approving_review_count=1`, `required_reviewers=[]`, no code-owner or last-push approval requirement, required thread resolution, nine central required workflows, deletion/non-fast-forward protection, and `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, the generic approval count is structurally unsatisfiable without forbidden self/model approval; the bypass is not routine merge authorization.

The owner repair remains `.github#1644@c94faa446774d012d684304fb0ac505d03e2f765` / #772. Fresh protected `.github/main` is `07d9ec23fb265c76539d23249e1dfa124ea7b23b`; #1644 is 19 protected-main commits behind/diverged and must adopt the intervening owner delta non-force before its governance evidence can become current. The intended repair keeps deterministic workflow/security/thread/deletion/non-fast-forward controls while removing the impossible generic approval requirement and routine bypass semantics. Source integration alone is not live-ruleset convergence.

Runner acquisition remains separate central control-plane work under `.github#712`. A queued/pre-checkout job with `runner_id=0`, no runner/group identity and `steps=[]` is non-passing evidence but not a reason to churn Wardnet source, downgrade runners, reuse predecessor evidence, or bypass a required gate.

## Immediate protected-main security path

### #155 — fail-closed management authentication

PR #155 remains exact `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` on protected main and is mechanically mergeable. Repository-owned CI `33590350994`, Fuzz `33590350997`, Security Scan `33590350967`, and SAST `33590350991` are terminal GREEN; current inline review threads are resolved.

Required OpenCode run `33590351182` has terminal-success bootstrap `100122902000`, coverage-source-tree `100272722468`, and coverage-evidence `100479589911`. Only `opencode-review` `100659819151` remains queued before checkout with `runner_id=0` and zero steps. This exact current-PR identity is already handed to `.github#712`; the same SHA's predecessor #138 evidence is not transferable. #78 closes only after this delta reaches protected main through satisfiable ordinary governance.

### #77 — Rust toolchain plus duplicate-Deployment fail-closed review repair

PR #77 is Ready/mergeable at exact `46fef54c9b5916eb77196fb515a8fabad13a05d1`. In addition to pinning Rust `1.98.0`, the current lineage repairs a valid CodeRabbit security finding in the Kubernetes deployment regression contract.

RED `43d2c874732063e418b3929e3435c388ccfa7c69` proved that first-match `find_map` validation could accept a valid first `Deployment` while ignoring a later YAML document with the same `waf-ids-ai-soc/waf-ids-ai-soc` resource identity. GREEN `17a2a1e833e6c4cab6101ef6a534589d75a5920a` requires exactly one canonical target Deployment and adds a hostile duplicate-resource regression whose second document contains a literal `ADMIN_TOKEN`. Cleanup/current `46fef54c...` removes only the temporary source-text RED scaffold; the behavior-level regression remains.

Fresh current-head CI `33807338426`, Security `33807338277`, SAST `33807338221`, Scorecard `33807338399`, and OSV `33807339076` are queued. The review thread stays unresolved until exact-current-head GREEN exists; source repair alone is not terminal verification.

### #136 — Network-Egress DNS deadline defect

Draft #136 remains exact `3cb1047416c3aa7fa8eb352b842cc55ad8c21b19`. Its shared outbound client already rejects dangerous literal destinations, validates/pins resolved addresses, disables ambient proxy/redirect behavior, bounds client-cache lifetime, and retains executable ownership fitness.

The current RED is real and source-bearing: `validated_outbound_http_client` awaits manual DNS resolution before the caller's request timeout begins. CI `33698726857` fails the intended end-to-end deadline contract. GREEN requires one absolute operation deadline shared across DNS validation and remaining HTTP work plus a deterministic stalled/delayed resolver runtime seam. Feed-specific/SOC/proxy timeout semantics must remain explicit; do not apply one phishing-feed constant globally. Final integration also follows protected #155 auth truth.

## Agent Artifact Admission

Draft #129 is exact `75f003e4c76182280011ca7ef63a952b7ab89b5a`. It owns the pre-execution structured artifact-install admission boundary and keeps hostile execution downstream. Current policy covers executable/ecosystem binding, exact coordinates/digests, indirect source/config/root/workspace/TLS authority, lifecycle-script/trust/integrity bypasses, Cargo build variants, and OCI platform ambiguity.

The current candidate adds fail-closed OCI platform-variant handling and hostile/edge coverage while preserving the public reason-code contract. Current workflows are queued/pre-execution, so keep Draft until exact-head deterministic/security/review evidence is terminal. Retrieved-byte or equivalent provenance verification and hostile execution remain executor/quarantine responsibilities.

## Release and supply-chain path

Wardnet still exposes no immutable GitHub Release. Issue #84 remains open and no branch may be represented as a production release merely because it can build an artifact.

Draft #164 is the new repository-owned release-evidence foundation. Its exact child head is `1d3f5a4bd618084031f3e722804b7c61303baeb5`. It was built from #77 parent `2f96565b9452ea49627b28f7ae380e07b68af115`; live #77 has since advanced to `46fef54c...` while repairing the deployment security finding, so #164 is currently non-mergeable and must be non-force restacked after #77 reaches protected main.

#164's review-driven security lineage is nevertheless useful and must be preserved:

- the PR-executable build/evidence job now has only `contents: read`; it cannot mint OIDC-backed attestations;
- attestation authority is isolated in a `workflow_dispatch`-only protected-main job with `id-token: write` and `attestations: write`;
- unnecessary `artifact-metadata: write` was removed;
- the attestation job downloads the exact SHA-named evidence bundle with an immutable `actions/download-artifact` pin, revalidates protected main, requested version, manifest source/version and SHA-256 records before provenance/SBOM attestation;
- a real zero-job workflow startup failure caused by job-level `runner.temp` use was reproduced and fixed by moving runner paths into step/runtime scope.

The repaired release workflow now materializes as run `33806666158`; build job `100818667579` remains queued before checkout with `runner_id=0`. Exact runner acceptance is on `.github#712`. #164 cannot tag, publish a GitHub Release, push an image, deploy, or promote from the feature branch. Final #84 evidence still needs immutable OCI identity/container-filesystem SBOM, admission-time verification, migration/canary/rollback and independent retention evidence on one protected release candidate.

## Scorecard and repository control-plane ownership

Draft #160 is exact `962623884347ccd52e653fb59504a7b848292086`. The first merged central reusable Scorecard owner (`.github@51b812d181989ed28366b5850d1a34f51df10187`) is not yet an acceptable immutable production pin because it uses Scorecard v2.4.3 while protected Wardnet already uses v2.4.4. `.github#1777` owns the forward-only reusable-owner repair. Wardnet must not restore a copied implementation or silently downgrade the scanner.

PR #153 remains the clean explicit-runner root at `b663f9d200e5f385c7dd067d074940a02836c68e`; #156/#157/#158 remain Draft children and are restacked only after #153 becomes protected truth. PR #159 retains PR-number concurrency and unique push run IDs so protected-main evidence is not replaced by another pending push.

## Context Fabric read-only boundary

Fresh metadata still reports `develop` as default for both Context Graph Contracts and EA Core. In CGC, `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` is protected while `main` at the same commit is unprotected; there is no GitHub Release. Release-provenance prerequisite #25 remains Draft exact `187f45927e697cfad9ac5b2523dfd86b695aa072`; DDD child #20 is `475ce14185db697940e8219c3cda7f24d66f3ed7`; Context Assertion/CloudEvent admission child #21 is `5cfab7d4819b94f3679d649367868e60f9c0d55a` on stale ancestry. No open PR head is production contract authority.

In EA Core, `develop@1c0fa8b15ceb9e72186274aeb255d6777eb84ef4` is protected and current `main@ca6889497728e1a3f09d68790a9096576e13a3ff` is unprotected; there is no GitHub Release. Live parent #39 is `c063570bd9177578fa75be69defd81c99e6ba2f3`; Draft projection child #40 is exact `723b6b94cb8afceb69c185a9995ce6fbd2dd65a2` and remains non-mergeable on obsolete parent ancestry. It must fail closed on unreleased CGC transport/admission contracts and be rebuilt non-force by the Context Fabric owner.

For both repositories, the accepted main/default transition is an owner-plane operational repair: protect main first, prove effective controls, switch default, re-read inherited rules, then rebuild roots/descendants. Wardnet does not mutate their source, refs, PR state, or branch topology.

## Live Wardnet queue

Fresh open-PR inventory contains 27 lanes:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #153, #155, #156, #157, #158, #159, #160, #162, #164`.

The merge/rebuild order is responsibility- and prerequisite-driven rather than oldest-first:

1. Protected exposure/security prerequisites: #155, then #77 when its repaired exact-head evidence is terminal; continue central governance/runner repair in parallel.
2. Network security: finish #136 DNS deadline/runtime RED and refresh it after #155 protected truth.
3. Supply chain: after #77 protected, non-force restack #164 and reacquire all release-evidence gates; #84 remains open until a real protected release identity exists.
4. Agent admission: finish #129 without absorbing quarantine execution or CO routing.
5. Control-plane foundations: #153, then restack #156/#157/#158; #159 can merge only on exact current deterministic/central evidence; #160 waits for the non-regressing central Scorecard owner.
6. Material UI #127 requires real-browser current-head WCAG 2.2 AA evidence for keyboard/focus, accessible name/description, responsive behavior and loading/error/permission states; source-string tests alone are insufficient.
7. #88 stays open but architecture-blocked until CO publishes a compatible immutable contract. Preserve unique credential/admission/streaming negative evidence while removing direct LiteLLM/provider/model authority in the eventual consumer reconstruction.
8. Broad/stale aggregates #90/#95/#112/#114/#115 are repair/transfer lanes, not Close candidates. Preserve unique OCSF/OTLP/syslog, PostgreSQL/outbox/Coraza, route lifecycle, rename/migration and official-feed deltas in bounded current-main successors before any retirement.
9. #162 remains the commercial-authority separation lane: the 2B KRW customer-readiness predicate is distinct from the standing USD 20B software-sale quality ambition. This file remains the sole writer for the product/technical gap baseline.

Closed/no-delta predecessor #154 is not returned to the queue. A PR is retired only by protected merge, explicit user instruction, malicious/no-valid delta, or verified complete successor transfer of all useful code/tests/fixtures/contracts/evidence.

## Open production gaps

The buyer-visible production order remains:

- #78 fail-closed management authentication through #155;
- #79 complete outbound allowlist/deny-overrides/evidence/deadline semantics through #136 and successors;
- #11 real attack-path CI and #75 deployable public path hardening;
- #128 Agent Artifact Admission through #129;
- #80 PostgreSQL production authority/tenant isolation, then #81 transactional outbox/leased effects;
- #82 Keyverse-backed identity/approval and #83 distributed/global admission without duplicating local limiter authority;
- #86 proven Coraza/CRS and Suricata detection with false-positive evidence;
- #84 immutable artifact/SBOM/provenance/reproducibility/rollback;
- #85 telemetry/SLO/incident/restore evidence;
- #87 final production-readiness closure only against one immutable protected release identity.

The root `src/lib.rs` remains a modularity pressure point, but file size alone does not justify a service split. Add dependency/ownership fitness first; prefer a modular monolith until transaction, isolation, scale, deployment or reuse evidence pays for another deployable boundary.

## Standards and evidence

Implementation and evidence remain grounded in current authoritative standards and primary/peer-reviewed work; citations constrain the design but do not prove a control is shipped.

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207
- Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- Lamb, C., & Zacchiroli, S. (2021). Reproducible builds: Increasing the integrity of software supply chains. *arXiv*. https://arxiv.org/abs/2104.06020
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082

Wardnet-owned production code targets 100% statement/branch/edge-case coverage and complete public rustdoc/docstrings. Security changes require realistic bypass/replay/race/DoS/network/cleanup tests and exact-source verification. Coverage exclusions, skipped paths, startup-failed/queued jobs, or evidence bound to another head/PR identity are not passing evidence.

## Release gate

No release is authorized at this snapshot. Wardnet, Context Graph Contracts, EA Core and the canonical external owners required by current integration work do not yet expose the complete compatible immutable release chain needed by Wardnet.

Release requires one exact integrated protected head with current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence, immutable artifact identity, and a verified publication path. A feature-branch artifact or attestation is evidence for the branch only; it is not a Wardnet release.
