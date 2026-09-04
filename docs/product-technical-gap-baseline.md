# Product and technical gap baseline

Snapshot date: 2026-09-04. This file is the Wardnet-owned commercial/security integration baseline. It is not a substitute for live GitHub state: before merge, release, restack, or foreign-owner handoff, re-read exact heads/bases, reviews/threads, checks, security results, rulesets, releases, and branch protection.

## Product and authority boundary

Wardnet is the Rust-first gateway/SOC control plane. Its owned bounded contexts are Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, Audit-Provenance, and Agent Artifact Admission. Wardnet does not execute hostile workloads and does not own model/provider routing.

`quarantine-sandbox-runtime` owns hostile execution isolation, lifecycle, cleanup, and artifact-analysis execution. `contextual-orchestrator` owns Agent/LLM orchestration plus provider/model/key discovery and routing. EgressWeave is the canonical outbound HTTP-policy candidate. `appguardrail` retains application-guardrail authority. Wardnet consumes released/versioned ports or Anti-Corruption Layers only; it does not copy foreign implementations or use cross-service SQL.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical object/authority references, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents, schemas, conformance, and shared admission grammar. `enterprise-architecture-core` is the EA Decision Plane. Both are read-only dependencies from this Wardnet lane while the Context Fabric owner loop is active. Wardnet security findings and verdicts remain Wardnet evidence; EA may reference validated risk/remediation evidence but must not copy those verdicts as authoritative architecture facts.

The optional SOC LLM seam remains ownership debt until a compatible immutable `contextual-orchestrator` release exists. No mutable CO branch, direct provider key, provider/model selector, or paid fallback is production authority for Wardnet.

## Protected truth and central governance

Protected/default Wardnet `main` is `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. Wardnet still exposes no GitHub Release.

Live organization ruleset `18156473` targets `~DEFAULT_BRANCH` and still carries a generic one-approval requirement with no required reviewer/team, required conversation resolution, central required workflows, deletion/non-fast-forward protection, and routine `OrganizationAdmin/always` bypass. Under the declared solo-maintainer model, self-approval and model/bot-as-human approval remain forbidden. The bare approval count and routine bypass are central governance defects, not a reason to weaken Wardnet. `.github#772` and its live successor own reconciliation while deterministic CI/security/coverage/SBOM/provenance/thread/branch-integrity controls remain intact.

Runner/event/review materialization is separately owned by `.github#712` and related central control-plane lanes. `queued`, pre-checkout `runner_id=0`, empty `steps`, startup-failed CodeQL, and a model-review request that never produces a current-head verdict are non-passing evidence. They are not reasons for no-op consumer churn, runner downgrades, predecessor-evidence reuse, or routine bypass.

## Immediate protected-main security path

### #155 — fail-closed management authentication

PR #155 remains Ready/mergeable at exact `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` on protected `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. Repository-owned CI `33590350994`, Fuzz `33590350997`, Security Scan `33590350967`, and SAST Semgrep `33590350991` are terminal GREEN; returned inline review threads are resolved.

Required OpenCode run `33590351182` has terminal-success bootstrap `100122902000`, coverage-source-tree `100272722468`, and coverage-evidence `100479589911`. Final `opencode-review` job `100659819151` did acquire GitHub-hosted runner `1001655142`, completed setup and the authenticated current-head review request, then remained at the fail-closed verdict boundary until the administrative three-hour limit and ended `cancelled` around `2026-09-04T04:37:15Z`. The current defect is therefore verdict materialization/timeout semantics, not runner acquisition. Exact evidence and GREEN acceptance are on `.github#712` comment `5535918616`. Do not rerun-storm this unchanged head. #78 closes only when this exact or a verified successor delta reaches protected main through satisfiable ordinary governance.

### #77 — Rust toolchain plus duplicate-Deployment fail-closed repair

PR #77 is Ready/mergeable at exact `46fef54c9b5916eb77196fb515a8fabad13a05d1`. The lineage pins Rust `1.98.0` and repairs a valid duplicate-Kubernetes-Deployment security finding.

RED `43d2c874732063e418b3929e3435c388ccfa7c69` proved a first-match manifest validator could accept a valid target Deployment while a later YAML document with the same resource identity weakened the administrator Secret boundary. GREEN `17a2a1e833e6c4cab6101ef6a534589d75a5920a` requires exactly one canonical target Deployment and adds a hostile duplicate-resource regression. Current `46fef54c...` removes only the temporary source-text RED scaffold; the behavioral regression remains. The finding thread is resolved, but fresh exact-head CI `33807338426`, Security `33807338277`, SAST `33807338221`, Scorecard `33807338399`, and OSV `33807339076` remain queued/non-passing.

### #136 — Network-Egress DNS deadline repair

Draft #136 is now exact `28e5776388b2fc31e1d0567382871a1f599aa3ed` on protected `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`, and GitHub reports it mergeable.

The original source-bearing RED remains immutable evidence: head `3cb1047416c3aa7fa8eb352b842cc55ad8c21b19` produced terminal CI failure `33698726857` at `phishing_feed_dns_resolution_shares_the_end_to_end_operation_deadline`, proving manual DNS resolution could outlive the intended feed/TAXII/KEV operation timeout.

Production repair was present by `9978f8c643433b5df0398e3d9f3608546fdadecd`: callers establish one absolute `tokio::time::Instant` deadline before destination validation, `validated_outbound_http_client` wraps the actual `lookup_host` future with `tokio::time::timeout_at(deadline, resolution)`, and request I/O receives only the remaining budget. Current head `28e5776388...` completes the deterministic acceptance by binding the architecture fence to that exact resolver primitive and exercising a forever-pending resolver surrogate against the shared deadline. Clearfolio/SOC/proxy timeout semantics remain separate.

Exact-current CI `33842763514`, Fuzz `33842763449`, Security Scan `33842763513`, and SAST Semgrep `33842763530` are queued. CI job `100928237991` is pre-checkout with `steps=[]` and `runner_id=0`. Exact runner evidence and acceptance are on `.github#712` comment `5536431288`. The DNS review thread intentionally remains unresolved until this unchanged head actually executes the regression and the relevant exact-head gate is terminal GREEN. After #155 becomes protected truth, refresh/revalidate #136 against the new protected base before integration.

## Agent Artifact Admission

Draft #129 is exact `6dfd777e1e9ce8b42c87c3311911a35f64f97190`, mergeable on protected `main@cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. It owns the pre-execution structured artifact-install security admission boundary; it does not fetch or execute hostile workloads.

The lineage fail-closes executable/ecosystem confusion, undeclared operands, indirect source/config/workspace/root authority, lifecycle-script/trust/integrity bypasses, Cargo build variants, OCI platform ambiguity, Podman registry trust weakening, and repository-wide mutable OCI pull expansion. The first OCI cardinality RED `d7f429c37a3bd26ea746254defc5d65f33ef71f2` proved bare Docker/Podman `-a` / `--all-tags` could widen one reviewed digest pull into a mutable repository-wide artifact set; GREEN `7f06137453dc2296e4c4ac8c439777bf19ba7244` rejected those switches as `artifact_not_approved`.

Fresh review then found the same semantic authority could be expressed through Boolean assignment syntax. RED `883d1d37e05b0ccd9d30b2c1b25fd7d53c6fc8d8` adds hostile Docker/Podman `--all-tags=true` and `-a=true` cases that the prior exact-token predicate did not classify. Causal GREEN `e9e07e696c013dab88df6a5a6dc1be8306b9b688` recognizes true assignments in the existing artifact-variant boundary without creating a provider-specific transport owner or new public reason code. Coverage `2207a6f79522dc8b6cb95e817be648bb6ef9a7f3` includes long/short true spellings and explicit-false non-regression; current `6dfd777e...` records primary Docker/Podman/NIST traceability.

Exact-current CI `33848015533`, SAST Semgrep `33848015479`, Security Scan `33848015485`, and Fuzz `33848015550` are queued/non-passing. CI job `100944222630` is pre-checkout with no steps materialized. Exact runner-acquisition evidence and acceptance are on `.github#712` comment `5537096153`; no rerun storm or leaf churn is justified. Returned inline threads are resolved. The read-only owner handoffs on `context-graph-contracts#27` and `enterprise-architecture-core#45` were refreshed against `6dfd777e...`: Wardnet owns pre-execution artifact security admission, while Noema owns governed activation/orchestration. Shared conformance must reject activation that depends on missing/stale/blocking Wardnet evidence or semantically widened artifact identity/cardinality, while also rejecting a Wardnet allow receipt as sufficient product activation.

## Release and supply-chain path

Wardnet still has no immutable GitHub Release. Issue #84 remains open; a feature-branch build or attestation is not a production release.

Draft #164 is exact `1d3f5a4bd618084031f3e722804b7c61303baeb5`. It isolates PR build/evidence from OIDC attestation authority, removes unnecessary artifact-metadata write permission, binds source/version/hashes before protected-main attestation, and repairs a real zero-job workflow startup defect caused by job-level `runner.temp`. Its release workflow now materializes as run `33806666158`, while build job `100818667579` remains queued pre-checkout with `runner_id=0`; central runner evidence is on `.github#712`.

#164 was built from an older #77 parent and is currently stale/non-mergeable relative to live #77. After #77 reaches protected main, preserve the child delta in a non-force restack and reacquire all exact-head release-evidence gates. Final #84 acceptance still requires immutable OCI identity/container-filesystem SBOM, admission-time verification, migration/canary/rollback, reproducibility, and independent retention on one protected release candidate.

## Scorecard and repository control-plane ownership

Draft #160 is exact `962623884347ccd52e653fb59504a7b848292086`. The first merged reusable central owner at `.github@51b812d181989ed28366b5850d1a34f51df10187` would regress protected Wardnet from OSSF Scorecard v2.4.4 to v2.4.3. Current #160 therefore keeps only a thin caller shape and refuses to consume that regressing immutable owner. The corrective owner path is `.github#1777`; Wardnet must consume the resulting protected owner SHA only after the canonical reusable workflow is advanced without scanner-version regression. Do not restore a copied Scorecard implementation or pin a mutable central PR head.

PR #153 remains the clean explicit-hosted-runner root at `b663f9d200e5f385c7dd067d074940a02836c68e`; #156/#157/#158 remain Draft dependents to rebuild only after #153 becomes protected truth. PR #159 retains PR-number concurrency for superseded PR runs while using unique push run IDs so protected-main evidence is not silently displaced.

## Context Fabric read-only boundary

Fresh repository metadata still reports `develop` as default for both Context Graph Contracts and EA Core. Their accepted integration/default target is protected `main`; branch topology/protection repair remains the Context Fabric/.github owner path, not a Wardnet source decision.

For `context-graph-contracts`, the open dependency order remains `#4 -> #6 -> #7 -> #8 -> #12 -> #13 -> #14 -> #16 -> #17 -> #18 -> #19 -> #25 -> #20 -> #21`. Release-provenance prerequisite #25 remains exact `187f45927e697cfad9ac5b2523dfd86b695aa072` with current repository package/reproducibility/supply-chain workflows terminal GREEN on its recorded ancestry. #20 is exact `475ce14185db697940e8219c3cda7f24d66f3ed7`. Context Assertion/CloudEvent admission child #21 is exact `5cfab7d4819b94f3679d649367868e60f9c0d55a`, Draft/non-mergeable on stale ancestry, with zero current PR workflow runs. Issue #27 owns the future external-capability contract; issue #24 owns protected-source release evidence; issue #15 owns repository integration acceptance. No mutable PR head is production contract authority.

For `enterprise-architecture-core`, parent #39 remains exact `c063570bd9177578fa75be69defd81c99e6ba2f3` with terminal-success repository workflows on its recorded ancestry. Draft projection child #40 is now exact `52645dd62d8ea2dbdc9f7dc3d7c59304f8fd5649`, non-mergeable on obsolete #39 ancestry, with zero current PR workflow runs. Its current lineage retains exact Context Assertion admission identity in the EA projection receipt, structured CloudEvent media-type compatibility, and bounded Noema/quarantine projection semantics. EA continues to fail closed on unreleased/mutable CGC contracts. Issue #45 owns portfolio-level external-capability adoption mapping; Wardnet remains read-only.

The latest dependency sweep re-read repository ownership and GitHub Releases for `context-graph-contracts`, EA Core, `contextual-orchestrator`, `quarantine-sandbox-runtime`, EgressWeave, and `appguardrail`; none exposes a compatible immutable GitHub Release for the current Wardnet integration path. Therefore Wardnet does not promote mutable sibling heads into production authority.

## Live Wardnet queue

Fresh open-PR inventory contains 27 lanes:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #153, #155, #156, #157, #158, #159, #160, #162, #164`.

The merge/rebuild order is responsibility- and prerequisite-driven rather than oldest-first:

1. Protected exposure/security: #155 first, then #77 after its repaired exact-head evidence is terminal; central governance/review control-plane repair proceeds in parallel.
2. Network security: execute #136's exact pending-resolver regression, then refresh/revalidate it after #155 is protected truth.
3. Supply chain: after #77 protected, non-force restack #164 and reacquire all release-evidence gates; #84 remains open until one real protected release identity exists.
4. Agent admission: continue #129 without absorbing quarantine execution or Noema/CO orchestration.
5. Control-plane foundations: #153, then #156/#157/#158; #159 only on exact deterministic/central evidence; #160 waits for a non-regressing protected reusable Scorecard owner.
6. Material UI #127 requires real-browser current-head WCAG 2.2 AA evidence for keyboard/focus, accessible name/description, responsive behavior, and loading/error/permission states; source-string tests alone are insufficient.
7. #88 remains architecture-gated until CO publishes a compatible immutable contract. Preserve unique credential/admission/streaming negative evidence while removing direct LiteLLM/provider/model authority in the eventual reconstruction.
8. Broad/stale aggregates #90/#95/#112/#114/#115 are repair/transfer lanes, not Close candidates. Preserve their unique OCSF/OTLP/syslog, PostgreSQL/outbox/Coraza, route lifecycle, rename/migration, and official-feed deltas in bounded current-main successors before retirement.
9. #130 remains the sole writer for this baseline. #162 owns commercial-authority separation: the 2B KRW customer-readiness predicate is distinct from the standing USD 20B software-sale quality ambition.

A PR is retired only by protected merge, explicit user instruction, malicious/no-valid delta, or verified complete successor transfer of all useful code/tests/fixtures/contracts/evidence.

## Open production gaps

Buyer-visible production order remains:

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

The root `src/lib.rs` remains a modularity pressure point, but file size alone is not evidence for a service split. Add dependency/ownership fitness first and prefer a modular monolith until transaction, isolation, scale, deployment, or reuse evidence pays for another deployable boundary.

## Standards and evidence

Implementation/evidence remains grounded in authoritative standards and primary or peer-reviewed work; citations constrain design but do not prove a control is shipped.

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207
- Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- Lamb, C., & Zacchiroli, S. (2021). Reproducible builds: Increasing the integrity of software supply chains. *arXiv*. https://arxiv.org/abs/2104.06020
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082

Wardnet-owned production code targets 100% statement/branch/edge-case coverage and complete public rustdoc/docstrings. Security changes require realistic bypass/replay/race/DoS/network/cleanup tests plus exact-source verification. Coverage exclusions, skipped paths, queued/startup-failed jobs, wrong-PR same-SHA evidence, or evidence bound to another head are non-passing.

## Release gate

No release is authorized at this snapshot. Release requires one exact integrated protected head with current CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence, immutable artifact identity, and a verified publication path. A feature-branch artifact or attestation is evidence for that branch only; it is not a Wardnet release.