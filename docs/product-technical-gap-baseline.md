# Product and technical gap baseline

Snapshot date: 2026-09-02. This document is a dated repository snapshot. Live refs, reviews, checks, rulesets, releases, and foreign-owner state must be re-read before any merge, release, or integration decision.

## Product and authority boundary

Wardnet is the Rust-first gateway/SOC control plane and owns Gateway, Admission Policy, Artifact Identity, Security Analysis Integration, Network-Egress, SOC Evidence, Runtime Control, Audit-Provenance, and the Agent Artifact Admission bounded context. It does not execute hostile workloads or own provider/model orchestration.

`ContextualWisdomLab/quarantine-sandbox-runtime` owns reusable hostile-workload isolation, execution lifecycle, cleanup, and artifact-analysis evidence. `contextual-orchestrator` owns Agent/LLM orchestration, provider/model discovery and routing, concrete model selection, provider credentials, and free/paid policy. EgressWeave is the canonical outbound HTTP-policy candidate. Wardnet consumes released/versioned ports and Anti-Corruption Layers; it does not copy those implementations or access foreign application databases.

The protected Wardnet tree still carries an integration debt at the optional SOC LLM seam: `soc_llm_chat_body(model, event)` accepts a caller model selector, and `tests/adaptive_orchestrator_default.rs` intentionally preserves that field. That is not the desired owner contract. Wardnet must eventually call a released/versioned contextual-orchestrator API/client/schema Agent without selecting a provider or concrete model. Fresh contextual-orchestrator release inventory is empty, so no mutable branch is promoted as the production replacement. Canonical CO owner PR #971 at `6fed18cf8d49248cea4904b14e4ed03b7e7fba88` already states that consumers must wait for integrated exact-head GREEN plus an immutable released API/client/schema before bumping.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel for canonical object/authority references, truth status/origin, valid/system time, provenance, Context Assertion, CloudEvents, schema, conformance, and admission. `enterprise-architecture-core` is the EA Decision Plane. Both remain read-only source dependencies from this writer while the dedicated Context Fabric writer is active. Security findings, alerts, malware verdicts, artifact risk scores, prompts, and customer/runtime data do not become authoritative EA facts.

## Protected truth and governance

Protected/default Wardnet `main` is `cc15cc2c34daf8c104eeb83d52a6a66f3cd6e128`. It contains PR #137's externally provisioned, non-optional Kubernetes administrator Secret boundary. Wardnet currently has no GitHub Release.

A fresh live read of organization ruleset `18156473` after its 2026-09-02 19:15 KST update still shows `~DEFAULT_BRANCH`, `required_approving_review_count=1`, `required_reviewers=[]`, no code-owner review, and no last-push approval requirement. Review-thread resolution, central required workflows, deletion protection, and non-fast-forward protection remain enabled. The live ruleset also still exposes routine `OrganizationAdmin/always` bypass capability; that existence is not normal merge authorization. Self-approval and bot/model-as-human approval are forbidden.

The bare approval count is structurally inconsistent with the declared solo-maintainer model. This is a central governance defect rather than a Wardnet staffing requirement. `.github#1644@8f95e06a5c6f7f471121344e4f1846c9893fbd38`, referencing #772 and related governance work, is the current owner-plane reconciliation candidate. Its source policy removes the impossible approval count while preserving deterministic workflow/security/coverage/SBOM/provenance/thread/branch-integrity controls. Source integration alone does not mutate live rulesets; the owner-plane apply remains separately privileged and must be proven from live settings before Wardnet treats the rule as repaired.

Runner acquisition is also a central control-plane concern. PR #153 pins repository-owned CI/Fuzz/Scorecard runner declarations to explicit `ubuntu-24.04` and permanently rejects floating `ubuntu-latest`. Exact head `b663f9d200e5f385c7dd067d074940a02836c68e` has already completed repository CI/Fuzz/Security/SAST successfully on that same source, proving the full hosted image is executable when admitted. Later exact-head waves across Wardnet, Context Graph Contracts, and EA Core have again remained pre-checkout with `runner_id=0`. `.github#712` owns that acquisition/capacity/policy-routing defect. `.github#1150@7981728db0862eb814588964182bf8aa107117b3` is the current read-only queue-health evidence successor: it preserves exact-current-head startup-failure evidence, but its own security/supply-chain checks are still queued or pending and it is not a runner-capacity repair by itself.

GitHub's current hosted-runner contract does not make `ubuntu-slim` an equivalent workaround: it is an unprivileged 1-vCPU/5-GB container runner with a 15-minute job ceiling intended for lightweight automation rather than typical heavyweight CI/CD. A successful slim job is therefore an admission canary, not justification to downgrade Wardnet CI/Fuzz/CodeQL/coverage workloads.

## Context Fabric live boundary

Fresh metadata still reports `develop` as the default branch for both `ContextualWisdomLab/context-graph-contracts` and `ContextualWisdomLab/enterprise-architecture-core`. Their protected `develop` tips remain `context-graph-contracts@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core@1c0fa8b15ceb9e72186274aeb255d6777eb84ef4`. Both expose zero GitHub Releases. The accepted protected-`main` transition remains central `.github`/Context Fabric owner work rather than a Wardnet source mutation.

Context Graph Contracts now has a dependency-root release-provenance prerequisite: Draft #25 is exact `f184cc4d44637fc429ba5d1072838f5d1dd1dc61` on #19 and binds package/SBOM identities to protected source plus independently verifiable manifest-attestation evidence. Its exact-current repository workflows remain pre-checkout/queued. Draft #20 remains exact `475ce14185db697940e8219c3cda7f24d66f3ed7`; child #21 remains exact `239a73d5f1a18b10ad317fdd51567b7fa040f570` on obsolete #20 ancestry and contains the structured Context Assertion/CloudEvent envelope and authority/conformance repair. The intended rebuilt order is `#19 -> #25 -> #20 -> #21`. No immutable CGC release exists, so Wardnet must not bind production behavior to any open PR head.

Enterprise Architecture Core #39 remains Draft at exact `c3879f172d97e2d814ff94d664be0a797e2228be` with current runner-acquisition evidence non-terminal. Child #40 remains Draft at exact `b3ec93a42528ab0defc0116ac4695d669298240f` on obsolete #39 ancestry. #40 already preserves the required Wardnet/quarantine authority boundary: `contextual-orchestrator -> quarantine application-service lease`, `Wardnet -> quarantine artifact-analysis evidence`, no malware verdict or artifact risk score as authoritative EA fact, and no direct database/source-copy integration. It explicitly remains fail-closed until compatible immutable CGC source-bound release evidence and qualifying quarantine release evidence exist.

Quarantine Sandbox Runtime, EgressWeave, and contextual-orchestrator expose no inspected immutable GitHub release usable as a Wardnet production dependency. Open sibling branches are evidence, not release authority.

## Live delivery queue

Fresh inventory contains 24 open PRs:

`#77, #88, #90, #93, #95, #111, #112, #114, #115, #127, #129, #130, #134, #135, #136, #140, #141, #144, #153, #154, #155, #156, #157, #158`.

PR #137 is protected-main truth. Predecessor checks, reviews, approvals, and artifacts do not transfer after head/base movement.

| PR | Exact head | State | Current decision |
| --- | --- | --- | --- |
| #88 LiteLLM ingress proxy | `98a935e4b058d0500d520425b8ebf6ff4106aa1b` | GitHub Ready flag, architecture Draft-required; mergeable false; RED | The direct LiteLLM virtual-key/provider proxy conflicts with contextual-orchestrator ownership. `tests/llm_owner_boundary.rs` now makes the repair gate executable: it remains RED while Wardnet ships the provider-specific proxy or chooses a SOC model. Preserve the unique fail-closed credential grammar, header minimization, streaming, zero-upstream-hit, property/fuzz and RFC 6750 evidence; do not close or merge it. Rework/transfer those valid Wardnet gateway/admission deltas behind a released CO ACL after CO publishes an immutable compatible client/schema/Agent. The connector Draft-state mutation currently fails before state change, so the UI Ready flag is not authority. |
| #129 Agent Artifact Admission | `1ea226df6ed871c64a0a749c7a4e4f5a6363e599` | Draft | Admission now also blocks npm workspace selectors (`--workspace`, `-w`, enabled `--workspaces`) in addition to previously covered uv/Cargo/pip/npm bypass classes. Current exact-head repository gates remain queued/non-passing; fresh review is required before Ready. Retrieval-byte/provenance verification and hostile execution stay executor/quarantine-owned. |
| #136 Network-Egress | `3e66c260bfcd09c7dc98dc5d1e931583f8379093` | Ready, source defect | Shared structural URL validation, resolved-address validation, DNS pinning, no ambient proxy/redirect, bounded client cache, response hop filtering, and architecture fitness are present. One exact-current review finding remains unresolved: manual `lookup_host` occurs before request timeout accounting, so slow DNS can exceed the intended feed/TAXII/KEV operation budget. Repair with deterministic bounded-resolution/deadline RED→GREEN before merge. #155 must also become protected truth before final integration. |
| #140 Runtime Configuration | `43d1b6e9122d8bb5cb882f8fc6e066c63b39ae45` | Ready | Security/SAST are GREEN on the current head; CI/Fuzz remain non-terminal. Runtime Configuration remains a supporting bootstrap boundary; Credential Registry remains secret authority. |
| #144 Kubernetes path/public docs | `9616b94ac1ecf70038071a8c9395348694e6312c` | Ready | Hardened manifest source moves to `deploy/kubernetes/wardnet.yaml` without renaming live Kubernetes resources. Review-driven path/link regressions are resolved. Current repository gates remain queued/non-passing. |
| #153 explicit hosted runner | `b663f9d200e5f385c7dd067d074940a02836c68e` | Ready, clean stack root | Same-source repository CI/Fuzz/Security/SAST have terminal GREEN evidence. Current central runner/review/governance evidence is non-terminal. `ubuntu-slim` is only an acquisition canary, not a heavyweight-workload replacement. |
| #154 commercial readiness target | `41098f76c8a823c20ba0e319c38cf24acb470346` | Ready | Aligns the shipped readiness threshold and buyer evidence to the 20B KRW target without rewriting historical plan artifacts. Current inline review-thread inventory is empty and the substantive automated review reports no source finding, but CI/Fuzz/Security/SAST are all queued on this exact head; queued evidence is non-passing. Normal auto-merge is armed but cannot integrate until live policy is satisfied. |
| #155 fail-closed management auth | `e6f05d77858e91c176cff25c4b11e790bc5dcdd1` | Ready, main-based | Non-loopback startup fails closed without write-capable admin credentials; current review threads are resolved. Same-source repository CI/Fuzz/Security/SAST have terminal GREEN evidence, while the latest replacement wave and central coverage/review gates remain non-terminal on the same source SHA. Issue #78 closes only after protected merge. |
| #156 operability evidence | `76037b8ae206ace8dab0e6622dfc9fc88c57deb3` | Draft, child of #153 | Preserve support-bundle/readiness evidence; reconstruct/restack on fresh protected main after #153 integrates, then regenerate all base-sensitive evidence. |
| #157 trusted proxy | `65a2b7fbf2827f69ae1aa288696b6c5630af28c4` | Draft, child of #153 | Preserve fail-closed forwarded-IP attribution. Reconstruct/restack after #153 protected merge. |
| #158 readiness metrics | `387a447f856093d02116dfadcf2c4a4a63c6d3ba` | Draft, child of #153 | Preserve readiness gauges using existing readiness/KPI authority. Reconstruct/restack after #153 protected merge. |

Auto-merge state, where enabled, is state only, not protected truth or transferable evidence. A changed head/base must reacquire the then-live policy evidence.

## Open issues and production order

Fresh issue inventory remains `#11, #38, #74, #75, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #89, #128, #139`.

1. Immediate exposure controls: #78 through #155, #79 through #136 plus remaining allowlist/evidence/deadline work, #11 real attack-path CI, and #75 through #144.
2. Security admission: #128 through #129, without absorbing quarantine execution authority.
3. LLM ownership repair: keep #88 open but non-integrable and RED until contextual-orchestrator ships the released provider-neutral contract; then preserve only Wardnet-owned credential/admission/streaming defenses and remove direct LiteLLM/provider/model authority.
4. Durable authority/effects: #80 PostgreSQL production authority and tenant isolation, then #81 transactional outbox/leased workers.
5. Identity/overload: #82 Keyverse-backed authorization/approval and #83 distributed/global admission. #157 is only the trusted-network attribution slice.
6. Proven security engines: #86 Coraza/CRS and Suricata with detection and false-positive evidence.
7. Immutable delivery/operation: #84 signed artifact/SBOM/provenance/rollback, then #85 telemetry/SLO/incident/restore evidence.
8. Supporting correctness: #74 deterministic persistence fault testing, #77 pinned compiler, #139 coherent runtime configuration, #153 deterministic hosted-runner selection, and #154 the 20B KRW commercial-readiness contract.

Close an issue only after its owning protected merge satisfies the issue acceptance contract on current evidence.

## DDD and implementation gaps

Agent Artifact Admission has a responsibility-aligned crate and domain-policy independence tests. Artifact retrieval verification, filesystem/mount/process isolation, and hostile execution remain downstream executor/quarantine responsibilities.

The legacy gateway remains concentrated in root `src/lib.rs`. File size alone is not a decomposition criterion, but repeated change pressure across client attribution, outbound policy, runtime configuration, proxying, SOC integration, rate limiting, support evidence, and management APIs is a real modularity signal. Add dependency/ownership fitness before structural movement and prefer a modular monolith until transaction, deployment, scaling, or reuse evidence justifies another deployable.

Network-Egress remains incomplete after #136. Besides the resolver-deadline defect, #79 still requires versioned hostname/suffix/IP/CIDR/scheme/port allowlists, deterministic deny-overrides precedence, connector parity, minimized policy-decision evidence, and operator migration/rollback/diagnostics.

The protected SOC LLM request builder and #88 together show the same ownership drift from two directions: caller-supplied model authority in current main and a direct LiteLLM proxy in an old feature branch. The repair is not another Wardnet provider adapter. It is a released contextual-orchestrator ACL followed by a Wardnet consumer bump and removal of local provider/model authority, with fail-closed behavior until that immutable dependency exists. The #88 architecture RED prevents this drift from becoming an accidental merge while the owner release is unavailable.

PR #95 remains too broad to serve as the production integration vehicle. Preserve its unique PostgreSQL/outbox/Coraza tests and evidence while reconstructing bounded #80/#81/#86 successor work instead of merging the cross-context god-PR.

## Research and standards grounding

Standards constrain implementation and evidence; they do not prove controls are shipped.

- Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207.
- Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218.
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/.
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082.

The microservices evidence is used only to resist decomposition-by-file-size: deployable boundaries require responsibility, scaling, transaction, isolation, or reuse evidence that justifies their operating cost.

## Quality and release gates

Wardnet-owned production code targets 100% statement/branch coverage and complete public rustdoc/docstrings. Security-critical changes require realistic hostile/bypass/replay/race/DoS/network/cleanup tests and current-source verification of review findings. Coverage exclusions, source rewriting, skipped required paths, or statuses bound to another revision are not evidence.

No release is authorized. Wardnet, Context Graph Contracts, EA Core, contextual-orchestrator, Quarantine Sandbox Runtime, and EgressWeave expose no usable immutable GitHub Release at this snapshot for the dependencies described above, and production release gate #87 remains open. Release requires one exact integrated protected head with CI/security/coverage/docstrings/package/SBOM/provenance/reproducibility/review/migration/rollback/recovery/operability evidence and immutable artifact identity.

## Next execution order

1. Continue #153/#155/#144/#154 through current exact-head gates while `.github#712` repairs runner acquisition and `.github#1644`/related owner work repairs solo-maintainer ruleset semantics.
2. Preserve #156/#157/#158 until #153 is protected, then non-force reconstruct/restack each child on fresh main and reacquire all evidence.
3. Repair #136's DNS-resolution deadline defect test-first; after #155 becomes protected truth, refresh #136 against live main and revalidate.
4. Finish #129 as one Agent Artifact Admission bounded context without absorbing quarantine or Agent/LLM orchestration.
5. Keep #88 open and architecture-blocked while contextual-orchestrator #971 completes canonical routing/client work and publishes an immutable compatible release; then reconstruct the Wardnet consumer slice against that released contract without direct model/provider authority.
6. Drain clean supporting work (#77, #90, #93, #111, #134, #135, #140, #141) only on unchanged exact heads with live evidence.
7. Reconstruct #95's valuable PostgreSQL/outbox/Coraza evidence into bounded #80/#81/#86 lanes.
8. Continue #82/#83/#84/#85 only after their declared prerequisites become protected/released truth.
9. Refresh this baseline whenever protected truth, queue topology, release state, or responsibility boundaries materially change.
