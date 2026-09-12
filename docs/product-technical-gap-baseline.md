# Product and technical gap baseline

Snapshot date: 2026-09-12. Re-read live refs, PRs, review threads, exact-head checks, rulesets, security evidence, owner contracts and releases before merge, release, restack or handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Draft/feature heads are provisional evidence; predecessor GREEN never transfers after a head or base moves.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution, isolation, cleanup and effective runtime environment/configuration authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider orchestration. `appguardrail` owns static package/security analysis. Keyverse remains the credential/identity backend.

Wardnet consumes released/versioned ports or ACLs only. It does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, execute package managers, or turn a reputation/admission decision into runtime or transport authority. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny. Browser acquisition, sessions, anti-bot challenges and CAPTCHA handling remain outside Wardnet.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth. Architecture-relevant lifecycle, ownership, risk and remediation may be projected only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. That protected change makes management writes fail closed when a public bind has no write-capable administrator credential. It is protected source truth, not an immutable release: Wardnet's fresh GitHub Release inventory remains empty.

Live organization ruleset `18156473` still requires one approving review plus thread resolution while naming no independent reviewer/team. Self-approval and model/bot-as-human approval are forbidden. `.github#772` owns that solo-maintainer governance defect. Central required workflows, deletion and non-fast-forward controls remain fail closed; routine administrator bypass is not merge evidence.

Runner/materialization failures remain `.github#712` / `.github#1234` authority. Delegated current-head CodeQL settlement remains `.github#1929`; the current canonical repair successor is Draft `.github#2040`, exact `3b2de64c2c4c95c56d2f5099a480a0825304d038` on central protected `main@cb0872c9a20d5584703dffacca65c096fc034c6c` at this snapshot. That mutable owner head is compatibility/repair evidence only. Wardnet does not copy central workflow logic, pin mutable repair heads, create no-op source churn to manufacture dispatch, or promote a later central scan over a failed required leaf gate.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed #130's own current SHA as product evidence. Each new ledger commit invalidates predecessor #130 workflow and review receipts and must reacquire exact-head evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps CGC protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and EA protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both GitHub Release inventories are empty.

CGC owner work remains mutable/unreleased. In addition to the existing Draft contract stack, Draft #25 is exact `10e5f4abc430437cfd15f79142703ac2b1fc612e` on parent #19 `db392d8aac550d88986a14011956e5e2e7fce677`; it binds release evidence to protected source identity and documents dependency order `#19 -> #25 -> #20 -> #21`. That is owner-side compatibility evidence only, not Wardnet production authority. EA #40 remains Draft exact `6bbdadddca345ba6eb33ad86e3fba99f417ad529` and likewise remains unreleased. Wardnet writes neither repository and does not promote Wardnet verdicts into authoritative EA truth.

## Commercial authority separation

Draft #162 owns the naming/authority repair that separates the 2B KRW customer-contract readiness predicate from the standing USD 20 billion product-quality ambition. Exact #162 remains `3e3a19a115448d5787ceaa34929018fb832fdd3d` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`; protected #155 authentication/security truth is inherited rather than copied. Repository/security lanes are already green except required CodeQL settlement; keep Draft and do not use predecessor evidence, self/model approval, source churn or routine bypass.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 is `9e90a4abbd42e3a790ba51c460e4b35e11042e1c` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, produced by ordinary expected-head merge of verified child #348 into prior exact root `8f74665077698a755cd4748e1f27747840ea0152`. No force update, destructive rebase, self/model approval, gate weakening, mutable foreign dependency or routine bypass was used.

The candidate preserves deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only; it is not proof of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

The latest causal slice is issue #347 / child #348. Test-first RED `ebbaeab99b93e1ba8a630a29b7bd6407ea23002a` preserved the preceding production behavior and proved that parser-valid direct `pip` / `pip3` global proxy authority before the `install` subcommand was not classified through the intended trust-root path. The minimum source repair `0e58a71968acd534355e4a1ad904ba04d32ad054` adds only a bounded pre-policy normalization for reviewed global `--proxy` / unambiguous `--prox` spellings, then restores `command_sha256` from the exact submitted argv so audit identity never hashes the normalized internal view. Formatting follow-up `5014a2e2ea9c29a16c37457d63a70abc36d6b224` and traceability response `5a3e85e2a5550e0311c2fe555b0dc0f4a03ad95e` complete the child without widening runtime, networking or filesystem authority.

The child precision suite requires the global proxy route to block with `AlternateTrustRoot`, prevents the consumed separate-token proxy value from masquerading as an artifact, preserves an actual extra package operand as `ArtifactNotApproved`, keeps unknown global grammar fail closed, and preserves the submitted command hash. Exact child `5a3e85e2a5550e0311c2fe555b0dc0f4a03ad95e` passed CI `34665161389` and Fuzz `34665161314`, had zero unresolved inline review threads, and was merged normally with fixed expected head into #129, producing `9e90a4abbd42e3a790ba51c460e4b35e11042e1c`.

The earlier #343/#344 pip short-option cluster repair, #341/#342 `-U` / `--upgrade` repair, #339/#340 `--prefi`…`--prefix` repair, `--ta`…`--target` repair, and the reviewed certificate/proxy/configuration/cache/output/dependency-group/no-clean and related admission controls remain inherited. Their child or predecessor receipts are historical after the root moved and do not transfer to this exact candidate. Open predecessor findings remain open until their effective deltas reach protected `main` or a verified complete successor preserves every valid code/test/fixture/contract/evidence delta.

Fresh root evidence on exact #129 `9e90a4abbd42e3a790ba51c460e4b35e11042e1c`: CI `34665569341`, Fuzz `34665569378`, Security Scan `34665569296`, and SAST Semgrep `34665569460` are terminal SUCCESS. Required CodeQL PR `34665569493` is terminal FAILURE despite exact-head language detection/checkout success: `CodeQL compatibility analysis (actions)` job `103476658494` successfully read the current-head dispatch verdict and then failed `Release runner or enforce current-head CodeQL verdict`; downstream job `103477055292` subsequently dispatched the unchanged-head scan successfully. The later dispatch does not promote the already failed required workflow. This exact tuple is central `.github#1929` evidence, not a Wardnet-source defect or bypass case.

Primary traceability for these admission controls remains in the corresponding `docs/doctoring/pypi-*.md` evidence and ADR/design authority. Parser normalization/classification is a bounded admission grammar, not a reimplementation of pip networking, resolution or execution. Foreign runtime/environment/filesystem authority remains with quarantine-sandbox-runtime, outbound transport authorization with EgressWeave, orchestration with contextual-orchestrator and static package analysis with AppGuardrail.

## Phishing.Database SSRF repair

Protected-baseline companion #295 established causal RED: an authenticated request-selected Phishing.Database loopback URL could be fetched through the former non-default-host bypass. Production repair #291 removes request-controlled feed URLs and the non-default-host bypass, resolves feed URLs server-side, keeps loopback override under `cfg(test)` only, validates the server-owned source host, and preserves the no-redirect client.

Current #291 remains exact `e01683d526da058a813f8d8f0fe87a52c3594b39` on protected main. CI, Fuzz, Security Scan and SAST are GREEN; required CodeQL remains a delegated-settlement failure. That ordering is central owner evidence, not justification to weaken or duplicate the workflow.

## Gateway route-boundary repair

Issue #180 / Draft #181 owns only Wardnet route-selection lexical-prefix semantics. Causal RED proved `/api` captured lexical siblings and `/api/admin` captured `/api/administrator`; the minimum repair keeps exact/slash-delimited descendant matching, root catch-all and longest-valid-match semantics without changing transport authorization.

Exact #181 remains `abbaff14a452671238c83c1325da22e15f9ee2ac` on protected main. Repository/security lanes are GREEN and required CodeQL remains at the delegated settlement boundary. Keep Draft; ordinary RED required workflows are not a guarded-bypass case.

## Outbound destination reputation

#173 remains Proposed/Draft Wardnet-owned reputation architecture, exact `8408c2d50e6419d551bfcccd8d72a97284f36a82`. Its current repository/security/CodeQL evidence is terminal GREEN, but production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns destination reputation into transport authority and does not consume mutable EgressWeave source/PR heads. Future EA projection must use released CGC provenance only.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217 -> #219 -> #221 -> #223 -> #224 -> #225 -> #226 -> #228 -> #229 -> #231 -> #233 -> #234 -> #236 -> #241 -> #242 -> #244. Parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence.

Root #140 remains exact `0c678a924e3bf6ecdd248167e4289c1cbff60688` while retaining pre-#155 ancestry. Reverse-direction helper #310 remains the repair lane for the remaining `src/lib.rs` semantic conflict; `src/credentials.rs` is already reconciled. The final repair must make `run_from_env` consume #140's immutable non-secret `RuntimeConfiguration` while retaining every #155 strict `ADMIN_TOKENS`, write-capable-principal, `require_write_auth_for_bind`, readiness `auth_mode`, loopback-listen, management 401/403, body/rate-limit and shutdown invariant. Secrets stay in the hardened `CredentialRegistry`; parse helpers stay single-sourced in `runtime_config.rs`. Wholesale ours/theirs selection, force/rebase or dependent-stack movement would discard valid authority.

The lineage also carries fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness, ambiguous-COMMIT fail-closed handling, physical recovery drills, divergent-writer serialization and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, exact coverage/rustdoc evidence, backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and lifecycle buyer paths

Draft #127 owns server-rendered admin-console browser acceptance: loading/normal/permission-denied states, keyboard skip-link transfer, computed accessibility semantics, atomic status announcements and 375/768/1440 clipping/overflow bounds. Browser/accessibility/responsive evidence is green; required central CodeQL remains non-passing, so the UI Delivery Gate remains PARTIAL rather than complete.

Draft #245 owns test-first Unix SIGINT graceful shutdown. Draft #134 owns support-bundle count and secret-redaction regression and has non-force adopted protected #155. Their repository/security lanes are green while required delegated CodeQL settlement remains non-passing; neither is a bypass candidate.

## Rust reproducibility and release evidence

#77 is the Rust/reproducibility prerequisite for #164. Draft #77 exact `1349b75b6e1441e531ebb443b32546ff707ac467` has repository/security lanes green and delegated CodeQL non-passing. Draft #164 exact `5f0be7710d3d36c4847e0c2f0a39de116dcf35e7` remains correctly stacked behind #77 and owns release-evidence/SBOM/provenance foundations only; it is not a release.

The PR-executable release-evidence job is read-only and may build/test/SBOM/upload evidence but does not mint protected OIDC-backed release attestations. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

## Research and standards grounding

The standards below constrain controls and acceptance criteria; they are not substitutes for exact-head implementation evidence.

- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218 — final baseline for secure development practices, provenance and verification discipline.
- National Institute of Standards and Technology. (2024). *Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile* (NIST SP 800-218A). https://doi.org/10.6028/NIST.SP.800-218A — final AI-specific profile relevant to agent/tool/package supply-chain risk.
- Boyens, J., McWhite, R., & Calloway, L. (2026). *NIST Cybersecurity Supply Chain Risk Management: Due Diligence Assessment Quick-Start Guide* (NIST SP 1326). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.1326 — final July 2026 guidance for ICT supplier/product due diligence; provenance, resilience, foundational cyber practices, ownership/control influence and supply-chain tiers inform artifact/supplier evidence without shifting execution or transport authority into Wardnet.
- National Institute of Standards and Technology. (2024). *Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations* (NIST SP 800-161 Rev. 1, Update 1). https://doi.org/10.6028/NIST.SP.800-161r1-upd1 — final updated C-SCRM baseline for supplier, provenance, vulnerability and SBOM risk management.
- National Institute of Standards and Technology. (2020). *Zero Trust Architecture* (NIST SP 800-207). https://doi.org/10.6028/NIST.SP.800-207 — authority separation, explicit verification and deny-by-default trust boundaries.
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/ — application/API verification requirements used for management and buyer-facing surfaces.
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082 — supports explicit service ownership and avoidance of hidden cross-service coupling; it is contextual research, not implementation proof.

NIST SP 1326 became final on 2026-07-08 and now supplements SP 800-161 Rev. 1 for implementation-ready supplier/product due diligence. NIST SP 800-218 Revision 1 / SSDF 1.2 is still an initial public draft as of this snapshot, so Wardnet monitors it but does not treat draft text as a final release gate. Final SP 800-218 Version 1.1 remains normative project guidance until the revision is finalized.

## Release readiness and buyer gaps

Wardnet is not release-ready. Protected #155 materially improves management authentication, but production gaps remain: Runtime Configuration/Keyverse integration and separation of duties; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; current-head graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC, EA, EgressWeave, contextual-orchestrator, quarantine or AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep #129 source stable on exact `9e90a4abbd42e3a790ba51c460e4b35e11042e1c`: CI `34665569341`, Fuzz `34665569378`, Security Scan `34665569296`, and SAST `34665569460` are GREEN; required CodeQL `34665569493` reproduced the central current-head verdict/release failure before a successful downstream dispatch. Route that exact tuple through `.github#1929` and its live successor #2040 rather than leaf source churn, blind reruns, synthetic status or bypass.

Keep #291, #162, #127, #134, #181 and #77 stable where repository/security lanes are already terminal; route delegated-CodeQL settlement through the central owner path rather than source churn. #164 remains behind #77. Repair #310/#140 foundation-first by ordinary non-force semantic conflict integration, then restack dependent trusted-proxy/PostgreSQL lanes in dependency order and invalidate/reacquire their exact-head evidence. Continue runner/materialization, delegated CodeQL, solo-maintainer governance and other central-control-plane defects through their canonical `.github` owner paths rather than copying workflows into Wardnet.

Only after protected prerequisites and all then-live gates are terminal-valid may Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL, mutable dependency authority or predecessor-evidence transfer.