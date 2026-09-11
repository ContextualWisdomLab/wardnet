# Product and technical gap baseline

Snapshot date: 2026-09-12. Re-read live refs, PRs, review threads, exact-head checks, rulesets, security evidence, owner contracts and releases before merge, release, restack or handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Draft/feature heads are provisional evidence; predecessor GREEN never transfers after a head or base moves.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution, isolation, cleanup and effective runtime environment/configuration authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider orchestration. `appguardrail` owns static package/security analysis. Keyverse remains the credential/identity backend.

Wardnet consumes released/versioned ports or ACLs only. It does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, execute package managers, or turn a reputation/admission decision into runtime or transport authority. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny. Browser acquisition, sessions, anti-bot challenges and CAPTCHA handling remain outside Wardnet.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth. Architecture-relevant lifecycle, ownership, risk and remediation may be projected only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. That protected change makes management writes fail closed when a public bind has no write-capable administrator credential. It is protected source truth, not an immutable release: Wardnet's fresh GitHub Release inventory remains empty.

Live organization ruleset `18156473` still requires one approving review plus thread resolution while naming no independent reviewer/team. Self-approval and model/bot-as-human approval are forbidden. `.github#772` owns that solo-maintainer governance defect. Central required workflows, deletion and non-fast-forward controls remain fail closed; routine administrator bypass is not merge evidence.

Runner/materialization failures remain `.github#712` / `.github#1234` authority. Delegated current-head CodeQL settlement remains `.github#1929`; the current canonical repair successor is Draft `.github#2040`. Wardnet does not copy central workflow logic, pin mutable repair heads, create no-op source churn to manufacture dispatch, or promote a later central scan over a failed required leaf gate.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed #130's own current SHA as product evidence. Each new ledger commit invalidates predecessor #130 workflow and review receipts and must reacquire exact-head evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps CGC protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and EA protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both GitHub Release inventories are empty.

CGC owner work remains mutable/unreleased. In addition to the existing Draft contract stack, Draft #25 is now exact `10e5f4abc430437cfd15f79142703ac2b1fc612e` on parent #19 `db392d8aac550d88986a14011956e5e2e7fce677`; it binds release evidence to protected source identity and documents dependency order `#19 -> #25 -> #20 -> #21`. That is owner-side compatibility evidence only, not Wardnet production authority. EA #40 remains Draft exact `6bbdadddca345ba6eb33ad86e3fba99f417ad529` and likewise remains unreleased. Wardnet writes neither repository and does not promote Wardnet verdicts into authoritative EA truth.

## Commercial authority separation

Draft #162 owns the naming/authority repair that separates the 2B KRW customer-contract readiness predicate from the standing USD 20 billion product-quality ambition. Exact #162 remains `3e3a19a115448d5787ceaa34929018fb832fdd3d` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`; protected #155 authentication/security truth is inherited rather than copied. Repository/security lanes are already green except required CodeQL settlement; keep Draft and do not use predecessor evidence, self/model approval, source churn or routine bypass.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 is `83514f9c9b69d9438af6fb866e5815ead737d5e7` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. It advanced by normal expected-head integration of verified child #340; no force update, destructive rebase, approval bypass or gate weakening was used.

The candidate preserves deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only; it is not proof of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

The latest causal slice is issue #339 / child #340. Test-only exact `d4639c9b77a458b244241ebc78dedb22c13fdd74` produced semantic RED in CI `34649961884`, rust job `103429556651`: checkout, pinned Rust setup and `cargo fmt --check` passed, then `cargo test --locked --workspace` failed because direct `pip --prefi=/tmp/wardnet-pip-prefix` remained `Allow` instead of the required `Block`. The preceding formatting-only failure was not semantic RED.

Minimum production repair exact `93b3f66b6bdb3e066e7360bb7a24918d75b9abbd` extends only the pinned direct-pip parser's verified unambiguous `--prefix` language, from `--prefi` through canonical `--prefix`, while rejecting ambiguous `--pref`, unrelated/superstring forms and non-long-option grammar. It does not execute pip, inspect/create/delete the destination, or absorb quarantine filesystem/workspace/isolation authority. Exact child CI `34650405906` and Fuzz `34650405852` completed SUCCESS before normal integration into #129. The earlier verified `--ta` through `--target` repair remains inherited; uv keeps independent parser semantics.

Fresh root evidence on exact #129 `83514f9c9b69d9438af6fb866e5815ead737d5e7` has CI `34651107815`, Fuzz `34651107792` and SAST Semgrep `34651107855` terminal SUCCESS. At the last fresh observation Security Scan `34651107865` was QUEUED and CodeQL PR `34651107816` was IN_PROGRESS, so root promotion is not yet terminal-valid. Re-read those exact runs rather than transferring child GREEN. Keep #339 and earlier admission findings open until their effective deltas reach protected `main` or a verified complete successor carries all code, tests, contracts and evidence.

Primary traceability for these admission controls remains in the corresponding `docs/doctoring/pypi-*.md` evidence and ADR/design authority. The parser classifiers are security boundary code, not a reimplementation of pip networking, resolution or execution.

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
- National Institute of Standards and Technology. (2020). *Zero Trust Architecture* (NIST SP 800-207). https://doi.org/10.6028/NIST.SP.800-207 — authority separation, explicit verification and deny-by-default trust boundaries.
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/ — application/API verification requirements used for management and buyer-facing surfaces.
- Soldani, J., Tamburri, D. A., & van den Heuvel, W.-J. (2018). The pains and gains of microservices: A systematic grey literature review. *Journal of Systems and Software, 146*, 215–232. https://doi.org/10.1016/j.jss.2018.09.082 — supports explicit service ownership and avoidance of hidden cross-service coupling; it is contextual research, not implementation proof.

NIST SP 800-218 Revision 1 / SSDF 1.2 is still an initial public draft as of this snapshot, so Wardnet monitors it but does not treat draft text as a final release gate. Final SP 800-218 Version 1.1 remains normative project guidance until the revision is finalized.

## Release readiness and buyer gaps

Wardnet is not release-ready. Protected #155 materially improves management authentication, but production gaps remain: Runtime Configuration/Keyverse integration and separation of duties; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; current-head graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC, EA, EgressWeave, contextual-orchestrator, quarantine or AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep #129 source stable while its fresh exact-root Security Scan and CodeQL/central required workflows settle; CI, Fuzz and SAST already passed on exact `83514f9c9b69d9438af6fb866e5815ead737d5e7`. Do not add no-op churn or reuse #340 child GREEN as root promotion evidence. Keep #291, #162, #127, #134, #181 and #77 stable where repository/security lanes are already terminal; route delegated-CodeQL settlement through `.github#1929` / canonical successor #2040 rather than leaf workarounds. #164 remains behind #77.

Repair #310/#140 foundation-first by ordinary non-force semantic conflict integration, then restack dependent trusted-proxy/PostgreSQL lanes in dependency order and invalidate/reacquire their exact-head evidence. Continue runner/materialization, delegated CodeQL, solo-maintainer governance and other central-control-plane defects through their canonical `.github` owner paths rather than copying workflows into Wardnet.

Only after protected prerequisites and all then-live gates are terminal-valid may Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL, mutable dependency authority or predecessor-evidence transfer.