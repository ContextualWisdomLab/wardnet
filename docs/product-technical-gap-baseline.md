# Product and technical gap baseline

Snapshot date: 2026-09-15. Re-read live protected refs, PR/Issue heads and bases, stacks, reviews, review threads, exact-head checks, rulesets, security evidence, foreign-owner contracts and releases before any merge, release, restack or handoff. Draft/feature heads are provisional evidence; predecessor GREEN never transfers after a head or base moves.

This file is Wardnet's sole commercial/product-technical current-state ledger. PR #130 is the sole writer for this path. It records current truth and active gaps, not a substitute changelog for every historical repair.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle, security policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution, isolation, cleanup and effective runtime/interpreter/filesystem authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider/tool orchestration. `appguardrail` owns its application/agent guardrail implementation. Keyverse remains credential/identity backend.

Wardnet consumes foreign capabilities only through released/versioned ports, evidence contracts or ACLs. It does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, execute package managers, or turn a reputation/admission decision into runtime or transport authority. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories both read-only while the Context Fabric writer owns them. Wardnet findings, IOCs, destination assessments, admission verdicts and incidents remain Wardnet truth. Architecture-relevant lifecycle, ownership, risk and remediation may be projected only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. The branch is protected and still requires the repository-owned `rust` status. Organization ruleset `18156473` is active on the default branch and requires one approving review, resolved review threads and the seven central required workflows: OpenCode review, PR review/merge scheduler, Security Scan, Strix, SAST Semgrep, Noema review and CodeQL PR. Allowed merge methods are merge/squash; deletion and non-fast-forward updates are prohibited.

Generic solo-maintainer approval remains central `.github#772` or verified successor. Hosted-runner/materialization/OpenCode control-plane defects remain `.github#712` / `.github#1234` or verified successors. Delegated current-head CodeQL terminal settlement remains `.github#1929` or verified successor. These are actionable owner defects, not reasons to copy central workflows into Wardnet, manufacture no-op source churn, synthesize status, self/model approve, weaken gates or routinely use administrator bypass.

Wardnet's immutable GitHub Release inventory remains empty. Protected source truth is therefore not yet an immutable commercial release. A release-ready candidate still requires one protected exact head that binds aligned version/CHANGELOG, tag, package/image digest, SBOM, provenance/attestation, reproducibility, deployment promotion, rollback/roll-forward and recovery evidence with all then-live gates terminal-valid.

## Architecture, product and documentation authority

Protected `AGENTS.md`, `CLAUDE.md` and `docs/architecture.md` preserve Wardnet's Rust-first baseline. Draft #111 remains the accepted-ADR consolidation lane; its accepted ADR text is provisional until that Draft reaches protected `main` and must not be described as protected-main authority. Draft #361 remains the canonical PRD/TRD/UML lane at exact `c6d3fd45eba1aceef074cc8b9934937f67b1d41a`; it records released-contract-only dependencies, realistic asynchronous Wardnet-owned buyer-path p95 <= 20 ms, release/SBOM/provenance requirements, mandatory Material UI Figma/Storybook/state/locale evidence, and the no-long-lived-database-transaction-across-slow-work rule. Draft #333 remains the sole CodeGraph guidance repair. These lanes are disjoint from this ledger and must not be duplicated here.

Material UI work remains incomplete unless reusable design/tokens/components plus Figma/Storybook evidence exist and buyer-critical flows cover normal, loading, empty, error, permission-denied, responsive, keyboard/accessibility states and KO/EN/JA/ZH/VI/ES/DE/FR text-layout robustness. Visible mock behavior or decorative controls are not completion.

## Context Fabric and foreign-owner release inventory

Fresh read-only inventory keeps CGC protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and EA protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both immutable GitHub Release inventories remain empty. Wardnet writes neither repository while the Context Fabric writer owns them and does not bind production behavior to those mutable default branches.

Foreign-owner protected/default refs currently inventory as `quarantine-sandbox-runtime develop@60a85c7633e03b425b67159ec6822c8178cf87ea`, `EgressWeave main@bd0339bf43cf5041e861bac86a84cb6e7e32637e`, `contextual-orchestrator main@767e67fbc6b881a452761f32abb69b9971b9b03b`, and `appguardrail develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`. Their immutable GitHub Release inventories remain empty. These mutable refs are inventory evidence only; missing immutable owner releases/contracts are capability gaps, not permission to duplicate canonical implementation inside Wardnet.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact root is `#129@625879592f0a4d7b06374df2a827cf08f304feb3` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. That head was produced by an ordinary expected-head merge of serialized child #427; no force update, destructive rebase, self/model approval, gate weakening or mutable foreign dependency was used.

The candidate preserves deny-by-default structured-argv admission; reviewed workspace-manifest SHA-256; exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding; package-manager source, trust, destination, configuration, lifecycle, mutation, dependency/build/platform/cardinality controls; audit-before-allow; bounded remote-instruction provenance; exact submitted-argv identity; and parser-phase separation between package-manager-owned authority and delegated child argv. An `allow` receipt is admission authority only. It is not proof of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation, activation, LLM/tool execution or guardrail execution.

Issue #426 / PR #427 repaired the distinct uv global-option artifact-operand evidence defect. Test-only exact `d0a0e38f7cea8b38cb195a5f9148e39fd36e20bd` established semantic RED after checkout/toolchain/format: CI `34795158441` reached Rust tests and proved parser-valid uv global options could hide causal `ArtifactNotApproved`; Fuzz `34795158448` succeeded. The minimum production repair reused `uv_active_command_index()` in `validate_artifact_operands()` and consumed install-root handling without widening `supported_install_command`. After correcting a test-oracle defect, final child exact `27e450bcfc8280376619f0331766eb2ed0efc796` completed CI `34847171263` **SUCCESS** and Fuzz `34847171299` **SUCCESS** with CodeRabbit/Devin statuses successful and no submitted reviews or inline review threads. PR #427 was then normally merged into #129 as merge commit `625879592f0a4d7b06374df2a827cf08f304feb3`. Issue #426 remains open because the effective delta has not reached protected `main`.

That root movement invalidates all predecessor #129 workflow receipts as current evidence. Exact-current #129 repository lanes show CI `34884595676` **SUCCESS**, Fuzz `34884595640` **SUCCESS**, SAST Semgrep `34884595634` **SUCCESS**, and Security Scan `34884595678` **SUCCESS**. CodeQL PR `34884595690` is terminal **FAILURE** only at the centrally owned delegated current-head settlement boundary; exact unchanged-head evidence is already handed to `.github#1929`. The failed required workflow remains non-passing and is not replaced by downstream dispatch, predecessor GREEN, source churn or bypass.

Issue #428 is the next serialized admission finding. Draft #429 is the sole child writer, based exactly on `#129@625879592f0a4d7b06374df2a827cf08f304feb3`. The hostile contract exercises `uv --color never pip install -r cwl-example==1.2.3 --require-hashes --no-deps --no-python-downloads`, where the reviewed package token is consumed as a requirements-file operand rather than a direct package operand. Controls cover attached `--color=never`, non-install `uv ... pip sync`, the ordinary reviewed direct install, exact argv hashing and consumed install-root semantics.

Test-only exact `6619db4fb82203af6cc6ac55c788fa679af9c33a` established hosted semantic RED. Fuzz `34911607856` completed **SUCCESS**. CI `34911607878`, rust job `104200113638`, passed checkout, Rust toolchain and `cargo fmt --check`, then failed `cargo test --locked --workspace` at exactly `uv_global_requirement_source_preserves_indirect_artifact_evidence` and `attached_uv_global_option_preserves_indirect_artifact_evidence`. Both observed only `[ForbiddenCommand]` instead of the required causal `ArtifactNotApproved`; all three controls passed. This is an implementation RED, not runner/bootstrap/format noise.

The minimum causal repair is exact `#429@0f206d6cb23ca88abfd6f0c0a84e1dcba6e35969`. Production changes only `policy.rs::requests_indirect_artifact_source()`: it reuses existing `uv_active_command_index()`, requires active exact `pip` followed by exact `install`, and scans only `arguments[pip_index + 2..]` for the already-reviewed indirect-source selectors. `supported_install_command` remains unchanged, no second uv parser was introduced, and no package-manager/runtime or foreign-owner behavior was copied. On this unchanged repair head, CI `34927770706` is terminal **SUCCESS**. Fuzz run `34927770671` first failed before workflow materialization with `runner_id=0`, no runner identity/group and no executed steps; its same-head attempt 2 is now **QUEUED** at the latest 2026-09-15 KST sweep and still has not produced materialized hosted Fuzz GREEN. Exact retry evidence and unchanged-head acceptance were refreshed to canonical runner owner `.github#712` in comment `5680631431`, superseding the earlier specimen comment `5678309257`. Fresh submitted-review and inline-thread inventories are empty. Keep #429 Draft until the same exact head has a materialized hosted Fuzz terminal GREEN plus then-live review/thread/security evidence; do not churn source merely to redispatch.

Issue #128 remains open because #129 is Draft/unprotected and no immutable Wardnet release exists. Predecessor admission issues remain open until their effective deltas reach protected main or a verified complete successor carries every valid code/test/fixture/contract/traceability/evidence delta.

## Gateway, acquisition and outbound boundaries

Draft #291 remains the Phishing.Database SSRF repair lane: request-controlled feed URLs and the former non-default-host bypass are removed, server-owned source identity is validated, redirects remain disabled, and loopback override is test-only. Wardnet owns the product-specific source decision; reusable outbound authorization remains EgressWeave authority.

Issue #180 / Draft #181 owns route-selection lexical-prefix semantics. Its bounded repair preserves exact/slash-delimited descendant matching, root catch-all and longest-valid-match semantics without changing transport authority. It remains Draft until exact-current gates and governance are terminal-valid.

Draft #173 remains Wardnet's destination-reputation architecture. Wardnet owns maliciousness assessment, evidence lifecycle, organizational admission policy and SOC accountability; EgressWeave remains executable transport authorization. A reputation `allow` can never substitute for transport authorization.

## Runtime Configuration and PostgreSQL production-state stack

The durable-state dependency chain remains ordered through #140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217 -> #219 -> #221 -> #223 -> #224 -> #225 -> #226 -> #228 -> #229 -> #231 -> #233 -> #234 -> #236 -> #241 -> #242 -> #244. Parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence; dependent PRs remain preserved.

Root #140 remains exact `e05df185c50a3792cf487c404c4dac68bc2daf36` on pre-#155 ancestry. Reverse-direction #310 remains the protected-base synthesis lane. `src/credentials.rs` is already reconciled; `src/lib.rs` remains the semantic source conflict. The synthesis must make `run_from_env` consume #140's immutable non-secret `RuntimeConfiguration` while preserving #155 strict `ADMIN_TOKEN` / `ADMIN_TOKENS`, write-capable-principal, pre-bind `require_write_auth_for_bind`, readiness `auth_mode`, loopback-listen, management 401/403, request-body/rate-limit and graceful flush/shutdown invariants. Secrets stay in hardened `CredentialRegistry`; parse helpers stay single-sourced in `runtime_config.rs`.

Do not source-restack #193 or later PostgreSQL dependents until the foundation has one unchanged synthesized exact head with repository-native hostile/authentication/security/review/base evidence. Future database-backed work must not hold explicit database locks or long-lived transactions across LLM calls, external I/O, sandbox execution or long-running computation. Read bounded state, end the transaction, do slow work, then open a bounded write transaction and revalidate the required optimistic/concurrency predicate before commit. Cross-service SQL remains forbidden.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state release gaps include protected integration, exact coverage/rustdoc evidence, backup/WAL retention/storage authority, encryption-key/IAM authority, production-shaped RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and buyer paths

Draft #127 owns browser acceptance for the server-rendered admin console. Loading/normal/permission-denied states, keyboard/focus/accessibility behavior and responsive 375/768/1440 evidence are implementation evidence only while the head is Draft. UI security/performance/readiness copy must remain evidence-backed.

Rust-first owned production hot paths retain the commercial target of 100% rustdoc/test/edge coverage. Realistic asynchronous k6/E2E buyer paths must report p95 <= 20 ms for Wardnet-owned processing with endpoint, concurrency, payload, warmup, sample size and runner class disclosed; external network/service latency is reported separately rather than hidden inside the local-processing claim.

## Release and supply-chain evidence

#77 remains the Rust/reproducibility prerequisite for #164. Draft #164 owns release-evidence/SBOM/provenance foundations only; it is not a release. PR-executable release-evidence jobs may build/test/SBOM/upload development evidence but do not mint protected release authority.

No release is ready until one unchanged protected candidate binds exact source/artifact identity across version, CHANGELOG, immutable tag/release, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence. Wardnet's GitHub Release inventory is empty, so production/release readiness remains false.

## Research and standards grounding

These standards constrain controls and acceptance criteria; they do not substitute for exact-head implementation evidence.

- Levine, J., & Vixie, P. (2010). *DNS Blacklists and Whitelists* (RFC 5782). Internet Engineering Task Force. https://doi.org/10.17487/RFC5782
- National Institute of Standards and Technology. (2020). *Zero Trust Architecture* (NIST SP 800-207). https://doi.org/10.6028/NIST.SP.800-207
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating Risk of Software Vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- National Institute of Standards and Technology. (2024). *Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile* (NIST SP 800-218A). https://doi.org/10.6028/NIST.SP.800-218A
- National Institute of Standards and Technology. (2024). *Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations* (NIST SP 800-161 Rev. 1, Update 1). https://doi.org/10.6028/NIST.SP.800-161r1-upd1
- Boyens, J., McWhite, R., & Calloway, L. (2026). *NIST Cybersecurity Supply Chain Risk Management: Due Diligence Assessment Quick-Start Guide* (NIST SP 1326). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.1326
- OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- World Wide Web Consortium. (2023). *Web Content Accessibility Guidelines (WCAG) 2.2*. https://www.w3.org/TR/WCAG22/
- PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation* — row security, constraints, transaction isolation, connection behavior and continuous archiving/PITR remain authoritative for Wardnet's PostgreSQL acceptance.

Draft or proposed standards remain research inputs unless explicitly accepted; they do not silently replace final release-gate authority. Where redistribution is not permitted, retain citation and stable locator rather than committing a copyrighted PDF.

## Completion / buyer gate

Wardnet is not production-ready until every mandatory product/security gap reaches protected truth and one unchanged immutable protected candidate simultaneously proves fail-closed auth/tenant/security boundaries, released foreign-owner contracts, authoritative durable state/recovery, durable external effects, bounded admission, human approval, deployed WAF/IDS attack behavior, Agent Artifact Admission, lifecycle cleanup, 100% owned-production statement/branch/edge/public-rustdoc evidence, realistic asynchronous buyer-path p95 <= 20 ms where owned, exact security/review/thread/governance gates, immutable supply-chain evidence, deployment/recovery/rollback and OTel/SLO/incident evidence with zero valid unresolved release findings.

Do not declare completion because a document, Draft branch, stacked child, predecessor check, mutable foreign head or readiness endpoint reports success. Guarded bypass remains limited to a proven control-plane chicken-and-egg with unchanged exact head, all runnable deterministic/security/coverage/package/SBOM/provenance gates GREEN, no unresolved findings, candidate-base compatibility, fixed expected head and immediate protection restoration; ordinary failed/queued checks never qualify.
