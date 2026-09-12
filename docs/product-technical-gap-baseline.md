# Product and technical gap baseline

Snapshot date: 2026-09-12. Re-read live refs, PRs, review threads, exact-head checks, rulesets, security evidence, owner contracts and releases before merge, release, restack or handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Draft/feature heads are provisional evidence; predecessor GREEN never transfers after a head or base moves.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle, security policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution, isolation, cleanup and effective runtime/interpreter/filesystem authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider orchestration. `appguardrail` owns static package/security analysis. Keyverse remains credential/identity backend.

Wardnet consumes foreign capabilities only through released/versioned ports or ACLs. It does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, execute package managers, or turn a reputation/admission decision into runtime or transport authority. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories them read-only while their Context Fabric writer is active. Wardnet findings, IOCs, destination assessments, admission verdicts and incidents remain Wardnet truth. Architecture-relevant lifecycle, ownership, risk and remediation may be projected only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. That protected change makes management writes fail closed when a public bind has no write-capable administrator credential. It is protected source truth, not an immutable release: Wardnet's current GitHub Release inventory is empty.

Live organization ruleset `18156473` requires one approving review plus resolved review threads and organization-required workflows; deletion and non-fast-forward updates remain prohibited. Self-approval and model/bot-as-human approval are forbidden. `.github#772` owns the generic solo-maintainer approval defect. Runner/materialization/OpenCode defects remain `.github#712` / `.github#1234` or verified successors. Delegated current-head CodeQL terminal settlement remains `.github#1929`. Wardnet does not copy those central workflows, pin mutable repair heads, manufacture source churn solely to redispatch, synthesize status, or use routine administrator bypass for ordinary failed/queued checks.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed #130's own current SHA as product evidence. Each new ledger commit invalidates predecessor #130 workflow/review receipts and must reacquire exact-head evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps CGC protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and EA protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both GitHub Release inventories are empty. Mutable owner proposals are compatibility evidence only, not Wardnet production authority. Wardnet writes neither repository while the Context Fabric writer owns them.

## Commercial authority separation

Draft #162 owns the naming/authority repair separating the 2B KRW customer-contract readiness predicate from the standing USD 20 billion product-quality ambition. Exact #162 remains `3e3a19a115448d5787ceaa34929018fb832fdd3d` on current protected main. Protected #155 authentication/security truth is inherited rather than copied. Keep this lane Draft until then-live required gates and governance are satisfiable; neither commercial target authorizes weakened security or release evidence.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 is `e618f37dcff24b8dae4416eacac9a2456a8f8a93` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, produced by ordinary expected-head/non-force integration of serialized hostile RED→GREEN children through #360. No force update, destructive rebase, self/model approval, gate weakening, mutable foreign dependency or routine bypass was used.

The candidate preserves deny-by-default structured-argv admission; reviewed workspace-manifest SHA-256; exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding; package-manager source, trust, destination, configuration, lifecycle, mutation, dependency/build/platform/cardinality controls; audit-before-allow; and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not proof of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

The newest causal lineage #355 → #356 → #357 → #358 → #359 → #360 partitions direct-pip Python-interpreter authority by parser phase. Pinned pip `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5` exposes General Option `--python` before command selection, while `pip install` additionally exposes `--python-version`; consequently an abbreviation can be uniquely interpreter authority pre-command but ambiguous post-command. The repair keeps broad verified abbreviation handling only in the pre-command General Option normalizer, canonicalizes that reviewed selector only in Wardnet's internal policy copy to exact `--python=VALUE`, accepts exact `--python` / `--python=...` only after `install`, stops at the `--` option terminator, and preserves the public `command_sha256` from exact submitted argv. Wardnet still does not execute pip, discover/launch interpreters, resolve packages, inspect/mutate runtime state or filesystem, or perform DNS/TLS/network I/O.

#360's hostile path reached the semantic admission assertion after checkout/toolchain/format; formatter/bootstrap noise was not accepted as RED. Minimum repair exact `e01f2860e2700b7f817c461afb44558c2036d69c` passed CI `34680208950` and Fuzz `34680208983`, with zero valid unresolved review threads, before ordinary expected-head merge produced current #129 `e618f37dcff24b8dae4416eacac9a2456a8f8a93`.

Fresh root evidence on unchanged exact #129 `e618f37dcff24b8dae4416eacac9a2456a8f8a93`:

- CI `34680577824` — **SUCCESS**;
- Fuzz `34680577806` — **SUCCESS**;
- Security Scan `34680577838` — **SUCCESS**;
- SAST Semgrep `34680577841` — **SUCCESS**;
- Devin Review and CodeRabbit commit statuses — **SUCCESS**;
- current valid unresolved inline review threads — **0**;
- required CodeQL PR `34680577821` — **FAILURE at delegated terminal settlement**.

CodeQL detect job `103518360694` checked out the exact head and succeeded. Compatibility job `103518381883` successfully read the current-head dispatch verdict and then failed `Release runner or enforce current-head CodeQL verdict`. Downstream dispatch job `103518645286` subsequently succeeded on the same unchanged head, but a later dispatch cannot retroactively satisfy the already-failed required workflow. Fresh consumer evidence plus RED→GREEN acceptance is handed to central `.github#1929` in comment `5644494204`. This is not a Wardnet source/test RED and is not a guarded-bypass case.

Earlier registry/trust, proxy, certificate, dependency-group, install-root, mutation, output/cache/system-package, OCI, npm-family and uv controls remain inherited. Their predecessor/child receipts are historical after root movement and do not transfer to the current root. Open predecessor findings remain open until their effective deltas reach protected main or a verified complete successor preserves every valid code/test/fixture/contract/traceability/evidence delta.

Issue #128 is refreshed to this exact root and remains open because #129 is Draft/unprotected and no immutable Wardnet release exists.

## Phishing.Database SSRF repair

Protected-baseline companion #295 established causal RED: an authenticated request-selected Phishing.Database loopback URL could be fetched through the former non-default-host bypass. Draft #291 removes request-controlled feed URLs and the non-default-host bypass, resolves feed URLs server-side, keeps loopback override under `cfg(test)` only, validates the server-owned source host and preserves a no-redirect client. Wardnet owns the product-specific source decision; reusable outbound authorization remains EgressWeave authority. The repair remains unprotected and must retain exact-head repository/security/governance evidence before integration.

## Gateway route-boundary repair

Issue #180 / Draft #181 owns Wardnet route-selection lexical-prefix semantics only. Causal RED proved `/api` captured lexical siblings and `/api/admin` captured `/api/administrator`; the minimum repair keeps exact/slash-delimited descendant matching, root catch-all and longest-valid-match semantics without changing transport authorization. Exact #181 remains `abbaff14a452671238c83c1325da22e15f9ee2ac` on current protected main. Repository/security lanes are GREEN while required CodeQL remains centrally unsettled. Keep Draft; an ordinary required-gate RED is not an emergency-bypass case.

## Outbound destination reputation

Draft #173 remains the Wardnet-owned reputation architecture. Wardnet owns destination maliciousness assessment, evidence lifecycle, organizational admission policy and SOC accountability; EgressWeave remains executable transport authorization. Production composition requires an immutable compatible released EgressWeave authorization/evidence contract. Wardnet never turns a reputation `allow` into transport authority and does not consume mutable EgressWeave source/PR heads. EA projection may use released CGC provenance only.

## Runtime Configuration and PostgreSQL production-state stack

The durable-state dependency chain remains ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence; dependent PRs remain preserved.

Root #140 has advanced concurrently to exact `e05df185c50a3792cf487c404c4dac68bc2daf36` while retaining pre-#155 ancestry. Reverse-direction #310 remains the protected-base synthesis lane. `src/credentials.rs` is already causally reconciled; the remaining semantic source conflict is `src/lib.rs`. The final synthesis must make `run_from_env` consume #140's immutable non-secret `RuntimeConfiguration` while retaining every #155 strict `ADMIN_TOKEN` / `ADMIN_TOKENS`, write-capable-principal, pre-bind `require_write_auth_for_bind`, readiness `auth_mode`, loopback-listen, management 401/403, request-body/rate-limit and graceful flush/shutdown invariant. Secrets stay in hardened `CredentialRegistry`; parse helpers stay single-sourced in `runtime_config.rs`.

The former architecture-text drift is repaired on exact #140 `e05df185c50a3792cf487c404c4dac68bc2daf36`: `docs/architecture.md` now describes the actual `CredentialRegistry` plus write-capable, header-presentable administrator contract, accepts `ADMIN_TOKEN`, a write-capable `ADMIN_TOKENS` principal or `WAF_IDS_CREDENTIALS_PATH` as bootstrap authority, and explicitly states that TLS/identity controls or read-only principals do not satisfy the public-bind write-auth prerequisite. This documentation repair does not resolve the remaining `src/lib.rs` source synthesis.

Fresh review of the architecture-fitness gate found the former substring detector could miss function-item aliases and falsely classify comments/literals. `6b314dd3b0541328726ffacb097fec1c6054efdb` replaces that gate with token-structured Rust syntax analysis over imports/aliases/calls while ignoring comments and normal/raw string bodies. `c039776bb15a3af936cd93720c60c27f777dd4aa` then repairs a hostile lifetime-apostrophe edge that could hide executable tokens and adds a lifetime-bearing environment-read regression. Exact `e05df185c50a3792cf487c404c4dac68bc2daf36` adds only the architecture-authority repair above. These are #140-owned fitness/documentation repairs, not a new configuration authority.

Central current-head workflows have materialized on exact #140 `e05df185c50a3792cf487c404c4dac68bc2daf36`; coverage-source-tree, coverage-evidence and OpenCode review are successful at the latest read, while Strix remains in progress. The repository-native Rust suite has not yet provided an exact-current source-head receipt, so exact-current source GREEN is **not claimed**. The valid architecture-fitness and public-bind/write-auth review threads remain unresolved pending #310 synthesis plus exact-head repository execution. Historical #140 Noema/CodeQL/repository receipts do not transfer.

First child #193 remains exact `7a93322c9a824e6e939a8143b1f20eccaeac856d` against historical #140 base `93a51f9706cf8a9704f69aed4a69df5be16c84e4`; its former CI/Fuzz GREEN is now historical child evidence. Do not source-restack #193 or later PostgreSQL dependents while #140/#310 is still moving. After the foundation has one unchanged synthesized exact head with repository-native hostile/authentication/security/review/base evidence, adopt it non-force and reacquire every dependent gate.

The PostgreSQL lineage already carries Draft evidence for fail-closed authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least privilege, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary production raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness, ambiguous-COMMIT fail-closed handling, physical recovery drills, divergent-writer serialization and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state release gaps include foundation-first protected integration, exact coverage/rustdoc evidence, backup/WAL retention/storage authority, encryption-key/IAM authority, production-shaped RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and lifecycle buyer paths

Draft #127 owns server-rendered admin-console browser acceptance: loading/normal/permission-denied states, keyboard/focus/accessibility behavior and responsive 375/768/1440 evidence. Its Delivery Gate remains **PARTIAL** while required central evidence is non-passing; UI evidence on a Draft head is not release authority.

Draft #245 owns test-first Unix SIGINT graceful shutdown. Draft #134 owns support-bundle count and secret-redaction regression. Their repository/security lanes are implementation evidence only until exact-current protected-base/governance/release gates are satisfied.

Material UI work must continue to preserve reusable design/token/Storybook/Figma evidence where applicable plus normal/loading/empty/error/permission/responsive/a11y E2E and KO/EN/JA/ZH/VI/ES/DE/FR robustness; visible behavior without functioning interactions or resilient states is not completion.

## Rust reproducibility and release evidence

#77 is the Rust/reproducibility prerequisite for #164. Draft #164 owns release-evidence/SBOM/provenance foundations only; it is not a release. PR-executable release-evidence jobs may build/test/SBOM/upload development evidence but do not mint protected release authority.

A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence. Wardnet's GitHub Release inventory remains empty, so production/release readiness is false.

## Documentation and architecture drift

Protected `AGENTS.md` still contains stale CodeGraph guidance despite `.codegraph/` existing on protected main. Draft #333 is the sole bounded repair lane and already carries hostile evidence; do not create a competing docs writer or duplicate the fix elsewhere.

`CLAUDE.md`, architecture/security/ops/test/release docs, PRD/TRD-equivalent product/technical specifications and ADRs are evidence-bearing architecture inputs, not substitutes for executable acceptance. Any material source or ownership change must update the relevant documents and diagrams without copying foreign-owner logic.

## Research and standards grounding

These standards constrain controls and acceptance criteria; they do not substitute for exact-head implementation evidence.

- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating Risk of Software Vulnerabilities* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- National Institute of Standards and Technology. (2024). *Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile* (NIST SP 800-218A). https://doi.org/10.6028/NIST.SP.800-218A
- Boyens, J., McWhite, R., & Calloway, L. (2026). *NIST Cybersecurity Supply Chain Risk Management: Due Diligence Assessment Quick-Start Guide* (NIST SP 1326). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.1326
- National Institute of Standards and Technology. (2024). *Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations* (NIST SP 800-161 Rev. 1, Update 1). https://doi.org/10.6028/NIST.SP.800-161r1-upd1
- OWASP Foundation. (2025). *Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform Resource Identifier (URI): Generic Syntax* (RFC 3986), §3.3.
- PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation* — row security, constraints, transaction isolation, connection behavior and continuous archiving/PITR remain authoritative for Wardnet's PostgreSQL acceptance.

Draft or proposed standards are recorded as research inputs only unless explicitly accepted; they do not silently replace final release-gate authority.

## Completion / buyer gate

Wardnet is not production-ready until every mandatory product/security gap reaches protected truth and one unchanged immutable protected candidate simultaneously proves fail-closed auth/tenant/security boundaries, released foreign-owner contracts, authoritative PostgreSQL state/recovery, durable external effects, bounded admission, human approval, deployed WAF/IDS attack behavior, Agent Artifact Admission, lifecycle cleanup, 100% owned-production statement/branch/edge/public-rustdoc evidence, realistic asynchronous buyer-path p95 ≤20 ms where owned, exact security/review/thread/governance gates, immutable supply-chain evidence, deployment/recovery/rollback and OTel/SLO/incident evidence with zero valid unresolved release findings.

Do not declare completion because a document, Draft branch, stacked child, predecessor check, mutable foreign head or readiness endpoint reports success. Guarded bypass remains limited to a proven control-plane chicken-and-egg with unchanged exact head, all runnable deterministic/security/coverage/package/SBOM/provenance gates GREEN, no unresolved findings, candidate-base compatibility, fixed expected head and immediate protection restoration; ordinary failed/queued checks never qualify.