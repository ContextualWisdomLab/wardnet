# Product and technical gap baseline

Snapshot date: 2026-09-23. This is Wardnet's sole commercial/product-technical current-state ledger; PR #130 is the sole writer for this path. Re-read protected refs, PR/Issue heads/bases/stacks, reviews/threads, exact-head checks, rulesets, security evidence, owner contracts and releases before an integration decision. Draft evidence is provisional; predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle and deterministic security-policy decisions. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime/interpreter/filesystem authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider/tool orchestration. `appguardrail` owns its guardrail implementation. Wardnet does not reproduce those owner semantics.

Foreign capabilities are consumed only through immutable released/versioned contracts, evidence ports or ACLs. Mutable sibling refs remain inventory evidence only: no source copy, cross-service SQL, mutable production dependency, or long-lived transaction spanning a foreign service call. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories both read-only while the Context Fabric writer owns them. Wardnet findings, IOCs, admission verdicts and incidents remain Wardnet truth and may project architecture-relevant lifecycle/risk/remediation only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. Organization ruleset `18156473` remains active/fail-closed with review/thread and required-workflow evidence plus deletion/non-fast-forward protection. Force push, destructive rebase, self/model approval, predecessor-status transfer and routine bypass are prohibited.

Central control-plane defects remain owner work, not Wardnet source work: generic solo-maintainer approval `.github#772` or successor; runner/OpenCode `.github#712/#1234` or successors; delegated exact-head CodeQL settlement `.github#1929` or successor; required-workflow Strix evidence-binder resolution `.github#2292` or successor. Wardnet does not copy central workflows, create wake/no-op commits to manufacture status, synthesize checks, weaken gates or use routine administrator bypass.

Wardnet's GitHub Release inventory remains empty. Protected source truth is therefore not an immutable commercial release. Release-ready protected truth still requires one unchanged candidate binding version/CHANGELOG, immutable tag/release, package/image digest, SBOM, provenance/attestation/signature, reproducibility, deployment promotion, rollback/roll-forward and recovery evidence with all then-live gates terminal-valid.

## Architecture, product and documentation authority

Protected `AGENTS.md`, `CLAUDE.md` and `docs/architecture.md` remain the Rust-first baseline. Draft #111 is the accepted-ADR consolidation lane. Draft #361 is the canonical PRD/TRD/UML lane at `bec3969bce3d340cb0c5da272b3e7257719a7f0f`. Draft #333 is the CodeGraph-guidance lane; this is material because protected `AGENTS.md` still says `.codegraph/` is absent while the repository tree contains `.codegraph/`. Those writers stay separate from this ledger.

The #361 PRD/TRD/UML preserves Wardnet ownership of gateway/SOC control plane, Agent Artifact Admission and security evidence/policy; treats quarantine-sandbox-runtime, EgressWeave, contextual-orchestrator and appguardrail as external canonical owners consumed only by released contract/evidence; keeps Context Fabric writes outside Wardnet; requires Rust-first hot paths, p95 <= 20 ms Wardnet-owned buyer processing, exact-head security/coverage/release evidence, Material UI design/token/Figma/Storybook plus normal/loading/empty/error/permission/responsive/keyboard/a11y and KO/EN/JA/ZH/VI/ES/DE/FR robustness; and separates research rationale from implementation/release proof.

All production LLM use must consume an immutable released `contextual-orchestrator` API. Wardnet owns the security question, evidence supplied to the call, deterministic policy and response treatment; orchestration/provider/tool behavior remains contextual-orchestrator authority. GitHub Actions model workflows remain central exact-SHA reusable-workflow concerns and are not reimplemented locally.

Material UI work is incomplete unless reusable design/tokens/components plus Figma/Storybook evidence exist and buyer-critical flows cover normal/loading/empty/error/permission-denied/responsive/keyboard-accessibility states plus KO/EN/JA/ZH/VI/ES/DE/FR text-layout robustness. Visible mock behavior, decorative controls or unverified security/performance copy are not completion.

## Context Fabric and foreign-owner inventory

Fresh read-only refs: CGC `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13`; EA `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`; `quarantine-sandbox-runtime develop@60a85c7633e03b425b67159ec6822c8178cf87ea`; `EgressWeave main@bd0339bf43cf5041e861bac86a84cb6e7e32637e`; `contextual-orchestrator main@5665b0ad1e07ffb5e9f8c59e44b6b2a785298013`; `appguardrail develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`. Fresh GitHub Release inventories for all six owners remain empty at the current inventory. Mutable owner heads therefore cannot be consumed as Wardnet production contracts. Wardnet writes neither CGC nor EA here.

## Agent Artifact Admission

Issue #128 / Draft #129 remains the canonical package-install admission lane. Root `#129@9efc804006057f099190d8ffcaa7096c955abe0d` preserves deny-by-default structured argv, reviewed workspace-manifest SHA-256, exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding, source/trust/destination/configuration/lifecycle/mutation/dependency/build/platform/cardinality controls, audit-before-allow, bounded remote-instruction provenance, exact submitted-argv identity and parser-phase separation. An `allow` receipt is admission authority only; it is not fetched-byte integrity, runtime configuration, transport authorization, installation, isolation, activation, LLM/tool execution or guardrail evidence.

Repository-owned #129 CI/Fuzz/SAST/Security are terminal SUCCESS on its unchanged exact head; required CodeQL remains a delegated central-settlement failure already handed to `.github#1929`. No Wardnet churn or bypass is justified. Issue lineage remains open until effective deltas reach protected main or a verified complete successor.

## Coraza/CRS enforcement

Issue #434 / Draft #435 is the single Wardnet-owned Coraza enforcement writer. Historical hostile RED/GREEN established header-only request-context evaluation, byte-exact valid UTF-8 vs actual lossy replacement, a loopback-only/no-redirect/no-ambient-proxy sidecar transport, and exact-request correlation binding. Generic outbound transport authorization remains EgressWeave-owned.

Post-repair review found #444: method + URI alone did not bind a clean/disruptive Coraza response to the exact request. Test-only child #445 exact `4c82db44f483aeb9014eba2b4db30bf0c09e0ce9` established hosted semantic RED in CI `35708687049`, rust job `106683725479`. Minimum repair `8400e88d39ac5a13fffa8a0ebafbb9866e2d9b6f` adds a bounded request-unique Wardnet correlation id to the sidecar envelope and requires exact correlation id + method + URI before Coraza evidence is accepted. Correlation is evidence binding, not authentication. Documentation successor `1456845cf40f9e49c017b25ea485238299bf569d` records the same boundary.

Once hosted runners resumed, CI `35728650113` on exact `1456845cf40f9e49c017b25ea485238299bf569d` acquired a runner, passed checkout/toolchain, and failed only `cargo fmt --check`. Rustfmt identified the same correlation-id expression in four Coraza integration fixtures: `tests/coraza_loopback_proxy_boundary.rs`, `tests/coraza_non_disruptive_detection.rs`, `tests/coraza_non_utf8_body.rs`, and `tests/coraza_proven_engine_adapter.rs`. That was a repository-owned source-format defect, not a runner/bootstrap or product-semantics failure.

The minimum non-destructive formatting repair moved #435 to exact `11e7fabfca76e0051fa883905228a0dbe472f4df`, still Draft and mechanically mergeable against protected main. On that unchanged head, repository-owned CI `35751758441`, Fuzz `35751758430`, Security `35751758443` and SAST `35751758520` are terminal SUCCESS; GitHub dynamic code scanning `35751753384`, required OpenCode review `35751755961`, Noema review `35751755933` and merge scheduler `35751755915` are also terminal SUCCESS. Delegated `CodeQL PR` `35751758575` remains queued under central `.github#1929` and does not inherit predecessor evidence.

Required Strix run `35751756065`, job `106864846606`, completed the actual scan with `Vulnerabilities 0 (No exploitable vulnerabilities detected)` and then failed because the central required-workflow runtime tried to resolve `scripts/ci/strix_evidence_binding.py` from Wardnet's trusted target workspace. The exact failure was `ERROR: Strix evidence binder is missing: /home/runner/work/_temp/trusted-workspace/scripts/ci/strix_evidence_binding.py`. This is central workflow/runtime ownership and is handed to `.github#2292` with exact Wardnet reproduction and RED→GREEN acceptance. Wardnet does not copy the binder locally, weaken the required check, blind-rerun the unchanged head or treat the zero-finding scan alone as protected GREEN. There is no submitted independent approval and no protected merge claim.

## Generic gateway HTTP mediation

Issue #440 / Draft #441 owns the generic HTTP-semantics mediation boundary. Hosted predecessor CI `35701602003`, rust job `106660704883`, established semantic RED after existing tests passed: admitted request `Content-Type` was omitted, duplicate `X-Admin-Token` reached upstream, duplicate request `Content-Type` was accepted, oversized `x-wardnet-app-meta` was accepted, and upstream `application/json` was replaced with synthesized `application/octet-stream`.

#441 added `src/gateway_mediation.rs` with a bounded request/response allowlist, management/request singleton rejection, 16,384-byte application-metadata bound, dynamic `Connection` nomination stripping and response allowlisting. At predecessor `7a769e57b5f53d0765b8a33da4bc5a095f09690a` the module remained undeclared and inactive in the live generic proxy path, which still sent only method/target/body and collapsed the upstream response to status/body.

After #435 moved to formatting-only exact `11e7fabfca76e0051fa883905228a0dbe472f4df`, #441 adopted the complete parent without force or destructive rebase through ordinary two-parent merge commit `853f468c46697c39c29bd1342c097f33939c618e`. Its temporary one-shot synthesis helper is anchored to that exact predecessor/new parent and current #441 is exact `4e57283a6e5af521e560856a101f89e631d01284` with base exact #435 `11e7fab...`.

The helper reconstructs complete `853f468...:src/lib.rs`, applies only the bounded mediation wiring, runs `cargo fmt --all`, the focused hostile mediation suite, locked library tests and strict Clippy, and only on GREEN removes itself and fast-forwards the same branch with the causal source repair. Hosted synthesis `35764715408`, job `106871208230`, exposed a helper-local guard defect after checkout/toolchain: the first guard incorrectly required the anchor to be the immediate parent, so a legitimate helper-only toolchain repair commit failed before synthesis. Minimum repair `4e57283a6e5af521e560856a101f89e631d01284` retains immutable anchor/Coraza-parent checks but verifies anchor ancestry plus the complete post-anchor changed-path set. Current synthesis `35777536865`, ordinary CI `35777542713` and Fuzz `35777542798` are queued. The staged helper is not production GREEN, predecessor conclusions do not transfer, and no bypass/rerun churn is justified while exact-head runner acquisition is pending.

Fresh review also found ambiguous response singletons: the policy rejects duplicate `Content-Type` but admits repeated `Location` and `Retry-After`. Test-only child #446 remains exact `01fda91dace6f23fac62507a718a9b9b3f1c1e51`. Its CI `35732508565`, rust job `106761365593`, acquired a hosted `ubuntu-24.04` runner and failed at `cargo fmt --check` before the singleton-response tests executed. The rustfmt delta was confined to four inherited Coraza fixtures already repaired on current #435; #446 still carries those pre-repair files because its intentionally parked base is historical #441 `7a769e57...`. This is parent/base-format evidence, not hosted semantic RED for duplicate `Location`/`Retry-After`, so it does not authorize a production singleton repair. While #441 carries the temporary synthesis helper, #446 remains test-only and is not disposable-restacked merely to inherit that helper. Once #441 settles onto a normal source head, #446 must adopt the complete settled parent non-force and reacquire exact-head CI; production repair remains solely #441 and waits for executed hostile RED.

Minimum GREEN is one live Wardnet-owned mediation boundary that validates request duplicates/bounds before route-upstream contact, forwards only admitted request metadata, reconstructs only admitted upstream response metadata, preserves legitimate multiplicity, fails request-side ambiguity as 400 and upstream-response ambiguity as 502, and preserves the #435 Coraza authority boundary. Response streaming/backpressure remains #442/#443; URL/address/DNS/peer/redirect/proxy/TLS authorization remains EgressWeave.

## Streaming, runtime configuration and durable state

Issue #442 / Draft #443 remains the response-streaming/backpressure lane at test-only exact `eedc56c1e0fefc4654f2e1bdc8b7ceae99a28825`. Hosted CI `35610237483`, rust job `106367237430`, proved three semantic RED cases after formatting and existing library tests passed: Wardnet withheld the first admitted response behind a delayed tail, withheld an admitted prefix behind a hostile large `Content-Length`, and withheld an admitted prefix until a later upstream body failure. Production repair is serialized behind the generic gateway seams and must use bounded async relay/backpressure/cancellation semantics rather than whole-body materialization.

Draft #140 remains the Runtime Configuration root at `99c7c6c798f13c9c37d00d9f586f102585ad3494`; its dependent PostgreSQL/durable-state stack remains preserved rather than collapsed. Repository-owned CI/Fuzz/SAST/Security are terminal SUCCESS on that root; delegated CodeQL remains central owner work. Durable-state release gaps still include protected integration, exact owned-production statement/branch/edge/public-rustdoc coverage, backup/WAL retention/storage authority, encryption-key/IAM authority, production-shaped RPO/RTO/SLO/restore evidence and immutable release identity.

## Buyer path and performance gates

Rust-first owned hot paths retain the target of 100% rustdoc/test/edge coverage. Realistic asynchronous k6/E2E buyer paths must report p95 <= 20 ms for Wardnet-owned processing with endpoint, concurrency, payload, warmup, sample size and runner class disclosed; external network/service latency is reported separately.

Admin-console work is incomplete until normal/loading/empty/error/permission/responsive/keyboard/a11y and eight-locale behavior is exercised against actual interactions. Figma/Storybook/tokens/components are evidence, not substitutes for working acceptance.

## Release and supply-chain evidence

#77 remains a Rust/reproducibility prerequisite for #164. Draft #164 owns release-evidence/SBOM/provenance foundations only; PR-executable jobs do not mint protected release authority. No release is ready until one unchanged protected candidate binds exact source/artifact identity across version, CHANGELOG, immutable tag/release, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

## Research and standards grounding

These sources constrain controls and acceptance; they do not substitute for exact-head evidence.

- Levine, J., & Vixie, P. (2010). *DNS Blacklists and Whitelists* (RFC 5782). Internet Engineering Task Force. https://doi.org/10.17487/RFC5782
- Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP Semantics* (RFC 9110). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9110
- Thomson, M., & Nottingham, M. (2022). *HTTP/1.1* (RFC 9112). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9112
- National Institute of Standards and Technology. (2020). *Zero Trust Architecture* (NIST SP 800-207). https://doi.org/10.6028/NIST.SP.800-207
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- National Institute of Standards and Technology. (2024). *Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile* (NIST SP 800-218A). https://doi.org/10.6028/NIST.SP.800-218A
- National Institute of Standards and Technology. (2024). *Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations* (NIST SP 800-161 Rev. 1, Update 1). https://doi.org/10.6028/NIST.SP.800-161r1-upd1
- Boyens, J., McWhite, R., & Calloway, L. (2026). *NIST Cybersecurity Supply Chain Risk Management: Due Diligence Assessment Quick-Start Guide* (NIST SP 1326). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.1326
- OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
- World Wide Web Consortium. (2023). *Web Content Accessibility Guidelines (WCAG) 2.2*. https://www.w3.org/TR/WCAG22/
- PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation*. Row security, constraints, transaction isolation, connection behavior and continuous archiving/PITR remain authoritative for Wardnet PostgreSQL acceptance.

Draft/proposed standards remain research inputs unless explicitly accepted. Where redistribution is not permitted, retain citation and a stable locator rather than committing copyrighted source material.

## Completion / buyer gate

Wardnet is not production-ready until every mandatory product/security gap reaches protected truth and one unchanged immutable protected candidate simultaneously proves fail-closed auth/tenant/security boundaries, released foreign-owner contracts, authoritative durable state/recovery, durable external effects, bounded admission, human approval, deployed WAF/IDS attack behavior, Agent Artifact Admission, lifecycle cleanup, 100% owned-production statement/branch/edge/public-rustdoc evidence, realistic asynchronous buyer-path p95 <= 20 ms where owned, exact security/review/thread/governance gates, immutable supply-chain evidence, deployment/recovery/rollback and OTel/SLO/incident evidence with zero valid unresolved release findings.

Do not declare completion because a document, Draft branch, stacked child, predecessor check, mutable foreign head or readiness endpoint reports success. Guarded bypass remains limited to a proven control-plane chicken-and-egg with unchanged exact head, all runnable deterministic/security/coverage/package/SBOM/provenance gates GREEN, no unresolved findings, candidate-base compatibility, fixed expected head and immediate protection restoration; ordinary failed or queued checks never qualify.
