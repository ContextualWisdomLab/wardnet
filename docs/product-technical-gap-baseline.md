# Product and technical gap baseline

Snapshot date: 2026-09-24. This is Wardnet's sole commercial/product-technical current-state ledger; PR #130 is the sole writer for this path. Re-read protected refs, PR/Issue heads/bases/stacks, reviews/threads, exact-head checks, rulesets, security evidence, owner contracts and releases before any integration decision. Draft evidence is provisional; predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle and deterministic security-policy decisions. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime/interpreter/filesystem authority. `EgressWeave` owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider/tool orchestration. `appguardrail` owns its guardrail implementation. Wardnet does not reproduce those owner semantics.

Foreign capabilities are consumed only through immutable released/versioned contracts, evidence ports or ACLs. Mutable sibling refs remain inventory evidence only: no source copy, cross-service SQL, mutable production dependency, or long-lived transaction spanning a foreign service call. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories both read-only while the Context Fabric writer owns them. Wardnet findings, IOCs, admission verdicts and incidents remain Wardnet truth and may project architecture-relevant lifecycle/risk/remediation only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. Organization ruleset `18156473` remains active/fail-closed with one required approving review, review-thread resolution, central required workflows, deletion protection and non-fast-forward protection. The generic solo-maintainer approval defect remains canonical central governance work in `.github#772`; Wardnet does not self/model-approve or treat administrator bypass as an ordinary integration path.

Central control-plane defects remain owner work, not Wardnet source work: generic solo-maintainer approval `.github#772` or successor; runner/OpenCode `.github#712/#1234` or successors; delegated exact-head CodeQL settlement `.github#1929` or successor; required-workflow Strix evidence-binder resolution `.github#2292` or successor. Wardnet does not copy central workflows, manufacture wake/no-op commits, synthesize statuses, weaken gates or use routine administrator bypass.

Wardnet's GitHub Release inventory remains empty. Protected source truth is therefore not an immutable commercial release. Release-ready protected truth still requires one unchanged candidate binding version/CHANGELOG, immutable tag/release, package/image digest, SBOM, provenance/attestation/signature, reproducibility, deployment promotion, rollback/roll-forward and recovery evidence with all then-live gates terminal-valid.

## Architecture, product and documentation authority

Protected `AGENTS.md`, `CLAUDE.md` and `docs/architecture.md` remain the Rust-first baseline. Draft #111 is the accepted-ADR consolidation lane. Draft #361 is the canonical PRD/TRD/UML lane at `bec3969bce3d340cb0c5da272b3e7257719a7f0f`. Draft #333 is the CodeGraph-guidance lane. These writers stay separate from this ledger.

The #361 contract keeps Wardnet ownership of gateway/SOC control plane, Agent Artifact Admission and security evidence/policy; treats quarantine-sandbox-runtime, EgressWeave, contextual-orchestrator and appguardrail as external canonical owners consumed only by released contract/evidence; keeps Context Fabric writes outside Wardnet; requires Rust-first hot paths, p95 <= 20 ms Wardnet-owned buyer processing, exact-head security/coverage/release evidence, Material UI design/token/Figma/Storybook plus normal/loading/empty/error/permission/responsive/keyboard/a11y and KO/EN/JA/ZH/VI/ES/DE/FR robustness; and separates research rationale from implementation/release proof.

All production LLM use must consume an immutable released `contextual-orchestrator` API. Wardnet owns the security question, evidence supplied to the call, deterministic policy and response treatment; orchestration/provider/tool behavior remains contextual-orchestrator authority. GitHub Actions model workflows remain central exact-SHA reusable-workflow concerns and are not reimplemented locally.

## Context Fabric and foreign-owner inventory

Fresh read-only refs remain: CGC `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13`; EA `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`; `quarantine-sandbox-runtime develop@60a85c7633e03b425b67159ec6822c8178cf87ea`; `EgressWeave main@bd0339bf43cf5041e861bac86a84cb6e7e32637e`; `contextual-orchestrator main@5665b0ad1e07ffb5e9f8c59e44b6b2a785298013`; `appguardrail develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`. Fresh GitHub Release inventories for all six owners remain empty. Mutable owner heads therefore cannot be consumed as Wardnet production contracts. Wardnet writes neither CGC nor EA here.

## Agent Artifact Admission

Issue #128 / Draft #129 remains the canonical package-install admission lane at exact `9efc804006057f099190d8ffcaa7096c955abe0d`. It preserves deny-by-default structured argv, reviewed workspace-manifest SHA-256, exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding, source/trust/destination/configuration/lifecycle/mutation/dependency/build/platform/cardinality controls, audit-before-allow, bounded remote-instruction provenance, exact submitted-argv identity and parser-phase separation. An `allow` receipt is admission authority only; it is not fetched-byte integrity, runtime configuration, transport authorization, installation, isolation, activation, LLM/tool execution or guardrail evidence.

Repository-owned #129 CI/Fuzz/SAST/Security are terminal SUCCESS on its unchanged exact head; required CodeQL remains delegated central-settlement owner work already handed to `.github#1929`. Issue lineage remains open until effective deltas reach protected main or a verified complete successor.

## Coraza/CRS enforcement and generic gateway mediation

Issue #434 / Draft #435 remains the single Wardnet-owned Coraza enforcement and generic gateway integration writer. #441 completed the bounded HTTP mediation slice and was normally merged into #435 with fixed expected-head protection; current #435 is exact `534a48b54dcd9e668ceeec8d3d00f824531b0ad1`, mechanically mergeable against protected main. The merge preserves #435's Coraza/OWASP CRS authority plus #441's request/response mediation instead of maintaining two competing writers.

The Coraza lineage still requires explicit disruption authority, independent local-deny precedence, exact-request correlation, byte-exact valid UTF-8 versus actual lossy-byte handling, loopback-only/no-redirect/no-ambient-proxy sidecar transport, monitor-mode degraded `engine_unavailable` evidence, and hostile/benign request-context regressions. The prior exact `11e7fabfca76e0051fa883905228a0dbe472f4df` had repository CI/Fuzz/Security/SAST, dynamic code scanning and OpenCode/Noema/merge-scheduler GREEN; delegated CodeQL settlement and the Strix evidence-binder defect were handed to their canonical central owners. Those predecessor receipts are history only after the #441 integration movement.

The integrated HTTP mediation contract is bounded Wardnet gateway policy: request authority/framing/credential fields and dynamic `Connection` nominations are removed, ambiguous request singleton authority is rejected, bounded application metadata is admitted, response `Content-Type`/`Location`/`Retry-After` ambiguity is rejected while legal multiplicity such as `WWW-Authenticate` and bounded `x-wardnet-app-meta` remains, and ordered list-valued `Content-Encoding` is preserved without enabling automatic decompression. The historical automatic-redirect specimen remains an EgressWeave consumer-contract gap rather than a second Wardnet redirect policy.

#441 is closed/merged; its exact source head `cd3c5985fd6317ab80c888fe1e37786f94d780e8` became #435 merge commit `534a48b54dcd9e668ceeec8d3d00f824531b0ad1`. Current #435 repository-owned Fuzz and SAST are terminal SUCCESS. One CI run attached to the same source commit is the intentionally hostile #450 stack-adoption merge context and fails only #443's streaming REDs, not #435's own PR merge context; #435's own current CI run is terminal SUCCESS. Security and CodeQL remain queued. No predecessor GREEN is promoted across the #441 integration movement.

## Streaming, runtime configuration and durable state

Issue #442 / Draft #443 remains the response-streaming/backpressure lane. It has now non-force adopted current #435 instead of waiting behind a separate #441 writer. Current exact #443 is `c47b35c36eed9aad1c0968c82aa14b1c40cf352b`, based on #435 `534a48b54dcd9e668ceeec8d3d00f824531b0ad1`; its effective parent-relative delta remains exactly four hostile test files. This establishes one serialized generic-gateway source lineage without duplicating Coraza or header-mediation authority.

Historical exact CI `35921459298` on test-only predecessor `2cccfb37b85c3fc30d4b91d3027266feaf338774` passed checkout/toolchain/formatting, all 142 existing library unit tests and pre-existing integration suites before establishing the additional slow-consumer and concurrent-stream semantic REDs: an unpolled buyer body allowed all `1024 x 64 KiB` chunks (64 MiB) to drain within the 250 ms witness window, and four held upstreams kept every buyer response head/prefix behind unreleased tails. Together with the earlier delayed-tail, dishonest-`Content-Length`, partial-upstream-failure, explicit over-budget and cancellation witnesses, the executed lineage proves whole-response materialization defeats bounded downstream backpressure, cancellation propagation and concurrent stream observability.

Fresh source review on the adopted parent identifies the causal production path: the generic proxy awaits `response.bytes()` before constructing the downstream response. The minimum Wardnet repair is one bounded asynchronous relay that preserves the already-admitted status/header map, exposes the upstream byte stream directly to the downstream body, preserves natural backpressure/cancellation and surfaces late upstream body failure as a downstream body error. It must not introduce an unbounded intermediary, automatic request replay, elapsed-time success inference, or EgressWeave transport semantics. The existing truncated-body unit acceptance must move from pre-response `BAD_GATEWAY` expectation to admitted response head plus body-read error.

Current #443 exact-head CI `35985182231` is terminal semantic RED on that expected defect after the ancestry restack; Fuzz `35985182228` and SAST `35985182196` are terminal SUCCESS, while Security `35985182193` and CodeQL PR `35985182368` remain queued. The minimum causal production repair has been dispatched on the existing #443 branch at this exact head; #443 stays Draft and no predecessor receipt becomes GREEN evidence after the resulting source movement.

Draft #140 remains the Runtime Configuration root at `99c7c6c798f13c9c37d00d9f586f102585ad3494`; its dependent PostgreSQL/durable-state stack remains preserved rather than collapsed. Repository-owned CI/Fuzz/SAST/Security are terminal SUCCESS on that root; delegated CodeQL remains central owner work. Durable-state release gaps still include protected integration, exact owned-production statement/branch/edge/public-rustdoc evidence, backup/WAL retention/storage authority, encryption-key/IAM authority, production-shaped RPO/RTO/SLO/restore evidence and immutable release identity.

## Buyer path, UI and release gates

Rust-first owned hot paths retain the target of 100% rustdoc/test/edge coverage. Realistic asynchronous k6/E2E buyer paths must report p95 <= 20 ms for Wardnet-owned processing with endpoint, concurrency, payload, warmup, sample size and runner class disclosed; external network/service latency is reported separately.

Material UI work is incomplete unless reusable design/tokens/components plus Figma/Storybook evidence exist and buyer-critical flows cover normal/loading/empty/error/permission-denied/responsive/keyboard-accessibility states plus KO/EN/JA/ZH/VI/ES/DE/FR text-layout robustness. Visible mock behavior, decorative controls or unverified security/performance copy are not completion.

The local Scorecard supply-chain evidence lane is independently code-current work, not release authority. Protected `main` still pins `github/codeql-action/upload-sarif` v4.37.7 in the local Scorecard workflow. Draft #174 exact `077fd4679093d57e6b7f18cc3a00353734cfffc3` advances only that uploader to immutable upstream v4.38.2 commit `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` while retaining the supported non-PR Scorecard event contract and explicit `security-events: write`; CI/Security/SAST/CodeQL on that exact head are freshly queued, so no predecessor result is promoted. Dependabot #451's v4.38.1 proposal is version-superseded by #174 but remains open until #174 is a verified complete successor; no routine close is authorized.

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
