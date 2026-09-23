# Product and technical gap baseline

Snapshot date: 2026-09-24. This is Wardnet's sole commercial/product-technical current-state ledger; PR #130 is the sole writer for this path. Re-read protected refs, PR/Issue heads/bases/stacks, reviews/threads, exact-head checks, rulesets, security evidence, owner contracts and releases before an integration decision. Draft evidence is provisional; predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle and deterministic security-policy decisions. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime/interpreter/filesystem authority. `EgressWeave` owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider/tool orchestration. `appguardrail` owns its guardrail implementation. Wardnet does not reproduce those owner semantics.

Foreign capabilities are consumed only through immutable released/versioned contracts, evidence ports or ACLs. Mutable sibling refs remain inventory evidence only: no source copy, cross-service SQL, mutable production dependency, or long-lived transaction spanning a foreign service call. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories both read-only while the Context Fabric writer owns them. Wardnet findings, IOCs, admission verdicts and incidents remain Wardnet truth and may project architecture-relevant lifecycle/risk/remediation only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. Organization ruleset `18156473` remains active/fail-closed with one required approving review, required review-thread resolution, central required workflows, deletion protection and non-fast-forward protection. The generic solo-maintainer approval defect remains canonical central governance work in `.github#772`; Wardnet does not self/model-approve or treat administrator bypass as an ordinary integration path.

Central control-plane defects remain owner work, not Wardnet source work: generic solo-maintainer approval `.github#772` or successor; runner/OpenCode `.github#712/#1234` or successors; delegated exact-head CodeQL settlement `.github#1929` or successor; required-workflow Strix evidence-binder resolution `.github#2292` or successor. Wardnet does not copy central workflows, create wake/no-op commits to manufacture status, synthesize checks, weaken gates or use routine administrator bypass.

Wardnet's GitHub Release inventory remains empty. Protected source truth is therefore not an immutable commercial release. Release-ready protected truth still requires one unchanged candidate binding version/CHANGELOG, immutable tag/release, package/image digest, SBOM, provenance/attestation/signature, reproducibility, deployment promotion, rollback/roll-forward and recovery evidence with all then-live gates terminal-valid.

## Architecture, product and documentation authority

Protected `AGENTS.md`, `CLAUDE.md` and `docs/architecture.md` remain the Rust-first baseline. Draft #111 is the accepted-ADR consolidation lane. Draft #361 is the canonical PRD/TRD/UML lane at `bec3969bce3d340cb0c5da272b3e7257719a7f0f`. Draft #333 is the CodeGraph-guidance lane; protected `AGENTS.md` still contains historical guidance that `.codegraph/` is absent, so that separate writer remains material. These writers stay separate from this ledger.

The #361 PRD/TRD/UML preserves Wardnet ownership of gateway/SOC control plane, Agent Artifact Admission and security evidence/policy; treats quarantine-sandbox-runtime, EgressWeave, contextual-orchestrator and appguardrail as external canonical owners consumed only by released contract/evidence; keeps Context Fabric writes outside Wardnet; requires Rust-first hot paths, p95 <= 20 ms Wardnet-owned buyer processing, exact-head security/coverage/release evidence, Material UI design/token/Figma/Storybook plus normal/loading/empty/error/permission/responsive/keyboard/a11y and KO/EN/JA/ZH/VI/ES/DE/FR robustness; and separates research rationale from implementation/release proof.

All production LLM use must consume an immutable released `contextual-orchestrator` API. Wardnet owns the security question, evidence supplied to the call, deterministic policy and response treatment; orchestration/provider/tool behavior remains contextual-orchestrator authority. GitHub Actions model workflows remain central exact-SHA reusable-workflow concerns and are not reimplemented locally.

Material UI work is incomplete unless reusable design/tokens/components plus Figma/Storybook evidence exist and buyer-critical flows cover normal/loading/empty/error/permission-denied/responsive/keyboard-accessibility states plus KO/EN/JA/ZH/VI/ES/DE/FR text-layout robustness. Visible mock behavior, decorative controls or unverified security/performance copy are not completion.

## Context Fabric and foreign-owner inventory

Fresh read-only refs remain: CGC `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13`; EA `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`; `quarantine-sandbox-runtime develop@60a85c7633e03b425b67159ec6822c8178cf87ea`; `EgressWeave main@bd0339bf43cf5041e861bac86a84cb6e7e32637e`; `contextual-orchestrator main@5665b0ad1e07ffb5e9f8c59e44b6b2a785298013`; `appguardrail develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`. Fresh GitHub Release inventories for all six owners remain empty. Mutable owner heads therefore cannot be consumed as Wardnet production contracts. Wardnet writes neither CGC nor EA here.

## Agent Artifact Admission

Issue #128 / Draft #129 remains the canonical package-install admission lane at exact `9efc804006057f099190d8ffcaa7096c955abe0d`. It preserves deny-by-default structured argv, reviewed workspace-manifest SHA-256, exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding, source/trust/destination/configuration/lifecycle/mutation/dependency/build/platform/cardinality controls, audit-before-allow, bounded remote-instruction provenance, exact submitted-argv identity and parser-phase separation. An `allow` receipt is admission authority only; it is not fetched-byte integrity, runtime configuration, transport authorization, installation, isolation, activation, LLM/tool execution or guardrail evidence.

Repository-owned #129 CI/Fuzz/SAST/Security are terminal SUCCESS on its unchanged exact head; required CodeQL remains delegated central-settlement owner work already handed to `.github#1929`. No Wardnet churn or bypass is justified. Issue lineage remains open until effective deltas reach protected main or a verified complete successor.

## Coraza/CRS enforcement

Issue #434 / Draft #435 is the single Wardnet-owned Coraza enforcement writer at exact `11e7fabfca76e0051fa883905228a0dbe472f4df`, mechanically mergeable against protected main. Historical hostile RED/GREEN established header-only request-context evaluation, byte-exact valid UTF-8 vs actual lossy replacement, loopback-only/no-redirect/no-ambient-proxy sidecar transport, and exact-request correlation binding. Generic outbound transport authorization remains EgressWeave-owned.

On this unchanged exact head, repository-owned CI `35751758441`, Fuzz `35751758430`, Security `35751758443` and SAST `35751758520` are terminal SUCCESS; GitHub dynamic code scanning `35751753384`, required OpenCode review `35751755961`, Noema review `35751755933` and merge scheduler `35751755915` are also terminal SUCCESS. Delegated CodeQL run `35751758575` failed in central current-generation settlement ordering after its own analysis path; the exact Wardnet specimen remains handed to `.github#1929` rather than repaired in leaf source. Required Strix `35751756065` completed its actual scan with zero exploitable vulnerabilities and then failed because the central runtime resolved `scripts/ci/strix_evidence_binding.py` from Wardnet's target workspace; that owner defect remains `.github#2292`. Neither central defect authorizes source churn, copied workflows/binders, predecessor evidence transfer or bypass.

## Generic gateway HTTP mediation

Issue #440 / Draft #441 is the sole production writer for generic HTTP header mediation. Hosted predecessor `4b938342ec1bc7f8dd2a1001cfcdf6a0136ccbca` produced a valid semantic RED in CI `35846750623`, rust job `107134631266`, after 146 existing library tests passed. The real loopback buyer fixture then failed exactly five intended cases: admitted request `Content-Type` was omitted; duplicate `X-Admin-Token` reached the routed upstream; duplicate request `Content-Type` was accepted; aggregate `x-wardnet-app-meta` beyond 16,384 bytes was accepted; and admitted upstream `application/json` was replaced with synthesized `application/octet-stream`. Request stripping and dynamic `Connection` response stripping already passed. Fuzz `35846750936` was terminal SUCCESS.

One-shot synthesis `35846743748`, job `107134608983`, generated normal causal successor `3ec25d1bb440b163cd3f1ae2ef92ae5b1167caed`, wiring `src/gateway_mediation.rs` into the real generic path, then removed the temporary helper. The implemented boundary admits only bounded application metadata, rejects duplicate management/request singleton authority before upstream contact, strips fixed and dynamic hop-by-hop/authority fields, reconstructs responses from an explicit allowlist, maps request mediation failures to 400 and invalid admitted upstream envelopes to 502, and does not absorb EgressWeave transport authorization or #443 streaming/backpressure ownership.

A later exact candidate `68fc8ed6e6b9644d3406f0bf0c31113e7c1b76e0` reached terminal repository CI `35864827991` SUCCESS and Fuzz `35864828031` SUCCESS. Fresh standards review then found a distinct response-singleton ambiguity: repeated upstream `Location` and `Retry-After` were admitted even though each field grammar carries one value.

Test-only child #446 predecessor `a6869e8b2fb1e3c6b9eb6e7d893950693297e864` established a valid real buyer-path duplicate-`Retry-After` RED. Its duplicate-`Location` witness used `302 Found`, so the historical 404 observation is classified as confounded by automatic redirect following rather than valid evidence that Wardnet relayed duplicate Location. The minimum Wardnet-owned production repair remains only in #441, which rejects duplicate `Content-Type`, `Location`, and `Retry-After` while preserving intentional multiplicity for `WWW-Authenticate` and bounded `x-wardnet-app-meta`.

Current #441 exact head is `29a35163fc5bab860f247a68a6b1d5f797d73182`, still based on exact #435 `11e7fabfca76e0051fa883905228a0dbe472f4df`. Exact CI `35893229211` and Fuzz `35893229215` are terminal SUCCESS; rust job `107290605213` completed formatting, locked workspace tests and strict Clippy successfully. This parent evidence remains valid only while that exact source head is unchanged.

Test-only response-singleton child #446 non-force adopted the complete current #441 repair through an ordinary two-parent merge. Hosted predecessor CI `35893328787`, rust job `107290948038`, passed formatting, all 151 library tests, the existing seven-case gateway mediation suite and the repaired duplicate-`Retry-After` buyer case; its duplicate-`Location` case then returned 404 because reqwest followed the fixture's 302 before `admit_response_headers()` could inspect the original field set. Exact child `b8b5804b655a424967252d8ac22172eb4a1338fb` therefore changes only that fixture to protocol-valid `201 Created` with duplicate Location, remains based exactly on #441 `29a35163fc5bab860f247a68a6b1d5f797d73182`, and has current CI `35918347719` queued. Only unchanged current-child GREEN can authorize normal integration into #441.

The automatic-redirect specimen is a separate foreign-owner integration gap: EgressWeave owns executable destination/DNS/peer/redirect/proxy/TLS/resource authorization. Exact Wardnet consumer evidence and RED/GREEN acceptance were handed to existing canonical EgressWeave Rust-consumer issue #237. EgressWeave's fresh Release inventory remains empty, so Wardnet cannot yet replace this gap with an immutable released owner contract and must not copy owner redirect/DNS/TLS policy locally.

Issue #447 / test-only child #448 track the separate representation-integrity gap: legal ordered `Content-Encoding` metadata must remain coupled to byte-identical coded bytes while hop-by-hop/framing/authority/credential fields remain excluded. CI `35893375073` on predecessor exact `44c03a0fe83b7199ebad43cff0e009646f7554f1` acquired a hosted runner but stopped at `cargo fmt --check` before Test because rustfmt 1.98.1 required only fixture-array reflow. Exact child `8a254028faf4db0485ba8710945c2781a876fbed` applies only that formatter repair, remains based exactly on #441, changes only `tests/gateway_content_encoding.rs`, and has current CI `35917178809` queued. Semantic Content-Encoding RED remains unestablished and no production repair is authorized yet.

#441 remains the sole production mediation writer. Minimum GREEN is one Wardnet-owned boundary that validates request duplicates/bounds before routed-upstream contact, forwards only admitted request metadata, reconstructs only admitted upstream response metadata, rejects ambiguous response singletons, preserves legitimate multiplicity and end-to-end representation metadata, fails request-side ambiguity as 400 and invalid upstream-response ambiguity as 502, and preserves the #435 Coraza authority boundary. Outbound redirect/destination authority must arrive through an immutable EgressWeave consumer contract.

## Streaming, runtime configuration and durable state

Issue #442 / Draft #443 remains the response-streaming/backpressure lane. Predecessor `eedc56c1e0fefc4654f2e1bdc8b7ceae99a28825` hosted CI `35610237483`, rust job `106367237430`, proved three semantic RED cases after formatting and existing library tests passed: Wardnet withheld the first admitted response behind a delayed tail, withheld an admitted prefix behind a hostile large `Content-Length`, and withheld an admitted prefix until a later upstream body failure. That predecessor evidence validates the causal finding but does not transfer as current-head promotion evidence.

Predecessor `239c747848a8241cbbccd66e6f91d20725860c51` added only slow-consumer and concurrent held-stream hostile fixtures. Hosted CI `35880184584`, rust job `107246315069`, acquired a real Ubuntu runner and stopped only at `cargo fmt --check` before Test; SAST `35880184578` was terminal SUCCESS. Current test-only exact `2cccfb37b85c3fc30d4b91d3027266feaf338774` applies only the rustfmt-prescribed fixture reflows. Fresh CI `35921459298`, Security `35921459231`, SAST `35921459251`, and CodeQL PR `35921459105` are queued/pending, so the new slow-consumer/concurrency cases have not yet established current-head semantic RED.

The #443 branch represents missing-`Content-Length`, dishonest-large-`Content-Length`, partial-failure, explicit over-budget real-body, downstream-cancellation, slow-consumer bounded read-ahead, and concurrent held-stream acceptance without changing production source. Production repair remains serialized behind #435/#441/#140 and must non-force compose with the single header-mediation boundary while preserving route/local-deny/Coraza/audit semantics. No EgressWeave/contextual-orchestrator/quarantine/appguardrail owner logic is copied.

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
