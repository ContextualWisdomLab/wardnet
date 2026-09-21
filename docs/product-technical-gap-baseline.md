# Product and technical gap baseline

Snapshot date: 2026-09-21. This is Wardnet's sole commercial/product-technical current-state ledger; PR #130 is the sole writer for this path. Re-read protected refs, PR/Issue heads/bases/stacks, reviews/threads, exact-head checks, rulesets, security evidence, owner contracts and releases before any integration decision. Draft/feature evidence is provisional and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle and security policy decisions. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime/interpreter/filesystem authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider/tool orchestration. `appguardrail` owns its guardrail implementation. Keyverse remains credential/identity backend.

Wardnet consumes foreign capabilities only through released/versioned contracts, evidence ports or ACLs. It does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, execute package managers, or turn reputation/admission evidence into runtime/transport authority. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories both read-only while the Context Fabric writer owns them; Wardnet findings, IOCs, destination assessments, admission verdicts and incidents remain Wardnet truth. Architecture-relevant lifecycle/risk/remediation projects only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. Organization ruleset `18156473` remains active/fail-closed with review/thread and required-workflow evidence plus deletion/non-fast-forward protection. Force pushes, destructive rebases, self/model approval, predecessor-status transfer and routine bypass remain prohibited.

Central control-plane defects remain owner work, not Wardnet source work: generic solo-maintainer approval `.github#772` or successor; runner/OpenCode `.github#712/#1234` or successors; delegated exact-head CodeQL settlement `.github#1929` or successor. Wardnet does not copy central workflows, create no-op/source churn to manufacture status, synthesize status, weaken gates or use routine administrator bypass.

Wardnet's immutable GitHub Release inventory and Git tag refs remain empty. Protected source truth is therefore not an immutable commercial release. Release-ready protected truth still requires one unchanged candidate binding version/CHANGELOG, immutable tag/release, package/image digest, SBOM, provenance/attestation/signature, reproducibility, deployment promotion, rollback/roll-forward and recovery evidence with all then-live gates terminal-valid.

## Architecture, product and documentation authority

Protected `AGENTS.md`, `CLAUDE.md` and `docs/architecture.md` remain the Rust-first ownership baseline. Draft #111 remains the accepted-ADR consolidation lane. Draft #361 remains canonical PRD/TRD/UML at `bec3969bce3d340cb0c5da272b3e7257719a7f0f`, including released-contract-only dependencies, Wardnet-owned asynchronous buyer-path p95 <= 20 ms, release/SBOM/provenance requirements, Material UI evidence requirements and the prohibition on long-lived DB transactions across slow work. Draft #333 remains the sole CodeGraph-guidance lane. Those writers remain separate from this ledger.

Material UI work is incomplete unless reusable design/tokens/components plus Figma/Storybook evidence exist and buyer-critical flows cover normal/loading/empty/error/permission-denied/responsive/keyboard-accessibility states plus KO/EN/JA/ZH/VI/ES/DE/FR text-layout robustness. Visible mock behavior, decorative controls or unverified security/performance copy are not completion.

All production LLM use must consume an immutable released `contextual-orchestrator` API. Wardnet owns the security question, supplied evidence, deterministic policy and response treatment; orchestration/provider/tool behavior remains contextual-orchestrator authority. GitHub Actions model workflows remain central exact-SHA reusable-workflow concerns and are not reimplemented locally.

## Context Fabric and foreign-owner inventory

Fresh read-only default/protected refs remain CGC `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13`, EA `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`, `quarantine-sandbox-runtime develop@60a85c7633e03b425b67159ec6822c8178cf87ea`, `EgressWeave main@bd0339bf43cf5041e861bac86a84cb6e7e32637e`, `contextual-orchestrator main@5665b0ad1e07ffb5e9f8c59e44b6b2a785298013`, and `appguardrail develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`. Their checked immutable GitHub Release inventories remain empty. Mutable foreign refs are inventory evidence only, never Wardnet production contracts. Wardnet writes neither CGC nor EA while their Context Fabric writer owns them.

## Agent Artifact Admission

Issue #128 / Draft #129 remains the canonical package-install admission lane. Current root `#129@9efc804006057f099190d8ffcaa7096c955abe0d` is based on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b` and incorporates serialized child #439 by ordinary expected-head integration. The candidate preserves deny-by-default structured argv; reviewed workspace-manifest SHA-256; exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding; source/trust/destination/configuration/lifecycle/mutation/dependency/build/platform/cardinality controls; audit-before-allow; bounded remote-instruction provenance; exact submitted-argv identity; and parser-phase separation. An `allow` receipt is admission authority only, not fetched-byte integrity, runtime configuration, transport authorization, installation, isolation, activation, LLM/tool execution or guardrail evidence.

Issue #438 / child #439 established hosted semantic RED at test-only exact `ea9c817a8d0edd0e78052d18493a1f1f0954e91f`: `uv --project run pip install ... --managed-python` mistook the global `--project` value token `run` for active `uv run`, losing causal `AlternateInstallRoot` evidence while still failing generically. Minimum causal repair exact `1dfcdcb38b5ef9bc2bee25e48dc63a15e65117a5` removed the duplicate raw token-position heuristic and reused `policy::uv_active_command_index()`. Child exact `#439@f84787e5b6bb4148be417a98957b24e102dd1137` had CI `35460113884` and Fuzz `35460113893` terminal SUCCESS before normal merge into #129.

On unchanged #129 root, CI `35477678285`, Fuzz `35477678328`, SAST `35477678290`, and Security `35477678327` are terminal **SUCCESS**. Required CodeQL `35477678309` is terminal **FAILURE** at the delegated central settlement boundary: exact-head checkout/classification succeeded, current-head verdict read succeeded, the required job failed at `Release runner or enforce current-head CodeQL verdict`, and later dispatch job `106115749380` succeeded. The same-head specimen and RED→GREEN acceptance were handed to canonical owner `.github#1929` in comment `5754488399`. A later dispatch does not retroactively replace the failed required workflow. #129 remains Draft; no source churn/bypass is justified. Issue #438 and predecessor admission issues remain open until effective deltas reach protected main or a verified complete successor.

## Gateway, Coraza and outbound boundaries

Draft #291 remains the Phishing.Database SSRF repair lane: server-owned source identity is validated, request-controlled feed URLs/non-default-host bypass are removed, redirects remain disabled and loopback override is test-only. Wardnet owns this product-specific decision; reusable outbound authorization remains EgressWeave authority.

Issue #434 / Draft #435 owns live Coraza/CRS enforcement. Hosted exact `3c97011161dbb63fb87797fcb61e8c97cc2c64e7` established the original header-only Shellshock RED. Guarded successor run `35509666499`, job `106075258491`, completed SUCCESS on exact `3e910314fcaf1515f2e378a6ab6c71bf0daf219f`, re-proved the request-context boundaries, passed focused suites, locked workspace tests, fmt and strict Clippy, then ordinary non-force promoted reviewed source/tests/docs as `ede52a7a25efc2f98e47b64802484009a43a8532`.

Post-promotion review found a narrower body-identity defect: the v1 JSON envelope must fail closed only when `String::from_utf8_lossy` actually replaces invalid bytes, not merely because valid input contains literal U+FFFD. Test-only exact `c0895b2374f06056efa22f4738bfbbe00052c93d` adds the real gateway regression for valid `a\u{FFFD}b`; dedicated run `35546351519` was cancelled by successor movement and is not claimed as terminal hosted RED. Minimum causal repair exact `e8d3e02875428911bea4a617c02a1170f3e39027` preserves the returned `Cow`: borrowed forwards exact valid UTF-8, including literal U+FFFD; owned proves lossy replacement and fails closed without Coraza authorization. Documentation exact `4443056d938e1851172c59f2041e0def31ecfa3a` records the boundary.

Current #435 exact is `4443056d938e1851172c59f2041e0def31ecfa3a`, still on protected main. CI `35546812838`, Fuzz `35546812816`, SAST `35546812842`, Security `35546812834`, and CodeQL `35546812813` remain **QUEUED**; reviews/threads are empty, which is not independent approval. No predecessor GREEN transfers. #435 remains Draft.

Issue #440 / Draft #441 is the generic HTTP-semantics RED lane. Protected `gateway()` uses inbound headers only for client-IP attribution; `proxy_request()` constructs upstream requests from method/target/body and drops upstream response metadata. Blanket passthrough is prohibited: production mediation must strip management credentials, forwarding/proxy identity, `Host`, framing/hop-by-hop fields and dynamic `Connection` nominations while preserving explicitly admitted end-to-end metadata.

Previous test-only #441 exact `d8fca38bdb57a10d8cfffc69e8b18b2ceef43427` acquired a hosted runner, but CI `35521507793` failed at rust job `106106284520` **Check formatting** before tests or Clippy. That was a fixture-format defect, not semantic RED and not a runner defect. Minimum repair only applied protected-main canonical rustfmt import ordering; production source remains byte-identical. Current exact #441 is `21302112fd4d6fa33e25292cf8775e455ba68b48`; fresh CI `35553329886`, SAST `35553329978`, Security `35553329949`, and CodeQL `35553329963` are **QUEUED**. No semantic RED/GREEN is claimed yet. Issue #440 comment `5754513027` records the repair. Production source remains serialized behind #435/#140 until the unchanged test-only lane reaches the real loopback assertions.

Issue #442 / Draft #443 separately owns response streaming/backpressure. Predecessor test-only exact `6a377f98adb07ad5daba013a955d4e8a107ae929` reached CI `35530968387`, but rust job `106131359715` failed only at `cargo fmt --check`; tests/Clippy did not establish semantic RED. Minimum test-fixture repair applied only the emitted canonical rustfmt layout and left production byte-identical. Current exact is `d5340a83e1bc7fbe374583d9c553909631201a0c`. Fresh CI `35556126682`, SAST `35556126704`, Security `35556126795`, and CodeQL `35556126724` are **QUEUED/PENDING**; no semantic RED/GREEN is claimed. The loopback upstream emits an immediate first chunk while withholding the tail so the test can require downstream response/first admitted chunk before tail release. Remaining hostile contract includes large/missing-or-dishonest `Content-Length`, slow-consumer backpressure, disconnect/cancellation, partial-upstream-failure and concurrent streams. Minimum GREEN must use bounded asynchronous streaming, preserve backpressure/cancellation, compose once with #440 mediation, and leave EgressWeave transport authorization/contextual-orchestrator-specific streaming with their owners.

Issue #180 / Draft #181 owns route-selection lexical-prefix semantics. Draft #173 remains destination-reputation architecture; EgressWeave remains executable transport authority. Draft #136 is preservation-only outbound-consumer evidence until EgressWeave publishes a compatible immutable release. Draft #88 is preservation-only LLM credential-boundary evidence until contextual-orchestrator publishes a compatible immutable release.

## Runtime Configuration and PostgreSQL production-state stack

The durable-state dependency chain remains #140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217 -> #219 -> #221 -> #223 -> #224 -> #225 -> #226 -> #228 -> #229 -> #231 -> #233 -> #234 -> #236 -> #241 -> #242 -> #244. Parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence; dependent PRs stay preserved rather than routinely closed.

Root #140 remains exact `99c7c6c798f13c9c37d00d9f586f102585ad3494`, based on protected main and Draft. Repository-owned CI `35208454126`, Fuzz `35208453837`, SAST `35208453851`, and Security `35208453961` are terminal SUCCESS; CodeQL `35208453935` is terminal FAILURE at canonical central `.github#1929`. That is not Wardnet source/test failure evidence and does not justify source churn or bypass. PostgreSQL/trusted-proxy dependents remain parked pending terminal-valid exact-head settlement and normal governance.

Database-backed work must not hold explicit locks or long-lived transactions across LLM calls, external I/O, sandbox execution or long-running computation. Read bounded state and end the transaction, perform slow work, then open a bounded write transaction and revalidate the optimistic/concurrency predicate. Cross-service SQL remains forbidden.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Durable-state release gaps still include protected integration, exact coverage/rustdoc evidence, backup/WAL retention/storage authority, encryption-key/IAM authority, production-shaped RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and buyer paths

Draft #127 owns browser acceptance for the server-rendered admin console. Loading/normal/empty/error/permission-denied states, keyboard/focus/accessibility behavior and responsive evidence remain implementation evidence only while Draft; full eight-locale robustness plus reusable design/token/Figma/Storybook evidence remain release requirements.

Draft #437 exact `a55ac164fcf3e546f4d7e50c501240519b3e05f6` is a public-package README cleanup serialized behind commercial-authority owner #162 exact `3e3a19a115448d5787ceaa34929018fb832fdd3d`. It changes no runtime authority and remains Draft until #162 reaches protected truth or a verified successor, followed by non-force adoption and fresh exact-head gates.

Rust-first owned hot paths retain the commercial target of 100% rustdoc/test/edge coverage. Realistic asynchronous k6/E2E buyer paths must report p95 <= 20 ms for Wardnet-owned processing with endpoint, concurrency, payload, warmup, sample size and runner class disclosed; external network/service latency is reported separately.

## Release and supply-chain evidence

#77 remains the Rust/reproducibility prerequisite for #164. Draft #164 owns release-evidence/SBOM/provenance foundations only; PR-executable evidence jobs do not mint protected release authority. No release is ready until one unchanged protected candidate binds exact source/artifact identity across version, CHANGELOG, immutable tag/release, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

## Research and standards grounding

These standards constrain controls and acceptance criteria; they do not substitute for exact-head implementation evidence.

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
- PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation*. Row security, constraints, transaction isolation, connection behavior and continuous archiving/PITR remain authoritative for Wardnet's PostgreSQL acceptance.

Draft/proposed standards remain research inputs unless explicitly accepted; they do not silently replace final release-gate authority. Where redistribution is not permitted, retain citation and stable locator rather than committing copyrighted source material.

## Completion / buyer gate

Wardnet is not production-ready until every mandatory product/security gap reaches protected truth and one unchanged immutable protected candidate simultaneously proves fail-closed auth/tenant/security boundaries, released foreign-owner contracts, authoritative durable state/recovery, durable external effects, bounded admission, human approval, deployed WAF/IDS attack behavior, Agent Artifact Admission, lifecycle cleanup, 100% owned-production statement/branch/edge/public-rustdoc evidence, realistic asynchronous buyer-path p95 <= 20 ms where owned, exact security/review/thread/governance gates, immutable supply-chain evidence, deployment/recovery/rollback and OTel/SLO/incident evidence with zero valid unresolved release findings.

Do not declare completion because a document, Draft branch, stacked child, predecessor check, mutable foreign head or readiness endpoint reports success. Guarded bypass remains limited to a proven control-plane chicken-and-egg with unchanged exact head, all runnable deterministic/security/coverage/package/SBOM/provenance gates GREEN, no unresolved findings, candidate-base compatibility, fixed expected head and immediate protection restoration; ordinary failed or queued checks never qualify.