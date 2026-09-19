# Product and technical gap baseline

Snapshot date: 2026-09-20. Re-read live protected refs, PR/Issue heads and bases, stacks, reviews, review threads, exact-head checks, rulesets, security evidence, foreign-owner contracts and releases before any merge, release, restack or handoff. Draft/feature heads are provisional evidence; predecessor GREEN never transfers after a head or base moves.

This file is Wardnet's sole commercial/product-technical current-state ledger. PR #130 is the sole writer for this path. It records current truth and active gaps, not a substitute changelog for every historical repair.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, destination-reputation assessment, Wardnet security-evidence lifecycle, security policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution, isolation, cleanup and effective runtime/interpreter/filesystem authority. EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization. `contextual-orchestrator` owns Agent/LLM/provider/tool orchestration. `appguardrail` owns its application/agent guardrail implementation. Keyverse remains credential/identity backend.

Wardnet consumes foreign capabilities only through released/versioned ports, evidence contracts or ACLs. It does not copy sibling source, query foreign application tables, pin mutable sibling heads as production dependencies, execute package managers, or turn a reputation/admission decision into runtime or transport authority. Protected forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization; neither authority may override the other's deny.

`context-graph-contracts` (CGC) is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` (EA) is the architecture Decision Plane. Wardnet inventories both read-only while the Context Fabric writer owns them. Wardnet findings, IOCs, destination assessments, admission verdicts and incidents remain Wardnet truth. Architecture-relevant lifecycle, ownership, risk and remediation may be projected only through released compatible CGC contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`, merged through #155. Organization ruleset `18156473` remains active and fail-closed: review/thread evidence and central required-workflow evidence are required, deletion and non-fast-forward updates are protected, and administrator capability is not ordinary integration authority. Force pushes, destructive rebases, self/model approval, predecessor-status transfer and routine bypass remain prohibited.

Generic solo-maintainer approval remains central `.github#772` or a verified successor. Hosted-runner/materialization/OpenCode defects remain `.github#712` / `.github#1234` or verified successors. Delegated current-head CodeQL terminal settlement remains `.github#1929` or a verified successor. These are actionable owner defects, not reasons to copy central workflows into Wardnet, manufacture source churn, synthesize status, self/model approve, weaken gates or routinely use administrator bypass.

Wardnet's immutable GitHub Release inventory and Git tag refs remain empty at the latest inventory. Protected source truth is therefore not yet an immutable commercial release. A release-ready candidate still requires one protected exact head that binds aligned version/CHANGELOG, immutable tag, package/image digest, SBOM, provenance/attestation, reproducibility, deployment promotion, rollback/roll-forward and recovery evidence with every then-live gate terminal-valid.

## Architecture, product and documentation authority

Protected `AGENTS.md`, `CLAUDE.md` and `docs/architecture.md` preserve Wardnet's Rust-first baseline. Draft #111 remains the accepted-ADR consolidation lane and is provisional until protected integration. Draft #361 remains the canonical PRD/TRD/UML lane at exact `bec3969bce3d340cb0c5da272b3e7257719a7f0f`; it records released-contract-only dependencies, realistic asynchronous Wardnet-owned buyer-path p95 <= 20 ms, release/SBOM/provenance requirements, mandatory Material UI Figma/Storybook/state/locale evidence, and the no-long-lived-database-transaction-across-slow-work rule. Draft #333 remains the sole CodeGraph-guidance repair. Those writers remain separate from this ledger.

Material UI work is incomplete unless reusable design/tokens/components plus Figma/Storybook evidence exist and buyer-critical flows cover normal, loading, empty, error, permission-denied, responsive, keyboard/accessibility states and KO/EN/JA/ZH/VI/ES/DE/FR text-layout robustness. Visible mock behavior or decorative controls are not completion.

All production LLM use must consume an immutable released `contextual-orchestrator` API. Wardnet owns the security question, supplied evidence, deterministic policy and response treatment; orchestration/model/provider/tool behavior remains contextual-orchestrator authority. GitHub Actions model workflows remain central exact-SHA reusable-workflow concerns and are not reimplemented locally.

## Context Fabric and foreign-owner release inventory

Fresh read-only inventory keeps CGC protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and EA protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Wardnet writes neither repository while the Context Fabric writer owns them and does not bind production behavior to those mutable default branches.

Foreign-owner protected/default refs inventory as `quarantine-sandbox-runtime develop@60a85c7633e03b425b67159ec6822c8178cf87ea`, `EgressWeave main@bd0339bf43cf5041e861bac86a84cb6e7e32637e`, `contextual-orchestrator main@5665b0ad1e07ffb5e9f8c59e44b6b2a785298013`, and `appguardrail develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`. The checked immutable GitHub Release inventories remain empty. Mutable protected refs are inventory evidence only, never Wardnet production contracts.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact root is `#129@fdd3e3dbd73a2838ffdabad41134a9c156cddca6` on protected `main@f8260f1e03836039ff9463dd99fa982e4e270c4b`. That candidate preserves deny-by-default structured-argv admission; reviewed workspace-manifest SHA-256; exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 binding; package-manager source, trust, destination, configuration, lifecycle, mutation, dependency/build/platform/cardinality controls; audit-before-allow; bounded remote-instruction provenance; exact submitted-argv identity; and parser-phase separation between package-manager-owned authority and delegated child argv. An `allow` receipt is admission authority only, not proof of retrieved-byte integrity, runtime configuration, transport authorization, installation, isolation, activation, LLM/tool execution or guardrail execution.

On exact root `fdd3e3dbd73a2838ffdabad41134a9c156cddca6`, repository-owned CI/Fuzz/SAST/Security evidence is terminal GREEN; delegated CodeQL terminal settlement remains central `.github#1929` ownership rather than Wardnet source/test/SARIF failure evidence.

Issue #438 / serialized child #439 is the only active Agent Artifact Admission child and remains based on exact `#129@fdd3e3dbd73a2838ffdabad41134a9c156cddca6`. Test-only exact `ea9c817a8d0edd0e78052d18493a1f1f0954e91f` established the hosted semantic RED: in `uv --project run pip install ... --managed-python`, the value token `run` consumed by global `--project` was mistaken for the active `uv run` command, so the request retained generic `ForbiddenCommand` but lost causal `AlternateInstallRoot` provider evidence. Minimum causal repair exact `1dfcdcb38b5ef9bc2bee25e48dc63a15e65117a5` removed the duplicate raw `run`/`pip` position heuristic and reused the parser-aware `policy::uv_active_command_index()` boundary. Subsequent commits through current exact child `#439@f84787e5b6bb4148be417a98957b24e102dd1137` only finish rustfmt's canonical formatting for the regression fixture. CI `35460113884` (rust job `105942336470`, latest inventory `runner_id=0`, no assigned runner/group and `steps=[]`) and Fuzz `35460113893` remain queued on that unchanged exact head; no GREEN/integration is claimed. The current exact-head runner-acquisition specimen is handed to canonical central owner `.github#712`; no no-op churn, local runner/workflow copy or gate weakening is warranted.

Issue #438 and predecessor admission issues remain open until their effective deltas reach protected `main` or a verified complete successor carries every still-valid code/test/fixture/contract/traceability/evidence delta.

## Gateway, Coraza and outbound boundaries

Draft #291 remains the Phishing.Database SSRF repair lane: request-controlled feed URLs and the former non-default-host bypass are removed, server-owned source identity is validated, redirects remain disabled, and loopback override is test-only. Wardnet owns the product-specific source decision; reusable outbound authorization remains EgressWeave authority.

Issue #434 / Draft #435 owns the live Coraza/CRS header-enforcement repair. Hosted exact `3c97011161dbb63fb87797fcb61e8c97cc2c64e7` established the original header-only Shellshock RED: a malicious `User-Agent` crossed a real block route while path/query/body stayed benign and Wardnet returned `200 OK` / `monitored` because protected-main local scoring did not inspect request headers.

The reviewed repair must preserve three authority boundaries. First, correlated CRS messages with `is_interrupted=false` are detection evidence, not disruption authority; enforced block requires explicit Coraza disruption. Second, attacker-controlled raw `X-Forwarded-For` / `X-Real-IP` must not cross the sidecar boundary in place of Wardnet's normalized transport-derived client identity. Third, a partial/truncated/unrepresentable allowlisted-header envelope must fail closed before sidecar authorization rather than make a clean verdict authoritative for a request Coraza did not inspect in full.

Current #435 is exact `ccc99a1caf9ae2ab95f38405a6a29bc344a13c07` on protected main, still Draft and mechanically mergeable. Production source is not promoted on this head. Predecessor one-shot run `35436569780` is terminal **FAILURE**, but before the harness failure its hosted job successfully reproduced all three semantic REDs: non-disruptive Coraza evidence promoted to block authority, raw XFF/X-Real-IP sidecar forwarding, and an oversized allowlisted-header envelope silently truncated while still eligible for clean authorization. It then stopped only at a formatter-sensitive repair-harness seam (`expected exactly one partial Coraza header-envelope seam`). That failure invalidates the harness, not the findings, and is not production GREEN.

Exact `308318691364b2462409fccd1cee2cc32b57c5f9` adds a formatter-robust marker/slice-based successor harness. Current exact `ccc99a1...` adds its one-shot successor workflow, guarded by exact parent/diff and expected remote head. Successor run `35448051223`, job `105910313524`, remains **QUEUED** on unchanged `ccc99a1...` with no execution steps at the latest fresh read. This current-head scheduling specimen is handed to canonical central owner `.github#712` in comment `5742559566`. The successor must receive a real runner, re-prove all three REDs, apply only the minimum reviewed fixes, pass focused tests, `cargo test --locked --workspace`, strict workspace/all-target Clippy, format/diff checks, verify the remote expected head, and only then push the production candidate while deleting the temporary repair workflows/helpers. No source churn, synthetic status, predecessor promotion or routine bypass substitutes for that execution.

Issue #180 / Draft #181 owns route-selection lexical-prefix semantics. Draft #173 remains Wardnet's destination-reputation architecture; EgressWeave remains executable transport authorization. Draft #136 remains preservation-only outbound consumer evidence until EgressWeave publishes a compatible immutable release. Draft #88 likewise remains preservation-only evidence for the LLM credential boundary; provider-routing authority must not enter protected Wardnet and a released contextual-orchestrator contract is required for production integration.

## Runtime Configuration and PostgreSQL production-state stack

The durable-state dependency chain remains ordered through #140 -> #193 -> #194 -> #196 -> #198 -> #199 -> #200 -> #207 -> #208 -> #209 -> #212 -> #216 -> #217 -> #219 -> #221 -> #223 -> #224 -> #225 -> #226 -> #228 -> #229 -> #231 -> #233 -> #234 -> #236 -> #241 -> #242 -> #244. Parent/protected-base movement requires ordinary non-force adoption and fresh exact-head evidence; dependent PRs remain preserved rather than routinely closed.

Current root #140 is exact `99c7c6c798f13c9c37d00d9f586f102585ad3494`, based on protected main, mechanically mergeable and still Draft. Repository-owned CI/Fuzz/SAST/Security evidence is terminal GREEN; delegated CodeQL terminal settlement remains central `.github#1929` ownership. PostgreSQL and trusted-proxy dependents remain parked until the unchanged root can reacquire terminal-valid CodeQL settlement and normal protected-branch governance.

Future database-backed work must not hold explicit database locks or long-lived transactions across LLM calls, external I/O, sandbox execution or long-running computation. Read bounded state, end the transaction, perform slow work, then open a bounded write transaction and revalidate the required optimistic/concurrency predicate before commit. Cross-service SQL remains forbidden.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state release gaps include protected integration, exact coverage/rustdoc evidence, backup/WAL retention/storage authority, encryption-key/IAM authority, production-shaped RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console and buyer paths

Draft #127 owns browser acceptance for the server-rendered admin console. Loading/normal/empty/error/permission-denied states, keyboard/focus/accessibility behavior and responsive evidence remain implementation evidence only while the head is Draft. UI security/performance/readiness copy must remain evidence-backed.

Draft #437 current exact `a55ac164fcf3e546f4d7e50c501240519b3e05f6` is a public-package README cleanup serialized behind commercial-authority owner #162 exact `3e3a19a115448d5787ceaa34929018fb832fdd3d`. Its exact-current CI `35450750866`, CodeQL `35450750872`, Security `35450750890` and SAST `35450750939` are queued and are not passing evidence. It changes no runtime authority and must remain Draft until #162 reaches protected truth or a verified successor, then adopt that protected result non-force and reacquire exact-head gates.

Rust-first owned production hot paths retain the commercial target of 100% rustdoc/test/edge coverage. Realistic asynchronous k6/E2E buyer paths must report p95 <= 20 ms for Wardnet-owned processing with endpoint, concurrency, payload, warmup, sample size and runner class disclosed; external network/service latency is reported separately rather than hidden inside the local-processing claim.

## Release and supply-chain evidence

#77 remains the Rust/reproducibility prerequisite for #164. Draft #164 owns release-evidence/SBOM/provenance foundations only; it is not a release. PR-executable release-evidence jobs may build/test/SBOM/upload development evidence but do not mint protected release authority.

No release is ready until one unchanged protected candidate binds exact source/artifact identity across version, CHANGELOG, immutable tag/release, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence. Wardnet's GitHub Release inventory and Git tag refs are empty, so production/release readiness remains false.

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
- PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation*. Row security, constraints, transaction isolation, connection behavior and continuous archiving/PITR remain authoritative for Wardnet's PostgreSQL acceptance.

Draft or proposed standards remain research inputs unless explicitly accepted; they do not silently replace final release-gate authority. Where redistribution is not permitted, retain citation and stable locator rather than committing a copyrighted PDF.

## Completion / buyer gate

Wardnet is not production-ready until every mandatory product/security gap reaches protected truth and one unchanged immutable protected candidate simultaneously proves fail-closed auth/tenant/security boundaries, released foreign-owner contracts, authoritative durable state/recovery, durable external effects, bounded admission, human approval, deployed WAF/IDS attack behavior, Agent Artifact Admission, lifecycle cleanup, 100% owned-production statement/branch/edge/public-rustdoc evidence, realistic asynchronous buyer-path p95 <= 20 ms where owned, exact security/review/thread/governance gates, immutable supply-chain evidence, deployment/recovery/rollback and OTel/SLO/incident evidence with zero valid unresolved release findings.

Do not declare completion because a document, Draft branch, stacked child, predecessor check, mutable foreign head or readiness endpoint reports success. Guarded bypass remains limited to a proven control-plane chicken-and-egg with unchanged exact head, all runnable deterministic/security/coverage/package/SBOM/provenance gates GREEN, no unresolved findings, candidate-base compatibility, fixed expected head and immediate protection restoration; ordinary failed or queued checks never qualify.