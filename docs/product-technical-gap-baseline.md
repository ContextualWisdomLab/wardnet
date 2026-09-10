# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. The branch is protected and repository-local `rust` remains a required status context. Fresh Wardnet GitHub Release inventory is empty, so protected source truth is not yet an immutable release identity.

Organization ruleset `18156473` remains active on the default branch. Its generic `required_approving_review_count=1` remains structurally incompatible with the declared solo-maintainer model while no eligible independent reviewer/team exists; `.github#772` is the canonical governance repair path. Self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates are not to be weakened and routine administrator bypass is not an acceptance path.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication/wake ordering remains `.github#1929` or its live successor. Wardnet does not add leaf provider/model/group fallbacks, duplicate central workflows, synthesize statuses, or source-churn a clean candidate to repair those planes.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed PR #130's own current SHA as merge evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both release inventories remain empty. Their mutable heads, open proposals and Draft contracts are compatibility evidence only; Wardnet does not write either repository while the Context Fabric owner is active. The still-misaligned default/protected `develop` metadata versus the intended protected `main` integration topology remains canonical `.github#1137` owner work.

Package-manager argv, Wardnet-local reason codes, findings and verdicts remain Wardnet-local security truth. Architecture-relevant lifecycle/ownership/risk/remediation changes may be projected through released compatible Context Graph contracts, not by copying Wardnet verdicts into authoritative EA truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `341a3e05a614654536431eda8e553585b2533886`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. It was produced by ordinary expected-head merge of #283 into predecessor `1f904898cd6280bc796bb81822171a2d6fb3073a`; no force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

### Integrated #280/#281: direct pip keyring-provider authority

Pinned pip parser/authentication behavior established that explicit direct-pip `import|subprocess` keyring-provider selection expands credential-provider authority beyond the reviewed `--no-input` baseline. Hosted semantic RED preceded the focused `pypi_keyring_provider_authority` repair. Exact child `25b499bca0d234889db9102e9db92a865bd66690` passed CI `34531637458` and Fuzz `34531637306`; #281 then merged ordinarily into #129. Issue #280 remains open until protected-main adoption.

### Integrated #282/#283: noninteractive direct pip authority

Test-only `124e1eb2cce935d83d302b265633a6d6c62482cf` established hosted semantic RED in CI `34536050936`: an otherwise reviewed direct pip install without canonical `--no-input` remained admissible. The minimum repair added focused `pypi_noninteractive_authority.rs` plus admission wiring using existing `missing_safety_flag`; subsequent failures were stale positive fixtures and were repaired without widening the rule to uv.

Final exact child `f3fe5262af0e9ffc0fad7808f6ea3ed978ad0da6` passed CI `34540381857` and Fuzz `34540381844`, with fresh review/thread inventories empty, then merged ordinarily into #129. Issue #282 remains open until protected-main adoption.

### Active #284/#287: uv subprocess keyring authority

Fresh exact review found the existing direct-pip keyring classifier did not govern admitted `uv pip install`. Current Astral documentation states uv keyring authentication is disabled by default, supports the `subprocess` provider, and delegates credential lookup to the PATH-resolved `keyring` command when selected. An attached `--keyring-provider=subprocess` therefore adds credential-helper authority without changing the reviewed artifact coordinate, manifest digest, registry or artifact hash.

Initial #287 exact `85b7b55648f29dc45a38dd01134583610fb0952f` was test-only and production-source-identical to #129. Parent exact CI `34542090175` is SUCCESS. Child CI `34542208606` later acquired hosted runner `1001872102`, passed checkout/toolchain/format and failed in `Test`; because the only child delta was the new hostile admission contract, this is semantic RED. Fuzz `34542208653` is SUCCESS. The earlier pre-allocation wait was updated on `.github#712` comment `5626859678` as resolved for that specimen rather than misreported as a continuing runner failure.

Minimum causal repair `9ce55e3f999932a041610bb7e67e47f406a4e9a6` extends the existing PyPI credential-provider classifier to `uv pip install`: direct pip/pip3 retains pinned abbreviation plus `import|subprocess` semantics; uv matches only the exact `--keyring-provider` option and treats only `subprocess` as authority-expanding. `fca4c79151c1ae88cf36414e97d63ffd6ac4d0ca` adds attached/separate subprocess reason coverage plus explicit attached `disabled` preservation. `485436224034b47f31f2f08f70b3b6903b648ac1` adds code-current doctoring with Astral primary documentation, NIST SP 800-218A, NIST SP 800-53 Rev. 5 Release 5.2.0 and CWE-15 traceability.

Current exact #287 is `485436224034b47f31f2f08f70b3b6903b648ac1`, Draft and mechanically mergeable into exact #129. Exact-current CI `34543336683` and Fuzz `34543336627` are runnerless queued with `runner_id=0` at this snapshot; predecessor GREEN does not transfer. The current recurring allocation state is recorded on the same `.github#712` handoff comment rather than by retrying/cancelling the sole current-head evidence. No Ready/merge claim is allowed until exact-current formatting/locked tests/Clippy/Fuzz and then-live security/review/thread evidence settle.

### Serialized follow-on gaps

Issue #285 remains issue-only behind #287 for uv platform certificate-store trust expansion. Current Astral TLS documentation states uv defaults to bundled Mozilla roots and `--system-certs` selects the platform native certificate store through `rustls-platform-verifier`; Wardnet must classify only parser-supported argv trust-source selection while EgressWeave remains executable TLS/transport authority and quarantine remains effective runtime/environment authority.

Issue #286 remains issue-only behind #285 for uv reinstall mutation authority. Current Astral reference documents `--reinstall` / `--force-reinstall` and `--reinstall-package` as environment-mutation selectors. The eventual Wardnet RED must prove those parser-supported selectors fail closed for the existing install-mutation authority reason without relying on accidental positional-token rejection; effective environment mutation remains quarantine-owned.

### Exact-current #129 gates

All predecessor #129 conclusions became historical when #283 merged. On exact current `341a3e05a614654536431eda8e553585b2533886`, CI `34542090175` and Fuzz `34542090160` are terminal SUCCESS. Security Scan `34542090158`, SAST Semgrep `34542090131`, and CodeQL PR `34542090178` remain queued/non-passing. No predecessor-result transfer, synthetic status or no-op source churn is acceptable.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. The evidence line remains ordered through business authorization, freshness, source/evidence health, exact generation membership, lifecycle validity, producer-version/tombstone cursor, atomic source replacement and ABA replay resistance. Durable production authority remains the PostgreSQL #80/#192 lineage because bounded current-only lifecycle memory cannot prove historical opaque generation uniqueness.

Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns a destination/reputation verdict into transport authority.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 advanced non-destructively from proven 375 px semantic RED `2ca5a8e55185730abec34886279b5aa576be5658` to exact current `83c4babc0e1bd9b428be7dc3afc5779ca68abdbd`. The single intervening repair changes only `src/lib.rs`: outer `header.app` wraps, generated tables gain a bounded horizontal overflow container, and the acceptance viewport/document itself is not widened or masked.

Exact-current hosted CI `34542012228` is terminal SUCCESS. Rust job `103086520275` acquired hosted runner `1001871978` and completed checkout/toolchain/format, the full Test step including the shipped Chrome/ChromeDriver route contract, and Clippy. Fuzz `34542012166`, Security Scan `34542012272`, and SAST Semgrep `34542012155` are also terminal SUCCESS. The browser contract covers loading/normal/permission-denied states, keyboard skip-link transfer, computed accessible admin-token name/description, atomic KPI live-region semantics and unchanged 375/768/1440 px clipping/overflow boundaries. Fresh inline review threads are resolved; submitted reviews are advisory/COMMENTED only.

UI Delivery Gate is **PASS for the material UI/product contract** on exact `83c4babc...`. The PR remains not merge-ready while CodeQL PR `34542012159` is still queued/non-passing and governance/coverage/package/SBOM/provenance requirements remain unresolved. No predecessor evidence or local browser result substitutes for those current protected-gate requirements.

## Process lifecycle and graceful shutdown

Draft #245 remains exact `d953c1d94ebbde87a0f7c4121a8088e0b9fa14f2`. Its test-first Unix signal lineage established semantic SIGINT RED; the minimum production repair registers SIGTERM/SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`, without creating a second lifecycle authority. Exact CI `34423929129`, Fuzz `34423929826`, Security `34423929246` and SAST `34423929010` are SUCCESS. CodeQL `34423928919` fails only at the central delegated terminal-verdict boundary tracked by `.github#1929`; Draft GREEN is not protected lifecycle truth.

## Release evidence foundation

Draft #164 remains stacked on Rust-toolchain prerequisite #77, exact head `42a673defb756d959cf754a8140227fbebfdd0f1`. It builds deterministic source/binary release evidence and keeps OIDC-backed attestation authority protected-main/manual-dispatch only. Its exact CI `34425717320`, rust job `102710399756`, is terminal SUCCESS on hosted runner `1001843210` through checkout, pinned toolchain, formatting, locked tests and strict Clippy; fresh reviews and inline threads are empty. The latest doctoring corrects SLSA v1.2 Approved Specification status and SPDX stable/RC status without claiming SLSA conformance merely because attestations exist.

This foundation is not itself a release. It remains Draft behind exact #77, and Wardnet release inventory remains empty.

## Release and operational buyer gaps

Wardnet is **not release-ready**. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep exact #129 `341a3e05a614654536431eda8e553585b2533886` as canonical Agent Artifact Admission parent until #287 is exact-current GREEN. Do not transfer predecessor evidence or churn source while runnerless current jobs are merely queued. Once #287 CI/Fuzz and review/thread evidence are terminal-valid, integrate it ordinarily into #129 with expected-head protection, reacquire #129's full gate set on the new exact head, and only then start #285 source work; #286 follows #285.

Let #127's hosted 375/768/1440 product contract and exact CI/Fuzz/Security/SAST GREEN stand without source churn while delegated CodeQL settles. Continue runner/materialization, delegated CodeQL and solo-maintainer governance repairs through `.github#712`, `.github#1929` and `.github#772`; branch-topology repair remains `.github#1137`. Continue the PostgreSQL/recovery/coverage stack dependency-first. Only after protected prerequisites and all then-live gates are terminal-valid should Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.