# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. The branch is protected and repository-local `rust` remains a required status context. Fresh Wardnet GitHub Release inventory is empty, so protected source truth is not yet an immutable release identity.

Organization ruleset `18156473` remains active on the default branch. Its generic `required_approving_review_count=1` remains structurally incompatible with the declared solo-maintainer model while no eligible independent reviewer/team exists; `.github#772` is the canonical governance repair path. Self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates are not to be weakened and routine administrator bypass is not an acceptance path.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication/wake ordering remains `.github#1929` or its live successor. Current Wardnet consumer evidence was refreshed on `.github#1929` after an unchanged #129 CodeQL run reached the compatibility-verdict enforcement failure while checkout/detection and later dispatch succeeded. Fresh central inventory also shows canonical repair PR `.github#2040@6706c231ab06a3c91c43fdb5b989cfcd79fff593` diverged from protected `.github/main@cb0872c9a20d5584703dffacca65c096fc034c6c`; the owner acceptance is non-force adoption of the intervening protected delta followed by exact-head reacquisition, not Wardnet source churn or copied workflow logic.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed PR #130's own current SHA as merge evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both fresh release inventories are empty. Their mutable heads, open proposals and Draft contracts are compatibility evidence only; Wardnet does not write either repository while the Context Fabric owner is active. The still-misaligned default/protected `develop` metadata versus the intended protected `main` integration topology remains canonical `.github#1137` owner work.

Package-manager argv, Wardnet-local reason codes, findings and verdicts remain Wardnet-local security truth. Architecture-relevant lifecycle/ownership/risk/remediation changes may be projected through released compatible Context Graph contracts, not by copying Wardnet verdicts into authoritative EA truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `341a3e05a614654536431eda8e553585b2533886`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. It was produced by ordinary expected-head merge of #283 into predecessor `1f904898cd6280bc796bb81822171a2d6fb3073a`; no force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

### Integrated #280/#281: direct pip keyring-provider authority

Pinned pip parser/authentication behavior established that explicit direct-pip `import|subprocess` keyring-provider selection expands credential-provider authority beyond the reviewed `--no-input` baseline. Hosted semantic RED preceded the focused `pypi_keyring_provider_authority` repair. Exact child `25b499bca0d234889db9102e9db92a865bd66690` passed CI `34531637458` and Fuzz `34531637306`; #281 then merged ordinarily into #129. Issue #280 remains open until protected-main adoption.

### Integrated #282/#283: noninteractive direct pip authority

Test-only `124e1eb2cce935d83d302b265633a6d6c62482cf` established hosted semantic RED in CI `34536050936`: an otherwise reviewed direct pip install without canonical `--no-input` remained admissible. The minimum repair added focused `pypi_noninteractive_authority.rs` plus admission wiring using existing `missing_safety_flag`; subsequent failures were stale positive fixtures and were repaired without widening the rule to uv.

Final exact child `f3fe5262af0e9ffc0fad7808f6ea3ed978ad0da6` passed CI `34540381857` and Fuzz `34540381844`, with fresh review/thread inventories empty, then merged ordinarily into #129. Issue #282 remains open until protected-main adoption.

### Active #284/#287: uv keyring-provider authority

Fresh exact review found the existing direct-pip keyring classifier did not govern admitted `uv pip install`. Current Astral documentation states uv keyring authentication is disabled by default, currently supports only the `subprocess` provider, and delegates credential lookup to the PATH-resolved `keyring` command when selected. Caller-selected non-disabled provider authority therefore expands credential/trust authority without changing the reviewed artifact coordinate, manifest digest, registry or artifact hash.

Initial #287 exact `85b7b55648f29dc45a38dd01134583610fb0952f` was test-only and production-source-identical to #129. Parent exact CI `34542090175` is SUCCESS. Child CI `34542208606` acquired hosted compute, passed checkout/toolchain/format and failed in `Test` because attached `--keyring-provider=subprocess` remained `Allow`; Fuzz `34542208653` is SUCCESS. This is semantic RED for the currently documented active provider.

Minimum repair `9ce55e3f999932a041610bb7e67e47f406a4e9a6` extended the existing PyPI credential-provider classifier to exact uv `--keyring-provider` while preserving direct pip/pip3 pinned abbreviation plus `import|subprocess` semantics. `fca4c79151c1ae88cf36414e97d63ffd6ac4d0ca` added attached/separate subprocess reason coverage and explicit `disabled` preservation.

Fresh review then found a forward-compatibility fail-open: Wardnet does not bind the installed uv binary/version, so a later client could add another active non-disabled provider while the first repair continued to block only literal `subprocess`. Test-only `7121333b2f37eb6a721e730c9c91a1f29dff63c1` added an unknown non-disabled provider regression while retaining exact `disabled` as the explicit no-provider baseline. Formatter-only successors preserved policy semantics until exact `7f7582fa06db5108de6e22aa33eb9e9470fec815` reached hosted CI `34547136579`, rust job `103102105097`, runner `1001873718`. Formatting succeeded and the locked workspace Test step executed. Every preceding suite shown in the job log passed, including the direct-pip keyring contract and the other three uv keyring tests; only `unknown_non_disabled_uv_keyring_provider_fails_closed` failed with `left: Allow`, `right: Block`. This is the required semantic RED for client-capability evolution.

Minimum causal repair `3e8725c87e61e8a667573704b6478f76c503af1e` changes only the existing classifier predicate: direct pip/pip3 remains semantically unchanged and still blocks its known `import|subprocess` providers; exact uv `--keyring-provider` now treats every explicit value except exact `disabled` as authority-expanding. It adds no uv parser emulation, PATH lookup, credential access, ambient `UV_KEYRING_PROVIDER` inference, transport behavior or second bounded context. Proposed doctoring `0a558835ff20ae88a9d7b023cc9882ec10bfa5fc` records both hosted REDs, alternatives/rejections, owner boundaries and traceability.

Current exact #287 is `0a558835ff20ae88a9d7b023cc9882ec10bfa5fc`, Draft and mechanically mergeable into exact #129. Exact-current CI `34547769453`, rust job `103103986975`, is queued with `runner_id=0`, no steps and label `ubuntu-24.04`; Fuzz `34547769489` is also queued. This current allocation state and GREEN acceptance are recorded on canonical `.github#712` comment `5627526046`; all earlier allocation specimens are historical after head movement. No retry flood, runner-label workaround or no-op source churn is justified. Exact-head GREEN is not claimed until hosted formatting, locked workspace tests, strict Clippy, Fuzz and then-live review/thread/security evidence settle.

### Serialized follow-on gaps

Issue #285 remains issue-only behind #287 for uv platform certificate-store trust expansion. Current Astral TLS documentation states uv defaults to bundled Mozilla roots and `--system-certs` selects the platform native certificate store through `rustls-platform-verifier`; Wardnet must classify only parser-supported argv trust-source selection while EgressWeave remains executable TLS/transport authority and quarantine remains effective runtime/environment authority.

Issue #286 remains issue-only behind #285 for uv reinstall mutation authority. Current Astral reference documents `--reinstall` / `--force-reinstall` and `--reinstall-package` as environment-mutation selectors. The eventual Wardnet RED must prove those parser-supported selectors fail closed for the existing install-mutation authority reason without relying on accidental positional-token rejection; effective environment mutation remains quarantine-owned.

Issue #288 remains issue-only behind #286 for uv `--break-system-packages` authority. It must stay serialized behind the current keyring/trust-store/reinstall work so one exact Agent Artifact Admission parent remains authoritative.

### Exact-current #129 gates

All predecessor #129 conclusions became historical when #283 merged. On exact current `341a3e05a614654536431eda8e553585b2533886`, CI `34542090175`, Fuzz `34542090160`, Security Scan `34542090158`, and SAST Semgrep `34542090131` are terminal SUCCESS. CodeQL PR `34542090178` is terminal FAILURE at central compatibility-verdict enforcement after its detection and later dispatch jobs succeeded; exact consumer evidence is recorded on `.github#1929` comment `5627309066`. This is central owner work, not evidence for predecessor-result transfer, synthetic status or Wardnet source churn.

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

UI Delivery Gate is **PASS for the material UI/product contract** on exact `83c4babc...`. The PR remains not merge-ready because CodeQL PR `34542012159` is terminal FAILURE at the central delegated verdict boundary and governance/coverage/package/SBOM/provenance requirements remain unresolved. No predecessor evidence or local browser result substitutes for those current protected-gate requirements.

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

Keep exact #129 `341a3e05a614654536431eda8e553585b2533886` as canonical Agent Artifact Admission parent until #287 is exact-current GREEN. Do not transfer predecessor evidence or churn source while runnerless current jobs are merely queued. Once #287 CI/Fuzz and review/thread evidence are terminal-valid, integrate it ordinarily into #129 with expected-head protection, reacquire #129's full gate set on the new exact head, and only then start #285 source work; #286 follows #285 and #288 follows #286.

Let #127's hosted 375/768/1440 product contract and exact CI/Fuzz/Security/SAST GREEN stand without source churn while central CodeQL settles. Continue runner/materialization, delegated CodeQL and solo-maintainer governance repairs through `.github#712`, `.github#1929` and `.github#772`; branch-topology repair remains `.github#1137`. Continue the PostgreSQL/recovery/coverage stack dependency-first. Only after protected prerequisites and all then-live gates are terminal-valid should Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.