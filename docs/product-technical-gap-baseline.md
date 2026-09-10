# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger. Detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. The branch is protected and repository-local `rust` remains a required status context. Fresh Wardnet release inventory is empty, so protected source truth is not yet an immutable release identity.

Organization ruleset `18156473` remains active on the default branch. Its generic `required_approving_review_count=1` remains structurally incompatible with the declared solo-maintainer model while no eligible independent reviewer/team exists; `.github#772` is the canonical governance repair path. Self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates are not to be weakened and routine administrator bypass is not an acceptance path.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication/wake ordering remains `.github#1929` or its live successor. Wardnet does not add leaf provider/model/group fallbacks, duplicate central workflows, synthesize statuses, or source-churn a clean candidate to repair those planes.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed PR #130's own current SHA as merge evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. CGC currently has 5 open issues and 14 open PRs; EA Core has 8 open issues and 24 open PRs. Both release inventories remain empty. Their mutable heads, open proposals and Draft contracts are compatibility evidence only; Wardnet does not write either repository while the Context Fabric owner is active.

CGC's current work includes protected-source/release-evidence contracts and external-capability/procedural-graph contracts; EA's current work includes Context Fabric consumer projections and Wardnet outbound-reputation architecture projection. None is an immutable production dependency until the canonical owner publishes a compatible release. Package-manager argv, Wardnet-local reason codes, findings and verdicts remain Wardnet-local security truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `1f904898cd6280bc796bb81822171a2d6fb3073a`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. It was produced by ordinary expected-head merge of #281 into predecessor `9de9f0b9410fd060b54978187b55263f5e8052c6`; no force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

Retained child lanes bind PyPI hash mode, uv insecure-host/configuration authority, pip CA/client-certificate/configuration/proxy/report/log/cache/system-package authority, durable audit-file path/permission/link authority, and direct pip installation mutation controls such as `--ignore-installed` and `--force-reinstall`. Their owning issues remain open until the effective deltas reach protected main.

### Integrated #280/#281: pip keyring-provider authority

Pinned `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5` defines `--keyring-provider` choices `auto|disabled|import|subprocess`. At the same exact revision, `network/auth.py` imports ambient Python `keyring` for `import`, PATH-resolves and invokes a `keyring` executable for `subprocess`, and suppresses keyring under `--no-input` only for the `auto|disabled` baseline unless a specific provider is requested.

Test-only `97d3d89a5ccd13b36239277736e19dfdcb1db38b`, followed only by rustfmt commit `12f8b1cde4802d622b3280af0de41c5712dd195b`, left production source unchanged. Hosted CI `34527752769` on exact `12f8b1c...` acquired a real `ubuntu-24.04` runner, passed checkout/toolchain/format and failed in `Test`, establishing semantic RED. The minimum causal repair is isolated to `pypi_keyring_provider_authority.rs` plus admission wiring: explicit `import|subprocess`, including pinned parser-accepted unambiguous long-option abbreviations, fail closed with stable `alternate_trust_root`; `auto|disabled` preserve the reviewed `--no-input` baseline. Exact child `25b499bca0d234889db9102e9db92a865bd66690` passed CI `34531637458` and Fuzz `34531637306`, with zero formal reviews and zero inline review threads. PR #281 was marked Ready and merged ordinarily with expected-head protection, producing current canonical #129 `1f904898cd6280bc796bb81822171a2d6fb3073a`. Issue #280 remains open until protected-main adoption.

Current exact #129 gate evidence on unchanged `1f904898...`: CI `34535375385`, Fuzz `34535375418`, SAST Semgrep `34535375405`, and Security Scan `34535375379` are terminal SUCCESS. CodeQL PR `34535375377` is terminal FAILURE at the central settlement boundary rather than in Wardnet source: detect job `103065638908` succeeded on a real hosted runner; compatibility job `103067185385` successfully read the current-head dispatch verdict and then failed at `Release runner or enforce current-head CodeQL verdict`; later job `103069857489` on the same unchanged head successfully dispatched the current-head CodeQL scan. That producer-after-settlement ordering specimen was handed to `.github#1929` with exact run/job/head evidence and unchanged-head RED/GREEN acceptance. Current review submissions are COMMENTED only and the sole inline thread is resolved/outdated. No leaf workaround, synthetic status, source churn or permissive fallback is acceptable.

### Current security lane #282/#283: noninteractive pip authority

Fresh source review after #281 found a separate default-path authority gap. Current #129 `validate_safety_flags` requires `--require-hashes` for pip/pip3 but not canonical `--no-input`. Pinned pip authentication code makes keyring eligible while prompting remains enabled, and default `auto` may import ambient Python keyring or invoke a PATH-resolved keyring executable. Omission of `--no-input` can therefore inherit interactive/ambient credential-provider authority without using the explicit provider options already blocked by #281.

Issue #282 records this Wardnet-local admission gap. Initial Draft #283 exact `124e1eb2cce935d83d302b265633a6d6c62482cf` was test-only: production source remained byte-identical to canonical #129 and only `pypi_noninteractive_authority_contract.rs` changed. Hosted CI `34536050936` / rust job `103067799015` acquired a real `ubuntu-24.04` runner, passed checkout/toolchain/`cargo fmt --check`, then failed in `cargo test --locked --workspace` exactly at `approved_pip_install_must_disable_interactive_credential_discovery`: the current implementation returned `Allow` where the security contract required `Block`; exit code 101. This is semantic RED, not runner/bootstrap/format failure.

After RED, the minimum production repair added only focused `pypi_noninteractive_authority.rs` plus admission wiring in `lib.rs`. Direct `pip|pip3 install` that omits the canonical exact `--no-input` token now appends the existing stable `missing_safety_flag` reason and blocks. No credential lookup, runtime/environment enforcement, transport authorization or package execution was introduced.

The first repaired-head attempt `87ed2bb041f5a7c8c96bc8cb38933549cc748511` reached real hosted CI `34536926267` / rust job `103070609378`, passed checkout/toolchain/format, and then exposed a pre-existing positive-fixture adoption defect at `pypi_artifact_source_identity_contract::exact_pypi_index_name_and_version_remain_allowed`: the approved direct-pip fixture still omitted newly mandatory `--no-input`, so the production evaluator correctly returned `Block`. Production logic was not weakened. Commit `85fbf8df45e16d8e8980dba655e670232bdc8bbe` adopted the new invariant in that exact fixture; follow-up source inventory found the same stale approved-baseline assumption in the remaining positive direct-pip PyPI authority fixtures. Current exact #283 head `e511c35c1dac203b6669dc0d6558a52e5bf88395` adopts those positive baselines together while leaving uv baselines unchanged because this lane governs direct `pip|pip3 install` only. Fresh CI `34538555073` and Fuzz `34538555053` are queued/non-passing. Keep #283 Draft until exact-head GREEN plus fresh review/thread verification, then integrate only by ordinary expected-head merge into #129. Issue #282 remains open until protected-main adoption.

### Next serialized security gap #284: uv subprocess keyring authority

Fresh exact review of canonical #129 found that the existing credential-provider classifier is intentionally scoped to direct `pip|pip3 install`, while `uv pip install` is an admitted command path and the uv configuration guard covers only explicit config-file authority. Current Astral uv documentation states that uv keyring use defaults to disabled but `--keyring-provider subprocess` is supported and invokes the PATH-resolved `keyring` command for credential lookup. Attached syntax such as `--keyring-provider=subprocess` is option-shaped and therefore does not become an undeclared positional artifact operand. Without an explicit Wardnet admission classification, an otherwise reviewed uv invocation can add caller-selected credential-helper authority without changing the reviewed package coordinate, manifest digest, registry, artifact hash or dependency-cardinality contract.

Issue #284 records the Wardnet-local pre-execution gap and preserves owner boundaries: Wardnet must only classify the structured argv and fail closed; Keyverse remains credential/identity backend, quarantine remains runtime/environment and hostile-execution authority, and EgressWeave remains executable outbound transport authority. Serialize #284 behind #283 to avoid competing source writers. Its RED must prove an otherwise approved exact uv install remains allowed while attached `--keyring-provider=subprocess` blocks with stable `alternate_trust_root`; its minimum GREEN should extend the existing credential-provider authority concept rather than create a second bounded context, preserve uv's disabled baseline, and avoid PATH lookup, process execution, credential access or network activity in Wardnet tests.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. The evidence line remains ordered through business authorization, freshness, source/evidence health, exact generation membership, lifecycle validity, producer-version/tombstone cursor, atomic source replacement and ABA replay resistance. Durable production authority remains the PostgreSQL #80/#192 lineage because bounded current-only lifecycle memory cannot prove historical opaque generation uniqueness.

Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns destination/reputation verdict into transport authority.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 remains at exact semantic product RED `2ca5a8e55185730abec34886279b5aa576be5658`. Hosted CI `34486350074` passed checkout/toolchain/format and all 121 library tests, then real Chrome/ChromeDriver failed at the 375 px shipped-route overflow assertion. Fuzz `34486350227`, Security Scan `34486350160`, and SAST Semgrep `34486350184` are terminal SUCCESS.

Root cause remains `header.app` as a non-wrapping flex row with 24 px side padding while the heading and toolbar/admin-token field cannot fit the resulting narrow content width. Minimum repair remains `flex-wrap:wrap` on the complete production declaration, followed by unchanged 375/768/1440 browser acceptance. Prior whole-file materialization attempts that truncated `src/lib.rs` were repaired; no incomplete-file write is acceptable. UI Delivery Gate remains **FAIL** until exact complete source carries the repair and the shipped-route browser test is GREEN.

## Process lifecycle and graceful shutdown

Draft #245 remains the process-lifecycle candidate. Its test-first Unix signal lineage established a semantic SIGINT RED and the minimum production repair registers SIGTERM/SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`; no second lifecycle authority was added. Draft GREEN is not protected lifecycle truth.

## Release and operational buyer gaps

Wardnet is **not release-ready**. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Treat canonical #129 exact `1f904898cd6280bc796bb81822171a2d6fb3073a` as the only current Agent Artifact Admission parent until #283 is integrated. Let #129's central CodeQL settlement defect progress through `.github#1929` without Wardnet source churn. Let #283 exact `e511c35c1dac203b6669dc0d6558a52e5bf88395` acquire current-head CI/Fuzz; on GREEN, verify review/thread state, mark Ready and ordinary expected-head merge into #129, then reacquire all canonical #129 gates. Keep #282 open until protected main. Only after #283 integrates, create the test-first #284 child from the then-exact canonical #129 head and prove uv subprocess keyring authority RED→minimum GREEN. Hand central governance/runner/CodeQL defects to `.github#772`, `.github#712`, and `.github#1929` with exact consumer evidence. Repair #127 only through a write path that preserves the complete `src/lib.rs` blob, then reacquire 375/768/1440 real-browser evidence. Continue #244/#243 with explicit coverage/rustdoc and production storage/recovery/release invariants. Integrate dependencies only through ordinary protected governance, then create and verify the immutable release without force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.
