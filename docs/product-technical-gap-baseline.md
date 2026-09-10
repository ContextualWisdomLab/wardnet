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

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Both release inventories remain empty. Their mutable heads, open proposals and Draft contracts are compatibility evidence only; Wardnet does not write either repository while the Context Fabric owner is active. The still-misaligned default/protected `develop` metadata versus the intended protected `main` integration topology was refreshed to canonical `.github#1137` with exact owner SHAs and acceptance criteria rather than repaired from Wardnet.

CGC and EA current work includes protected-source/release-evidence contracts, external-capability/procedural-graph contracts, Context Fabric consumer projections and Wardnet outbound-reputation architecture projection. None is an immutable production dependency until the canonical owner publishes a compatible release. Package-manager argv, Wardnet-local reason codes, findings and verdicts remain Wardnet-local security truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. Current exact #129 head is `341a3e05a614654536431eda8e553585b2533886`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. It was produced by ordinary expected-head merge of #283 into predecessor `1f904898cd6280bc796bb81822171a2d6fb3073a`; fresh compare from that predecessor is ahead 7 / behind 0 and carries the complete 15-path #283 delta. No force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only. It is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

Retained child lanes bind PyPI hash mode, uv insecure-host/configuration authority, pip CA/client-certificate/configuration/proxy/report/log/cache/system-package authority, durable audit-file path/permission/link authority, direct pip installation mutation controls, explicit pip keyring-provider authority and direct-pip noninteractive credential authority. Their owning issues remain open until the effective deltas reach protected main.

### Integrated #280/#281: pip keyring-provider authority

Pinned `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5` defines `--keyring-provider` choices `auto|disabled|import|subprocess`. At the same exact revision, `network/auth.py` imports ambient Python `keyring` for `import`, PATH-resolves and invokes a `keyring` executable for `subprocess`, and suppresses keyring under `--no-input` only for the `auto|disabled` baseline unless a specific provider is requested.

Test-only `97d3d89a5ccd13b36239277736e19dfdcb1db38b`, followed only by rustfmt commit `12f8b1cde4802d622b3280af0de41c5712dd195b`, left production source unchanged. Hosted CI `34527752769` on exact `12f8b1c...` acquired a real `ubuntu-24.04` runner, passed checkout/toolchain/format and failed in `Test`, establishing semantic RED. The minimum causal repair is isolated to `pypi_keyring_provider_authority.rs` plus admission wiring: explicit `import|subprocess`, including pinned parser-accepted unambiguous long-option abbreviations, fail closed with stable `alternate_trust_root`; `auto|disabled` preserve the reviewed `--no-input` baseline. Exact child `25b499bca0d234889db9102e9db92a865bd66690` passed CI `34531637458` and Fuzz `34531637306`, with zero formal reviews and zero inline review threads. PR #281 was marked Ready and merged ordinarily with expected-head protection. Issue #280 remains open until protected-main adoption.

### Integrated #282/#283: noninteractive pip authority

Fresh source review after #281 found a separate default-path authority gap. The canonical evaluator required `--require-hashes` for pip/pip3 but not canonical `--no-input`. Pinned pip authentication code makes keyring eligible while prompting remains enabled, and default `auto` may import ambient Python keyring or invoke a PATH-resolved keyring executable. Omission of `--no-input` could therefore inherit interactive/ambient credential-provider authority without using the explicit provider options already blocked by #281.

Initial test-only #283 head `124e1eb2cce935d83d302b265633a6d6c62482cf` left production source byte-identical to its parent and changed only the new hostile contract. Hosted CI `34536050936` / rust `103067799015` acquired a real `ubuntu-24.04` runner, passed checkout/toolchain/`cargo fmt --check`, then failed in `cargo test --locked --workspace` exactly at `approved_pip_install_must_disable_interactive_credential_discovery`: the implementation returned `Allow` where the contract required `Block`; exit code 101. This was semantic RED, not runner/bootstrap/format failure.

After RED, the minimum production repair added only focused `pypi_noninteractive_authority.rs` plus admission wiring. Direct `pip|pip3 install` that omits the canonical exact `--no-input` token appends existing `missing_safety_flag` and blocks. The first repaired head `87ed2bb041f5a7c8c96bc8cb38933549cc748511` reached hosted CI and exposed a stale positive fixture rather than a production weakness; `85fbf8df45e16d8e8980dba655e670232bdc8bbe` and `e511c35c1dac203b6669dc0d6558a52e5bf88395` adopted the new invariant across the remaining positive direct-pip fixtures while leaving uv baselines unchanged.

Final exact child `f3fe5262af0e9ffc0fad7808f6ea3ed978ad0da6` added `docs/doctoring/pypi-noninteractive-credential-authority.md` with pinned pip source, NIST SP 800-218A, decision/rejected alternatives and RED→GREEN traceability. On the unchanged exact head, CI `34540381857` and Fuzz `34540381844` both became terminal SUCCESS after initially waiting for hosted runners; fresh submitted reviews and inline threads were both zero. #283 was marked Ready and merged ordinarily with expected-head protection into #129, producing current canonical `341a3e05...`. Issue #282 remains open until protected-main adoption.

### Current security lane #284/#287: uv subprocess keyring authority

Fresh exact review of current canonical #129 found the existing `pypi_keyring_provider_authority` classifier remains deliberately scoped to direct `pip|pip3 install`, while `uv pip install` is admitted. Current Astral uv documentation states keyring authentication is disabled by default but `--keyring-provider subprocess` is supported and delegates lookup to the `keyring` executable. Attached `--keyring-provider=subprocess` is option-shaped and therefore can add caller-selected credential-helper authority without becoming an undeclared positional artifact operand.

Issue #284 records the Wardnet-local pre-execution gap. Draft #287 is the sole active Agent Artifact Admission source writer and is based directly on current canonical `341a3e05...`. Its initial exact head `85b7b55648f29dc45a38dd01134583610fb0952f` is test-only: production source is byte-identical to #129 and the only changed path is `tests/uv_keyring_provider_authority_contract.rs`. The contract preserves the exact approved uv baseline, then requires attached subprocess-provider selection to block with stable `alternate_trust_root`. CI `34542208606` and Fuzz `34542208653` are queued/non-passing. No production fix is permitted until hosted CI reaches the new assertion and establishes semantic RED.

### Next serialized trust gap #285: uv system certificate-store authority

Fresh exact review also found `uv pip install` can expand TLS trust through caller-selected native certificate-store options that Wardnet does not currently classify. Astral's current TLS documentation states uv uses bundled Mozilla roots by default and `--system-certs` switches verification to the platform native certificate store via `rustls-platform-verifier`. This can add enterprise/local roots absent from the reviewed bundled trust set without changing artifact identity or digest authority.

Issue #285 remains issue-only behind #287. Wardnet must classify parser-supported trust-source argv and fail closed with stable `alternate_trust_root`; it must not enumerate OS stores, perform TLS/network I/O, or infer ambient `UV_SYSTEM_CERTS`. EgressWeave remains executable transport/TLS authorization and quarantine remains effective runtime/environment authority. Deprecated `--native-tls` is covered only if the then-pinned upstream grammar still accepts it.

### Next serialized mutation gap #286: uv reinstall authority

Current Astral command/reference documentation identifies `--reinstall` and alias `--force-reinstall` as reinstalling all packages regardless of installed state and implying refresh, while `--reinstall-package` applies the same authority to a selected package. The current Wardnet `pypi_install_mutation_authority` is direct-pip-only, so attached uv reinstall selectors can request broader environment mutation without changing the reviewed artifact coordinate, manifest or digest.

Issue #286 remains issue-only behind #285. Its future RED must preserve the ordinary exact uv baseline while proving `--reinstall`, alias `--force-reinstall`, and attached `--reinstall-package=<name>` fail closed for the existing install-mutation authority reason rather than via accidental positional rejection. Effective environment mutation remains quarantine-owned.

### Exact-current #129 gate state

All predecessor #129 gate conclusions became historical when #283 merged. Fresh workflows have materialized for exact current `341a3e05a614654536431eda8e553585b2533886`: CI `34542090175`, Fuzz `34542090160`, Security Scan `34542090158`, SAST Semgrep `34542090131`, and CodeQL PR `34542090178` are queued/non-passing at this snapshot. The concurrent test-only #287 CI/Fuzz are also queued. Exact allocation evidence and acceptance criteria were refreshed to `.github#712`; no Wardnet source churn or selector weakening is justified by the wait.

Delegated CodeQL terminal-verdict settlement remains `.github#1929` owner work. Current evidence there distinguishes Draft exemptions from actual Ready-PR verdicts; Wardnet must not treat a Draft workflow success as proof the broken Ready path is repaired. Solo-maintainer one-approval incompatibility remains `.github#772`; self/model approval and routine administrator bypass remain forbidden.

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

Treat canonical #129 exact `341a3e05a614654536431eda8e553585b2533886` as current Agent Artifact Admission parent. Let its current exact CI/Fuzz/Security/SAST/CodeQL runs materialize without predecessor-evidence reuse or source churn, with central allocation and delegated-settlement defects progressing through `.github#712` and `.github#1929`. Keep #282 open until protected main.

Run #287 test-first from exact `341a3e05...`: semantic RED must be the new uv subprocess-keyring assertion, not runner/bootstrap failure. Only after that RED may the minimum credential-provider classifier repair be made; reacquire exact-head CI/Fuzz and review/thread evidence, then ordinary expected-head merge into #129 and reacquire the canonical parent's full gate set. Next serialize #285, then #286, always from the then-exact canonical parent. Hand governance/runner/CodeQL defects to `.github#772`, `.github#712`, and `.github#1929` with exact consumer evidence. Repair #127 only through a write path that preserves the complete `src/lib.rs` blob, then reacquire 375/768/1440 real-browser evidence. Continue #244/#243 with explicit coverage/rustdoc and production storage/recovery/release invariants. Integrate dependencies only through ordinary protected governance, then create and verify the immutable release without force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.
