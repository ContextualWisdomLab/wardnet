# Product and technical gap baseline

Snapshot date: 2026-09-11. Re-read live refs, PRs, reviews/threads, exact-head checks, rulesets, security evidence and releases before merge, release, restack or foreign-owner handoff. This is Wardnet's sole commercial/product-technical current-state ledger; detailed RED→GREEN receipts remain in the owning PR and issue histories. Draft/feature heads are provisional evidence, not protected or released truth, and predecessor GREEN never transfers after head/base movement.

## Authority boundary

Wardnet owns the Rust-first gateway/SOC control plane, Agent Artifact Admission, outbound destination-reputation assessment, Wardnet security-evidence lifecycle, policy decisions and SOC accountability. `quarantine-sandbox-runtime` owns hostile execution/isolation/cleanup and effective runtime environment/config authority; EgressWeave owns executable outbound URL/address/DNS/peer/redirect/proxy/TLS/resource authorization; `contextual-orchestrator` owns Agent/LLM/provider orchestration; `appguardrail` owns static package/security analysis; Keyverse remains credential/identity backend. Wardnet consumes released/versioned ports or ACLs only and does not copy sibling source, query foreign application tables, or pin mutable sibling heads as production dependencies.

Protected ADR truth keeps browser acquisition, sessions, anti-bot challenges and CAPTCHA handling outside Wardnet. A Wardnet reputation `allow` is not transport authorization: forwarding must compose Wardnet policy with independently authoritative EgressWeave authorization, and neither authority can override the other's deny.

`context-graph-contracts` is the provider-neutral Context Fabric Shared Kernel and `enterprise-architecture-core` is the EA Decision Plane. Wardnet reads those owner paths for compatibility and handoff only. Wardnet findings, IOCs, destination assessments and incidents remain Wardnet truth; architecture-relevant lifecycle/ownership/risk/remediation may be projected only through released compatible contracts/provenance.

## Protected truth, governance and release state

Protected/default Wardnet truth remains `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. Fresh Wardnet GitHub Release inventory is empty, so protected source truth is not yet an immutable release identity.

The organization solo-maintainer governance defect remains canonical `.github#772`: the generic one-approval requirement is structurally unsatisfiable without inventing a reviewer, while self-approval and model/bot-as-human approval remain forbidden. Deterministic workflow/security/SAST/coverage/package/SBOM/provenance/thread/branch-integrity gates must remain fail closed.

Runner/materialization remains `.github#712` authority. Delegated CodeQL terminal-verdict publication/wake ordering remains `.github#1929` or its live successor. Wardnet does not copy central workflow logic or churn clean product source to manufacture a terminal verdict.

PR #130 is the sole writer for this ledger. Every refresh advances its exact head, so this file deliberately does not embed #130's own current SHA as merge evidence.

## Context Fabric and EA compatibility

Fresh read-only inventory keeps `context-graph-contracts` protected/default `develop@99cb5468ba3c15c5e79688f53dee74724fae2d13` and `enterprise-architecture-core` protected/default `develop@dd71e40a86385fb7861b0f1be19891a3f3e29ece`. Their mutable heads and open proposals are compatibility evidence only; Wardnet does not write either repository while the Context Fabric owner is active. Package-manager argv, Wardnet-local reason codes, findings and verdicts remain Wardnet-local security truth.

## Agent Artifact Admission

Issue #128 / Draft #129 remains Wardnet's canonical package-install admission lane. After ordinary expected-head integration of #292, current exact #129 is `a6ead941fcb17cf7f8e1cb3c23cbaa5355263e43`, based on protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e`. No force update or destructive rebase is part of this lineage.

The candidate keeps deny-by-default structured-argv admission, reviewed workspace-manifest and artifact identity, exact ecosystem/name/version/registry/owner/digest binding, package-manager source/destination/config/workspace/lifecycle/integrity/build/platform/cardinality constraints, audit-before-allow and bounded remote-instruction provenance. An `allow` receipt is admission authority only; it is not evidence of retrieved-byte integrity, effective runtime configuration, transport authorization, installation, isolation or activation.

Integrated uv hardening includes keyring-provider authority, platform certificate-store trust selection, reinstall mutation authority and the `--break-system-packages` system-package boundary. For the reinstall slice, test-only `e2ef6f13eb2c19672967c20a73fa6bcb9f8e1dfa` established hosted semantic RED: ordinary reviewed uv install stayed `Allow` while `--reinstall`, `--force-reinstall` and attached `--reinstall-package=cwl-example` were incorrectly `Allow`. Minimum causal repair extended the existing PyPI mutation classifier only to exact `uv pip install` grammar. Exact #290 head `fbf417bca80a115bf9447699d2569a0ed05784a0` then reached CI `34554402631` SUCCESS and Fuzz `34554402508` SUCCESS, with fresh reviews/threads empty and exact parent comparison ahead-by-5/behind-by-0, before ordinary expected-head merge into #129. Issue #286 remains open until the effective delta reaches protected main.

### Integrated #288/#292: uv externally-managed Python override

Test-only formatter-clean `79230872fac291abe4be3fcec6dcaacc741c4768` left production source byte-identical to parent `f8966ae182d6569513750245707fdb2c009c3597` and established hosted semantic RED in CI `34555610360` / rust `103127551723`: the ordinary reviewed uv install remained `Allow`, while exact `--break-system-packages` incorrectly inherited artifact approval. The earlier test-only predecessor failed only rustfmt and was not reused as RED evidence.

Minimum causal repair at exact child `19439f1847ddcd3e1918a47eaf28a7676d3782bd` extended only the existing system-package-authority classifier to exact uv grammar. Direct `pip|pip3` retains the reviewed unambiguous Python `optparse` long-option-prefix semantics; uv accepts only exact `--break-system-packages`, and prefix lookalikes plus an invented `=true` form do not inherit pip behavior. Exact child CI `34556203889` and Fuzz `34556203868` reached terminal SUCCESS. Fresh reviews and inline threads were empty; exact compare against parent was ahead-by-3/behind-by-0 with that exact merge base and only the classifier plus hostile contract changed. #292 was marked Ready only after those gates and ordinarily merged with expected head `19439f1847ddcd3e1918a47eaf28a7676d3782bd`, producing canonical #129 head `a6ead941fcb17cf7f8e1cb3c23cbaa5355263e43`. Issue #288 remains open until protected-main adoption.

Fresh exact-file verification also corrected one false follow-on finding before any code delta: canonical `policy.rs::requests_alternate_install_root` already blocks uv `--user`, `--target`, `-t`, `--root`, `--prefix`, `--system`, `--python` and `-p`. Issue #293 was therefore closed under the explicit no-valid-delta condition; stale/incomplete code-search indexing is not source authority.

### Active #294/#296: uv torch backend source authority

Current Astral `uv pip install` documentation states that `--torch-backend` selects the backend for PyTorch ecosystem packages and, when set, ignores configured index URLs for those packages in favor of the backend-defined index. Exact canonical `requests_alternate_trust_root` and the uv artifact-variant classifier do not bind this selector.

Now that #292 is integrated, Draft #296 is the sole serialized source child for #294, based exactly on canonical #129 `a6ead941fcb17cf7f8e1cb3c23cbaa5355263e43`. Test-only exact head `dcfe46c6a66cf6e625e6b82cd9c5763f9b48a0c4` changes only `uv_torch_backend_authority_contract.rs`; production source remains byte-identical to the parent. The ordinary reviewed uv install is the Allow control. Current documented `--torch-backend=cpu` must fail closed with exactly `alternate_trust_root`; separate-value `--torch-backend cpu` must also carry `alternate_trust_root` rather than being rejected only as an accidental positional-artifact mismatch. CI `34557204481` and Fuzz `34557204505` are queued. RED remains unclaimed until hosted CI passes checkout/toolchain/format and reaches the semantic assertion. Wardnet must not resolve backend indexes, perform transport, inspect ambient `UV_TORCH_BACKEND`, or duplicate EgressWeave/quarantine authority.

### Concurrent SSRF repair #291/#295

Draft #291 exact `fb7ea1c5c9ced5ed4a532655ececcb6e7fe5cfe8` removes request-controlled Phishing.Database feed URLs and the `allow_non_default_hosts` escape hatch, resolves feed URLs server-side, and restricts the resulting fetch to sanctioned Phishing.Database hosts or loopback test fixtures. Its description now accurately states that production uses built-in upstream URLs and the URL override is test-only; no production mirror/configuration surface is claimed.

Because #291's repaired tree could not itself prove the protected baseline was vulnerable, Draft #295 was created from exact protected `main@a52ccd0a24a727d9349bb32def7713882d8cad1e` as a test-only hostile companion. Exact `#295@2e60e6dc4b49b82002f7452a37b670d6b4d0269a` starts a loopback feed and requires an authenticated request-selected `domain_url` plus `allow_non_default_hosts=true` to be rejected before any fetch. Production source is byte-identical to protected main. CI `34557037833` is queued and currently non-passing evidence until checkout/toolchain/format reach the semantic assertion. #291 remains Draft until hosted causal RED is recorded and its unchanged repair carries the complete valid invariant; the companion is not closed merely to reduce PR count.

## Outbound destination reputation

#173 remains the proposed Wardnet-owned reputation architecture and #175 the root pure-Rust `wardnet.reputation.v1` contract. Production composition still requires an immutable compatible EgressWeave authorization/evidence contract. Wardnet never turns a destination/reputation verdict into transport authority.

## PostgreSQL production-state prerequisite stack

The durable-state stack remains dependency ordered through #140 → #193 → #194 → #196 → #198 → #199 → #200 → #207 → #208 → #209 → #212 → #216 → #217 → #219 → #221 → #223 → #224 → #225 → #226 → #228 → #229 → #231 → #233 → #234 → #236 → #241 → #242 → #244. Any parent movement requires ordinary non-force adoption and fresh exact-head evidence.

The Draft lineage establishes fail-closed PostgreSQL authority selection, credential indirection, immutable generation identity, atomic publication/head persistence under FORCE RLS, least-privilege roles, failure-atomic migration/recovery, externally managed LOGIN mapping, transaction-local tenant binding, typed publication/replay/conflict semantics, mandatory actor/decision attribution, removal of arbitrary raw-SQL escape hatches, authoritative-complete reads, bounded pool replenishment/readiness, ambiguous-COMMIT fail-closed handling, physical recovery drills and no automatic replay after database work begins.

Issue #243 remains open because `cargo test` is not proof of 100% owned-production statement/line, branch, edge and public-rustdoc coverage. Remaining durable-state gaps include dependency-first protected integration, explicit exact-head coverage/rustdoc evidence, production backup/WAL retention/storage authority, encryption-key/IAM authority, production RPO/RTO/SLO/restore evidence and immutable release identity.

## Admin console buyer path

Draft #127 exact `83c4babc0e1bd9b428be7dc3afc5779ca68abdbd` retains hosted real-browser product GREEN: CI `34542012228`, Fuzz `34542012166`, Security Scan `34542012272` and SAST Semgrep `34542012155` are terminal SUCCESS. The browser contract covers loading/normal/permission-denied states, keyboard skip-link transfer, computed accessibility semantics and unchanged 375/768/1440 responsive clipping/overflow boundaries. UI Delivery Gate is PASS for the material UI/product contract on that exact head; delegated CodeQL/governance/coverage/package/SBOM/provenance still prevent protected integration.

## Process lifecycle and graceful shutdown

Draft #245 remains exact `d953c1d94ebbde87a0f7c4121a8088e0b9fa14f2`. Its test-first Unix signal lineage established semantic SIGINT RED; the minimum production repair registers SIGTERM/SIGINT before readiness and resolves the existing shutdown future through one `tokio::select!`, without creating a second lifecycle authority. Exact CI `34423929129`, Fuzz `34423929826`, Security `34423929246` and SAST `34423929010` are SUCCESS; delegated CodeQL remains central control-plane work.

## Release evidence foundation

Draft #164 remains stacked on Rust-toolchain prerequisite #77, exact head `42a673defb756d959cf754a8140227fbebfdd0f1`. It builds deterministic source/binary release evidence and keeps OIDC-backed attestation authority protected-main/manual-dispatch only. Exact CI `34425717320` is terminal SUCCESS. This foundation is not itself a release, and Wardnet release inventory remains empty.

## Release and operational buyer gaps

Wardnet is not release-ready. A release-ready protected head must bind one exact source/artifact identity across version, CHANGELOG, tag, package/image digest, SBOM, signature/provenance, reproducibility, deployment promotion, rollback/roll-forward, security/coverage and recovery evidence.

Material production gaps still include protected management authentication and Runtime Configuration foundations; PostgreSQL authority/RLS/recovery and exact coverage; transactional outbox/idempotent workers; Keyverse-backed identity/tenant authorization/separation-of-duties and governed human approval; bounded/distributed admission and trusted client attribution; proven Coraza/CRS + Suricata enforcement with deployed attack evidence; Agent Artifact Admission integrated through released foreign-owner ports; graceful shutdown/cleanup; production telemetry/SLO/incident/restore evidence; and immutable release governance.

No mutable CGC/EA/EgressWeave/contextual-orchestrator/quarantine/AppGuardrail head satisfies a released-contract prerequisite. Wardnet fails closed rather than duplicating those canonical owners.

## Execution order

Keep exact #129 `a6ead941fcb17cf7f8e1cb3c23cbaa5355263e43` as canonical Agent Artifact Admission parent while #296 establishes hosted RED and then the minimum uv `--torch-backend` alternate-source/trust repair. Do not transfer predecessor evidence or churn source while current jobs are merely queued. After causal RED, preserve the ordinary uv Allow control, bind only current parser-supported `--torch-backend` forms to `alternate_trust_root`, reacquire exact-head CI/Fuzz plus fresh review/thread/parent compatibility, then integrate ordinarily with expected-head protection.

Advance concurrent #291 independently. #295 must first establish the protected-baseline hostile SSRF receipt; then verify #291's unchanged server-owned URL/allowlist repair carries the complete valid invariant, reacquire current-head deterministic/security evidence and only then consider ordinary protected integration. Do not treat the independent lane as a race.

Let #127's hosted 375/768/1440 product contract stand without source churn while central CodeQL settles. Continue runner/materialization, delegated CodeQL and solo-maintainer governance repairs through `.github#712`, `.github#1929` and `.github#772`. Continue the PostgreSQL/recovery/coverage stack dependency-first. Only after protected prerequisites and all then-live gates are terminal-valid should Wardnet create version/tag/package/SBOM/provenance/reproducibility/rollback evidence and publish an immutable release. No force updates, destructive rebases, gate weakening, self/model approval, routine bypass, source copying, cross-service SQL or predecessor-evidence transfer.
