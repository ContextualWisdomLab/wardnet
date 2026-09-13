# Agent Artifact Admission Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independently deployable Rust admission service that blocks AI-agent package installation unless a reviewed manifest and exact content-addressed artifact policy authorize it.

**Architecture:** A new workspace crate owns strict models, pure deterministic policy evaluation, append-only audit sinks, configuration/credential loading, and a small authenticated Axum API. It never executes commands; callers receive a durable allow/block receipt and must fail closed when the service is unavailable.

**Tech Stack:** Rust 2024, Axum 0.8, Tokio 1, Serde/serde_json 1, `ring` SHA-256, `subtle` constant-time comparison, `reqwest::Url`, Tower integration tests, proptest.

**Spec:** `docs/superpowers/specs/2026-08-28-agent-artifact-admission-design.md`

## Global Constraints

- Base all work directly on protected `main`; do not stack on unrelated Wardnet PRs.
- Production code is Rust only.
- Runtime credentials come from the credential JSON file; no runtime secret lookup from environment variables.
- The process binds only to an IP loopback address in v0.1.
- Requests contain structured `argv`; no shell command string API exists.
- Empty policy, absent evidence, malformed evidence, and audit failure all block.
- Unknown JSON fields are rejected.
- Public APIs require doc comments.
- Production statement coverage, branch coverage, and public API documentation coverage target 100%.
- No raw token or raw command may appear in responses, logs, or audit records.
- Existing Wardnet gateway behavior must remain unchanged.

---

### Task 1: Lock the threat contract with a failing test

**Files:**
- Create: `tests/agent_artifact_admission_red.rs`
- Create: `docs/superpowers/specs/2026-08-28-agent-artifact-admission-design.md`
- Create: `docs/superpowers/plans/2026-08-28-agent-artifact-admission.md`

**Interfaces:**
- Consumes: none
- Produces: the required public API names used by the implementation tasks

- [ ] **Step 1: Write the failing attack regression**

```rust
use wardnet_agent_artifact_admission::{
    AdmissionPolicy, InstallIntent, admission_decision,
};

#[test]
fn unowned_package_from_llms_txt_is_blocked() {
    let policy = AdmissionPolicy::deny_all_for_test();
    let intent = InstallIntent::unowned_llms_package_for_test();
    let decision = admission_decision(&policy, &intent);
    assert_eq!(decision.decision.as_str(), "block");
}
```

- [ ] **Step 2: Push the test and verify RED on GitHub Actions**

Expected: the Rust job fails because `wardnet_agent_artifact_admission` does not yet exist. This establishes that the test detects the missing boundary rather than passing against existing behavior.

- [ ] **Step 3: Commit**

```bash
git add tests/agent_artifact_admission_red.rs docs/superpowers

git commit -m "test(security): define agent artifact admission boundary"
```

### Task 2: Create strict domain models and SHA-256 helpers

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/agent-artifact-admission/Cargo.toml`
- Create: `crates/agent-artifact-admission/src/lib.rs`
- Create: `crates/agent-artifact-admission/src/model.rs`
- Test: `crates/agent-artifact-admission/tests/admission_contract.rs`
- Delete: `tests/agent_artifact_admission_red.rs`

**Interfaces:**
- Consumes: design request/policy schema
- Produces: `InstallIntent`, `AdmissionPolicy`, `ApprovedManifest`, `ApprovedArtifact`, `AdmissionDecision`, `DecisionKind`, `ReasonCode`, `sha256_hex`, `is_sha256_hex`

- [ ] **Step 1: Move the RED regression into the new crate and add strict-deserialization tests**

Cover unknown fields, empty IDs, invalid lowercase SHA-256, duplicate artifact arguments, and serialization of snake-case enums.

- [ ] **Step 2: Run the focused tests and verify RED**

```bash
cargo test -p wardnet-agent-artifact-admission --test admission_contract
```

Expected: unresolved model functions/types.

- [ ] **Step 3: Implement the model types**

Use `#[serde(deny_unknown_fields)]` on all input/config structs and `#[serde(rename_all = "snake_case")]` on enums. Bound all identifiers, arguments, artifact fields, and counts during validation rather than accepting unbounded strings.

- [ ] **Step 4: Implement SHA-256 through `ring::digest`**

```rust
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, input);
    digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}
```

Add NIST-known vector assertions for empty input and `abc`.

- [ ] **Step 5: Run focused tests and verify GREEN**

```bash
cargo test -p wardnet-agent-artifact-admission --test admission_contract model_
```

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/agent-artifact-admission tests/agent_artifact_admission_red.rs

git commit -m "feat(security): add artifact admission domain model"
```

### Task 3: Implement pure fail-closed policy evaluation

**Files:**
- Create: `crates/agent-artifact-admission/src/policy.rs`
- Modify: `crates/agent-artifact-admission/src/lib.rs`
- Modify: `crates/agent-artifact-admission/tests/admission_contract.rs`

**Interfaces:**
- Consumes: `AdmissionPolicy`, `InstallIntent`
- Produces: `pub fn admission_decision(policy: &AdmissionPolicy, intent: &InstallIntent) -> AdmissionDecision`

- [ ] **Step 1: Add failing tests for source provenance**

Test remote `llms_txt`, `llms_full_txt`, `web_page`, and `issue_comment` sources with missing URI, HTTP URI, user-info URI, missing digest, query, and fragment. Query/fragment must be removed from the normalized response URI.

- [ ] **Step 2: Add failing tests for forbidden command paths**

Test shells, downloaders, `npx`/`pnpx`/`bunx`, runtime `-c`/`-e`, alternate Python trust roots, non-allowlisted executable, empty/missing artifact arguments, and duplicate artifacts.

- [ ] **Step 3: Add failing tests for exact policy matching**

Test manifest, ecosystem, name, version, registry, owner, digest, and artifact-argument mismatch independently. Test moving versions (`latest`, `main`, wildcard, range) and empty deny-all policy.

- [ ] **Step 4: Add failing tests for package-manager safety flags**

Require `--ignore-scripts`, `--require-hashes`, `--locked`, and container `@sha256:` according to executable/subcommand.

- [ ] **Step 5: Run all policy tests and verify RED**

```bash
cargo test -p wardnet-agent-artifact-admission --test admission_contract
```

- [ ] **Step 6: Implement deterministic validation and reason ordering**

The evaluator accumulates stable `ReasonCode` values without including untrusted text. It returns `allow` only when the reason list is empty. Exact artifact matching uses normalized HTTPS registry URLs and all identity fields.

- [ ] **Step 7: Add a proptest invariant**

For arbitrary `argv`, source strings, and package fields, assert that the evaluator never panics. Assert that an empty policy never allows.

- [ ] **Step 8: Run focused and property tests; verify GREEN**

```bash
cargo test -p wardnet-agent-artifact-admission --test admission_contract
```

- [ ] **Step 9: Commit**

```bash
git add crates/agent-artifact-admission/src crates/agent-artifact-admission/tests

git commit -m "feat(security): enforce exact package admission policy"
```

### Task 4: Add append-only audit with audit-before-allow semantics

**Files:**
- Create: `crates/agent-artifact-admission/src/audit.rs`
- Modify: `crates/agent-artifact-admission/src/lib.rs`
- Create: `crates/agent-artifact-admission/tests/audit_contract.rs`

**Interfaces:**
- Consumes: `InstallIntent`, `AdmissionDecision`
- Produces: `AuditRecord`, `AuditArtifact`, `AuditSink`, `FileAuditSink`, `MemoryAuditSink`, `build_audit_record`

- [ ] **Step 1: Write failing audit minimization tests**

Assert records contain command SHA-256 and normalized source URI, but not raw argv, query, fragment, or token-shaped test values. Assert artifact coordinates and policy identity are preserved.

- [ ] **Step 2: Write failing file durability tests**

Append two records and verify two complete NDJSON lines. Force an oversized serialized record and deterministic sink failure; both must return an error.

- [ ] **Step 3: Run and verify RED**

```bash
cargo test -p wardnet-agent-artifact-admission --test audit_contract
```

- [ ] **Step 4: Implement sinks**

`FileAuditSink` serializes writers with `std::sync::Mutex`, opens with append/create, writes one bounded line, flushes, and calls `sync_data`. `MemoryAuditSink` stores records for embedding/tests. Neither sink logs paths or payloads in errors returned to clients.

- [ ] **Step 5: Run and verify GREEN**

```bash
cargo test -p wardnet-agent-artifact-admission --test audit_contract
```

- [ ] **Step 6: Commit**

```bash
git add crates/agent-artifact-admission/src/audit.rs crates/agent-artifact-admission/tests/audit_contract.rs

git commit -m "feat(security): persist minimized admission audit evidence"
```

### Task 5: Add configuration, credentials, and strict CLI

**Files:**
- Create: `crates/agent-artifact-admission/src/config.rs`
- Modify: `crates/agent-artifact-admission/src/lib.rs`
- Create: `crates/agent-artifact-admission/tests/cli_contract.rs`
- Create: `deploy/agent-artifact-admission.example.json`
- Create: `deploy/agent-artifact-admission.credentials.schema.json`

**Interfaces:**
- Produces: `AdmissionServiceConfig`, `CredentialFile`, `CliArgs`, `parse_cli_args`, `load_config`, `load_admin_token`, `validate_service_config`

- [ ] **Step 1: Add failing config tests**

Reject unsupported version, non-loopback bind, zero/oversized body limit, missing audit path, duplicate policy entries, forbidden allowlisted executable, malformed artifact/manifest identity, and empty/short/oversized credential.

- [ ] **Step 2: Add failing CLI tests**

Require exactly one `--config PATH` and one `--credentials PATH`; reject duplicates, missing values, positional arguments, and unknown flags.

- [ ] **Step 3: Run and verify RED**

```bash
cargo test -p wardnet-agent-artifact-admission --test cli_contract
```

- [ ] **Step 4: Implement loading and validation**

Read bounded UTF-8 JSON, reject unknown fields, and return stable non-secret errors. The committed config contains an empty policy and therefore denies all operations.

- [ ] **Step 5: Run and verify GREEN**

```bash
cargo test -p wardnet-agent-artifact-admission --test cli_contract
```

- [ ] **Step 6: Commit**

```bash
git add crates/agent-artifact-admission/src/config.rs crates/agent-artifact-admission/tests/cli_contract.rs deploy

git commit -m "feat(security): load reviewed admission policy and credentials"
```

### Task 6: Add authenticated HTTP admission API

**Files:**
- Create: `crates/agent-artifact-admission/src/http.rs`
- Create: `crates/agent-artifact-admission/src/main.rs`
- Modify: `crates/agent-artifact-admission/src/lib.rs`
- Create: `crates/agent-artifact-admission/tests/http_contract.rs`

**Interfaces:**
- Produces: `AdmissionState`, `build_app`, `run_service`, `run_cli`, routes `/healthz`, `/v1/policy`, `/v1/admissions`

- [ ] **Step 1: Add failing authentication tests**

Verify missing, duplicate, wrong, non-ASCII, empty, and oversized `X-Admin-Token` return 401. Verify the correct token succeeds. Include equal-length and different-length wrong tokens.

- [ ] **Step 2: Add failing response-semantics tests**

Verify policy block returns 200 and `decision=block`; candidate allow returns 200 only after the audit sink contains the record. Verify malformed authenticated JSON returns audited 400.

- [ ] **Step 3: Add failing audit-outage tests**

Inject a sink that always fails. Both candidate allow and candidate block must return 503 with a block decision and `audit_unavailable`; no caller may receive allow.

- [ ] **Step 4: Run and verify RED**

```bash
cargo test -p wardnet-agent-artifact-admission --test http_contract
```

- [ ] **Step 5: Implement the router and fixed-size constant-time token comparison**

Use Axum `DefaultBodyLimit`. Hash malformed bodies before building the minimized audit record. Move synchronous audit append to `tokio::task::spawn_blocking`.

- [ ] **Step 6: Implement thin process entrypoint**

Parse CLI, load/validate policy and credential files, construct `FileAuditSink`, bind the validated loopback socket, and serve with graceful Ctrl-C/SIGTERM shutdown.

- [ ] **Step 7: Run and verify GREEN**

```bash
cargo test -p wardnet-agent-artifact-admission --test http_contract
cargo test -p wardnet-agent-artifact-admission --test cli_contract
```

- [ ] **Step 8: Commit**

```bash
git add crates/agent-artifact-admission/src crates/agent-artifact-admission/tests

git commit -m "feat(security): expose authenticated artifact admission API"
```

### Task 7: Publish contracts, threat model, and research traceability

**Files:**
- Create: `docs/api/agent-artifact-admission.openapi.yaml`
- Create: `docs/adr/0012-agent-artifact-admission.md`
- Create: `docs/security/agent-artifact-admission.md`
- Create: `docs/doctoring/agent-artifact-admission.md`
- Create: `docs/product-technical-gap-baseline.md`

**Interfaces:**
- Consumes: final service behavior
- Produces: buyer/operator contract and traceability

- [ ] **Step 1: Write OpenAPI 3.1 contract**

Define strict request/response schemas, stable reason codes, authentication, body limit, and 200/400/401/413/503 semantics.

- [ ] **Step 2: Write accepted ADR**

Record why this is a separate Wardnet process, why source text is non-authoritative, why policy is immutable/file-backed in v0.1, and why policy blocks use HTTP 200.

- [ ] **Step 3: Write threat model and operations runbook**

Cover dependency confusion, package hallucination, prompt injection, source poisoning, registry substitution, install scripts, audit outage, bypass, replay, and direct service exposure. Provide integration sequence and incident response.

- [ ] **Step 4: Write APA 7 research/standards note**

Trace decisions to the METAL LAB incident report, OWASP Secure Coding with AI/MCP/Agentic guidance, NIST SSDF, SLSA, TUF, CWE-829, and CWE-494. Do not commit copyrighted papers without redistribution permission.

- [ ] **Step 5: Update product/technical gap baseline**

Record the feature as implemented on the PR head and retain explicit gaps: execution-broker integration, signed policy distribution, transitive graph/SBOM verification, sandbox receipts, durable PostgreSQL outbox, and SIEM projection.

- [ ] **Step 6: Commit**

```bash
git add docs

git commit -m "docs(security): define agent artifact admission operating model"
```

### Task 8: Exact-head verification and PR readiness

**Files:**
- Modify as required by verified findings only

- [ ] **Step 1: Run repository gates**

```bash
cargo fmt --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

- [ ] **Step 2: Run coverage**

```bash
cargo llvm-cov --locked -p wardnet-agent-artifact-admission --all-targets --branch --fail-under-lines 100 --fail-under-branches 100
```

If stable Rust cannot instrument branches, use the repository's date-pinned nightly coverage lane; do not suppress or rewrite failed tests.

- [ ] **Step 3: Inspect security and review evidence**

Read all exact-head CI, Security Scan, Semgrep, CodeQL, fuzz/property, and automated review outputs. Reproduce each actionable finding, fix the root cause, rerun, and resolve only after the exact head contains the fix.

- [ ] **Step 4: Remove all one-shot workflow/bootstrap artifacts**

A temporary lockfile-update workflow may exist only long enough to produce the reviewed `Cargo.lock`; delete it in the same development loop and confirm the final diff contains no self-modifying workflow.

- [ ] **Step 5: Mark ready and enable auto-merge only when truthful**

Required conditions: exact-head checks successful, zero unresolved actionable threads, branch current with `main`, and the live independent approval rule satisfied. Never admin-bypass or self-approve.
