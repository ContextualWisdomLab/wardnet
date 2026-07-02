# Program Completion Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the MVP into a standalone program-complete baseline with persistent state, deterministic management writes, smoke verification, and updated CI/docs.

**Architecture:** Keep the app as one Rust Axum binary. Add file-backed JSON persistence behind optional `WAF_IDS_STATE_PATH`, strengthen validators and upserts, retain gateway events with a cap, and prove the end-to-end control loop through a shell smoke test.

**Tech Stack:** Rust 2024, Axum 0.8, Tokio, Serde/Serde JSON, Reqwest rustls, Bash/curl for smoke verification, GitHub Actions CI.

## Global Constraints

- Keep the project Rust-first for gateway, DNSBL, and high-throughput control-plane code.
- Do not implement fake WAF/IDS engines; keep Coraza/OWASP CRS and Suricata as future real adapters.
- Default bind address remains `127.0.0.1:8080`.
- `ADMIN_TOKEN` protects management writes when configured.
- `WAF_IDS_STATE_PATH` is optional; absence means seeded in-memory mode.
- CI must run `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --locked -- -D warnings`.

---

### Task 1: Runtime Configuration And Persistence

**Files:**
- Modify: `src/main.rs`
- Modify: `src/lib.rs`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `AppConfig { admin_token, state_path, dnsbl_origin, event_limit }`
- Produces: `AppState::load(config: AppConfig) -> Result<AppState, String>`
- Produces: `AppState::seeded(admin_token: Option<String>) -> AppState` for existing tests

- [x] Add environment parsing for `WAF_IDS_STATE_PATH`, `DNSBL_ORIGIN`, and `EVENT_LIMIT`.
- [x] Serialize/deserialize `AppData`.
- [x] Load state from JSON file when configured; seed and write the file when it does not exist.
- [x] Persist successful management writes.
- [x] Persist gateway events when file-backed state is enabled.
- [x] Ignore local runtime state files under `.gitignore`.

### Task 2: Management Semantics And Validation

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `upsert_route`, `upsert_threat`, `upsert_dnsbl`
- Produces: `validate_threat`, `validate_dnsbl`

- [x] Route writes upsert by `id`.
- [x] Threat writes upsert by `indicator_type`, `value`, and `source`.
- [x] DNSBL writes upsert by `address`.
- [x] Reject empty threat fields and zero TTL.
- [x] Reject DNSBL codes outside `127.0.0.0/8`.
- [x] Use configured DNSBL origin in `/dnsbl/zone`.

### Task 3: Event Retention And Health Reporting

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `HealthStatus`
- Produces: `record_event` retention behavior using `event_limit`

- [x] Cap stored events to `EVENT_LIMIT`.
- [x] Include `persistence`, `dnsbl_origin`, and `event_limit` in `/healthz`.
- [x] Update KPI `gateway_mode` text from MVP wording to program-complete baseline wording.

### Task 4: Tests And Smoke Verification

**Files:**
- Modify: `src/lib.rs`
- Create: `scripts/smoke.sh`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `scripts/smoke.sh`

- [x] Add unit tests for JSON persistence, upserts, validation, health config, event cap, and DNSBL origin behavior.
- [x] Add a smoke script that starts the binary with a temporary state file and verifies health, admin, auth rejection, route upsert, block mode, KPIs, DNSBL zone export, and restart persistence.
- [x] Add clippy to CI.

### Task 5: Documentation And Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Create: `docs/runbooks/operations.md`

**Interfaces:**
- Consumes: features from Tasks 1-4

- [x] Document completion criteria and runtime environment.
- [x] Document state-file behavior and smoke testing.
- [x] Document production limits and next real-engine adapters.
- [x] Run `cargo fmt --check`, `cargo test --locked`, `cargo llvm-cov --workspace --all-features --fail-under-lines 100 --show-missing-lines`, `cargo clippy --locked -- -D warnings`, `actionlint`, and `scripts/smoke.sh`.
- [ ] Push a PR, wait for required checks, merge, and verify zero open PRs.
