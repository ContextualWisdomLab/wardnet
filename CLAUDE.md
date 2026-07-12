# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Read `AGENTS.md` first** — it is the canonical agent operating guide for this repository. Its guardrails (Rust-first, integrate proven security engines instead of inventing detections, keep MVP scope narrow, run `cargo fmt --check` and `cargo test` before claiming code is ready) override anything else. This file complements it with commands and architecture.

## What This Is

wardnet (crate name `waf-ids-ai-soc`) is a Rust-first WAF/IDS/AI SOC gateway and control-plane baseline for ContextualWisdomLab: web-managed API gateway routes, request scoring from threat indicators and DNSBL entries, monitor/block enforcement, RFC 5782-style DNSBL zone export, SOC event/KPI APIs, commercial readiness evidence APIs, and an embedded admin console at `/admin`. It deliberately does not reimplement a full WAF/IDS/SIEM — production coverage is meant to come from adapters to proven engines (OWASP CRS/Coraza, Suricata, STIX/TAXII, MISP/OpenCTI).

## Commands

CI (`.github/workflows/ci.yml`) gates on exactly these three:

```bash
cargo fmt --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Other common commands:

```bash
cargo run                                  # serve on 127.0.0.1:8080; open /admin
cargo test --workspace <test_name_filter>  # run a single test by name
cargo test -p waf-ids-core                 # test only the core crate
scripts/smoke.sh                           # end-to-end smoke: boots the binary, exercises the API, verifies restart persistence
```

Fuzzing (requires nightly + cargo-fuzz; see `docs/fuzzing.md`):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_score_request -- -max_total_time=60
# targets: fuzz_score_request, fuzz_appdata_json, fuzz_parse_admin_tokens, fuzz_dnsbl_zone
```

`.github/workflows/fuzz.yml` smoke-fuzzes each target for 60s on PRs touching `src/**`, `crates/**`, or `fuzz/**` (300s nightly). Crashing inputs are uploaded as artifacts.

## Toolchain

`rust-toolchain.toml` pins the `stable` channel with `llvm-tools-preview` (needed by `cargo llvm-cov`), `rustfmt`, and `clippy`. Both workspace crates use `edition = "2024"`. Fuzzing is the one exception that needs nightly.

## Workspace Layout

Root Cargo workspace with two members (resolver 3):

- `crates/waf-ids-core` — pure domain crate, no async/HTTP deps (only `serde` + `percent-encoding`): models, validation, upserts, request scoring, DNSBL zone formatting, event retention, threat-feed freshness, KPI snapshots, commercial readiness, buyer evidence manifests.
- Root crate `waf-ids-ai-soc` (`src/lib.rs`) — Axum management API, embedded admin console, optional JSON state persistence, upstream proxying, NDJSON event export, support bundle assembly, plus the in-crate HTTP tests. Depends on `waf-ids-core`.
- `src/main.rs` — deliberately thin shim over `waf_ids_ai_soc::run_from_env` so all config/serve logic is unit-testable; covered end-to-end by `tests/binary.rs` (SIGTERM graceful shutdown).
- `fuzz/` — a **separate** cargo workspace (empty `[workspace]` table in `fuzz/Cargo.toml` — do not remove) so root `cargo test --workspace` never builds fuzz targets. Seed corpora live in `fuzz/corpus/<target>/`.

The core stays an in-repo workspace crate on purpose (no git submodule) until it has an independent release cadence.

## Tests

- In-crate HTTP tests: `#[cfg(test)]` module in `src/lib.rs` (uses `tower::ServiceExt` to drive the Axum app). Tests that mutate env vars serialize on `ENV_GUARD`.
- E2E binary test: `tests/binary.rs`.
- Property-test mirrors of the fuzz invariants (run on stable in normal CI): `tests/fuzz_invariants.rs` and `crates/waf-ids-core/tests/fuzz_invariants.rs` (proptest).
- External smoke: `scripts/smoke.sh`.

## Runtime Configuration

Read in `run_from_env` (`src/lib.rs`): `BIND_ADDR` (default `127.0.0.1:8080`), `ADMIN_TOKEN` (write token for `X-Admin-Token`), `ADMIN_TOKENS` (comma-separated `token:actor` pairs for multi-token RBAC with per-token audit actors), `WAF_IDS_STATE_PATH` (optional JSON state file; omitted = seeded in-memory state), `DNSBL_ORIGIN` (default `dnsbl.local`), `EVENT_LIMIT` (default 1000, must be > 0), `RATE_LIMIT` / `RATE_LIMIT_WINDOW`.

## Key Conventions

- Management writes require `X-Admin-Token` and are **upserts**: routes keyed by `id`, threat indicators by `indicator_type` + `value` + `source`, DNSBL entries by `address`. DNSBL response codes must be in `127.0.0.0/8`.
- State persistence uses write-to-temp-sibling + atomic rename; management API mutations roll back in memory if the state file cannot be replaced.
- Audit logs must never leak admin tokens (`scripts/smoke.sh` asserts this).
- Untrusted-input surfaces (request scorer, state deserializer, admin-token parser, DNSBL zone export) are fuzzed; if you change one, keep its libFuzzer target and proptest mirror in sync (`docs/fuzzing.md` lists the invariants per target).
- Block mode is route-scoped; default bind is localhost. See `docs/architecture.md` for security boundaries and the near-term adapter roadmap.
- Deployment assets: `Dockerfile` (two-stage build, pinned base images, runs as non-root `wafids`), `deploy/docker-compose.yml`, `deploy/kubernetes/waf-ids-ai-soc.yaml`.

## Further Docs

- `docs/architecture.md` — component map, security boundaries, integration roadmap.
- `docs/fuzzing.md` — fuzz target table and invariants.
- `docs/commercial/20b-krw-sale-readiness.md` — formal acceptance criteria behind the commercial readiness APIs.
- `docs/runbooks/operations.md`, `docs/security/threat-model.md`.
