# WAF IDS AI SOC MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish the initial ContextualWisdomLab WAF/IDS/AI SOC MVP repository.

**Architecture:** A single Rust Axum binary provides web management, gateway request decisioning, event/KPI surfaces, and DNSBL zone export. Future production security engines are adapters, not fake in-tree replacements.

**Tech Stack:** Rust 2024, Axum, Tokio, Reqwest with Rustls, Serde, GitHub Actions.

## Global Constraints

- Bind to `127.0.0.1:8080` by default.
- Write APIs accept optional `ADMIN_TOKEN` through `X-Admin-Token`.
- Figma Code Connect is not used.
- Use real engines as follow-up adapters: Coraza/OWASP CRS for WAF, Suricata for IDS, STIX/TAXII plus MISP/OpenCTI for threat intelligence, Hickory DNS for authoritative DNSBL serving.
- Run `cargo fmt --check` and `cargo test` before handoff.

---

### Task 1: Rust Service Scaffold

**Files:**
- Create: `src/lib.rs`
- Modify: `src/main.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: `build_app(AppState) -> Router`
- Produces: `AppState::seeded(admin_token: Option<String>) -> AppState`

- [x] Add Axum/Tokio/Serde/Reqwest dependencies.
- [x] Start the server with `BIND_ADDR` and optional `ADMIN_TOKEN`.
- [x] Serve `/admin`, `/healthz`, management APIs, gateway path, and DNSBL zone export.

### Task 2: Gateway Decisioning

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `score_request(...) -> ScoredRequest`
- Produces: `upstream_target(...) -> Result<String, String>`

- [x] Select the longest enabled route prefix.
- [x] Score request path, query, body, and client IP against indicators and DNSBL entries.
- [x] Record monitored or blocked events.
- [x] Proxy HTTP upstreams and support `mock://` upstreams for local smoke use.

### Task 3: DNSBL Publishing

**Files:**
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `reverse_ipv4_for_dnsbl([u8; 4]) -> String`
- Produces: `export_dnsbl_zone(origin: &str, entries: &[DnsblEntry]) -> String`

- [x] Export reversed IPv4 labels.
- [x] Emit `A` and `TXT` records.
- [x] Unit test RFC 5782-style record shape.

### Task 4: Product, Design, Analytics, and Governance Docs

**Files:**
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `AGENTS.md`
- Create: `docs/architecture.md`
- Create: `docs/product-design/admin-console-brief.md`
- Create: `docs/figma/diagram-brief.md`
- Create: `docs/analytics/soc-kpis.md`
- Create: `docs/goals/2026-07-02-initial-mvp-goal.md`

- [x] Document run commands, API examples, and roadmap.
- [x] Document Product Design admin-console surfaces.
- [x] Document Figma diagram plan without Code Connect.
- [x] Document SOC KPI model.
- [x] Document concrete MVP goal and acceptance criteria.

### Task 5: CI and Publication

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/scorecard-analysis.yml`
- Create: `.github/dependabot.yml`
- Create: `LICENSE`

- [x] Add CI for formatting and tests.
- [x] Add Scorecard workflow and Dependabot baseline.
- [x] Run final local verification.
- [x] Create `ContextualWisdomLab/waf-ids-ai-soc` if absent.
- [x] Push the initial implementation to `main`.
