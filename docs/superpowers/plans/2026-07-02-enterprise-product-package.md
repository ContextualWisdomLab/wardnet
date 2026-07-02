# Enterprise Product Package Implementation Plan

> **Contributor note:** Execute this checklist task by task. Keep checkbox (`- [ ]`) status current as work moves through implementation, verification, PR, and merge.

**Goal:** Turn the current runnable WAF/IDS/AI SOC baseline into a stronger 2B KRW enterprise product package by adding a maintainable core library boundary and committed product/design/analytics/complexity evidence.

**Architecture:** One Rust workspace. The root crate remains the web-managed gateway and deployment unit. `crates/waf-ids-core` contains deterministic domain logic that future Coraza, Suricata, MISP, TAXII, DNS, and AI SOC adapters can reuse.

**Tech Stack:** Rust 2024, Axum, Tokio, Reqwest with rustls, Serde, Cargo workspace, shell smoke test, GitHub Actions, Scorecard.

---

- [x] Register the concrete Goal for autonomous execution.
- [x] Use Figma to produce the FigJam architecture artifact without Figma Code Connect.
- [x] Use Product Design to define operator and buyer workflows for the console, readiness, feed operations, and support bundle.
- [x] Use Ponytail to decide the smallest useful complexity reduction.
- [x] Use Data Analytics to define sale-readiness and SOC value metrics.
- [x] Select a local workspace crate instead of a git submodule.
- [x] Add `crates/waf-ids-core` and move pure domain logic into it.
- [x] Commit Figma, Product Design, Ponytail, Data Analytics, Superpowers, README, and architecture documentation.
- [x] Run full local verification: format, workspace tests, coverage gate, clippy, actionlint, smoke, and diff check.
- [ ] Publish a PR and address real review/check findings.
- [ ] Merge after checks are green or only review-process latency remains.
- [ ] Verify main branch CI, Scorecard, and open PR count.
