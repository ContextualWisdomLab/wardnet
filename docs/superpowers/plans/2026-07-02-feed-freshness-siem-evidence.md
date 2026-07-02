# Feed Freshness and SIEM Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add buyer-verifiable threat-feed freshness and SOC/SIEM event export evidence to the existing 2B KRW product package.

**Architecture:** Keep one Rust workspace. Add deterministic freshness helpers to `waf-ids-core`, keep NDJSON serialization in the root app crate where `serde_json` already exists, expose both through Axum, and verify through tests and smoke.

**Tech Stack:** Rust 2024, Axum, Tokio, Serde, Cargo workspace, shell smoke test, GitHub Actions, FigJam.

## Global Constraints

- Do not use Figma Code Connect.
- Do not add a submodule or new dependency for this tranche.
- Do not create a fake WAF, IDS, SIEM, or scheduler integration.
- Keep the admin console compact and operational.
- Review process latency is not a blocker, but real findings and failing checks must be addressed.

---

- [x] Register the concrete autonomous Goal for this tranche.
- [x] Extend the existing FigJam architecture board with the feed freshness and SOC export evidence flow.
- [x] Add Superpowers spec and implementation plan files.
- [x] Add core freshness classification, KPI counts, readiness TTL semantics, and root NDJSON export.
- [x] Add Axum endpoints, support bundle evidence, admin console surfaces, and tests.
- [x] Update README, architecture, commercial, buyer due-diligence, Product Design, Data Analytics, and Ponytail docs.
- [x] Run local verification: format, workspace tests, coverage gate, clippy, actionlint, smoke, and diff check.
- [ ] Publish PR, address real review/check findings, and merge.
- [ ] Verify main CI, Scorecard, ruleset restoration, and open PR count zero.
