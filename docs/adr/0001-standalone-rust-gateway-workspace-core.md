# ADR 0001: Standalone Rust gateway with in-workspace `waf-ids-core`

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`README.md` workspace notes;
  `docs/architecture.md` components and security boundaries; root
  `Cargo.toml` workspace members)

## Context

wardnet (crate name `waf-ids-ai-soc`) is the WAF / IDS / AI SOC gateway
and control-plane leaf for ContextualWisdomLab. Operators need a binary
that starts, serves management and gateway HTTP, and scores requests
without checking out sibling products.

Domain logic (models, validation, upserts, scoring, DNSBL zone text,
event retention, feed freshness, KPI snapshots) is reusable. Splitting
that logic into a git submodule before an independently versioned
engine or SDK exists would add release and review overhead without an
external consumer.

Cargo workspaces keep multiple packages on one lockfile and one
`cargo test --workspace` surface (The Cargo Book, n.d.).

## Decision

1. Ship a **standalone Rust gateway**. The process runs by itself with
   optional operator configuration. No sibling checkout is required.
2. Keep reusable domain code in **`crates/waf-ids-core`**, a member of
   the same Cargo workspace (`path` dependency), not a git submodule,
   until an independently versioned engine, SDK, or adapter needs its
   own release lifecycle.
3. Treat sibling ContextualWisdomLab products as **optional composition
   callers** over HTTP or documented contracts:
   - **naruon** and **gyeot** may call or be called when an operator
     wires them; they are not required tree members.
   - **contextual-orchestrator** is the intended front door for the
     optional SOC LLM path. Current `main` exposes the `SocLlmConfig`
     runtime hook, but `run_from_env` does **not** yet wire
     `SOC_LLM_BASE_URL`; absent explicit in-process configuration, SOC
     assist stays off.
   - **Clearfolio** is an optional document-viewer relay target.
     Current `main` exposes the `ClearfolioConfig` runtime hook, but
     `run_from_env` does **not** yet wire `CLEARFOLIO_BASE_URL`;
     absent explicit in-process configuration, that surface stays
     disabled.
   Existing optional caller links stay in place. Do not require those
   services to start the gateway.

## Consequences

- Operators can `cargo run` and use `/admin`, `/gateway/{path}`, and
  `/dnsbl/zone` on a single binary.
- `waf-ids-core` stays free of async/HTTP dependencies so domain tests
  and fuzz mirrors do not pull the Axum crate graph.
- A later submodule or crates.io publish is deferred until a real
  second consumer and release cadence exist.
- Optional Clearfolio and orchestrator hooks must remain inert when
  unconfigured so the leaf stays independently runnable.

## References

The Cargo Book. (n.d.). *Workspaces*.
https://doc.rust-lang.org/cargo/reference/workspaces.html
