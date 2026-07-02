# Program Completion Baseline Design

## Purpose

The previous delivery completed the published MVP: a Rust Axum gateway with web management, threat scoring, DNSBL export, tests, and CI. This design raises the bar to a program-complete runnable baseline: the service must survive restart with operator-managed state, expose predictable management behavior, and provide a repeatable smoke test that proves the main security control loop works end to end.

## Completion Criteria

The program is complete for this baseline when all of these are true:

1. The service can load and persist routes, threat indicators, DNSBL entries, events, and the next event id through a JSON state file configured by `WAF_IDS_STATE_PATH`.
2. If `WAF_IDS_STATE_PATH` is absent, the service still runs in seeded in-memory mode for demos and tests.
3. The health endpoint reports persistence mode, DNSBL origin, and event retention settings.
4. Management writes require `ADMIN_TOKEN` when configured, validate records, upsert deterministic records, and persist successful changes before returning.
5. Gateway events are retained with a configurable cap and persisted when file-backed state is enabled.
6. DNSBL export uses configurable `DNSBL_ORIGIN` and validates response codes as loopback-style DNSBL addresses.
7. A local smoke script proves health, admin HTML, unauthorized write rejection, authorized route update, block enforcement, KPI/event recording, DNSBL export, and state-file persistence across restart.
8. CI runs formatting, tests, and clippy with warnings denied.
9. Documentation explains run configuration, persistence, smoke testing, architecture, and the remaining production adapters without claiming those adapters already exist.

## Non-Goals

- Do not implement a fake WAF or IDS engine. Coraza/OWASP CRS and Suricata remain real-engine adapters for later work.
- Do not add a database service. JSON state is enough for a standalone baseline and keeps the program easy to run locally.
- Do not expose remote admin as production-safe. TLS, identity proxying, and deployment hardening remain required before internet-facing use.

## Architecture

`src/main.rs` reads operator configuration from the environment and builds an `AppConfig`. `src/lib.rs` owns the Axum app, in-memory state, file-backed persistence, validators, scoring, event recording, and DNSBL export. The state file stores a single serialized `AppData` object so restart behavior can be tested without adding a database dependency.

The management write path is: validate request, mutate state under a write lock, clone the new state, persist the snapshot if configured, and return the accepted object only after persistence succeeds. If persistence fails, the in-memory mutation is rolled back before the API returns `500`. State files are written to a temporary sibling file and then atomically renamed over the configured path to avoid partial JSON on process crash. Gateway event writes use the same consistency path but log persistence failures instead of failing a proxied request after a security decision has already been made.

## Testing

Unit tests cover state load/save, upsert semantics, validators, event retention, DNSBL origin/export, scoring, route selection, and upstream target construction. `scripts/smoke.sh` covers the runnable program from the outside using HTTP calls and a temporary state file.
