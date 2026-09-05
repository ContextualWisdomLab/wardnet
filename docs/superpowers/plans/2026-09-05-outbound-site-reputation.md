# Outbound Site Reputation Implementation Plan

> **For agentic workers:** Execute one bounded task at a time with the executing-plans or subagent-driven-development workflow. Record a failing test before its causal implementation; retain exact-head review and validation evidence. Unchecked items below are planned work, not completed code.

**Goal:** Make outbound destination security reputation an explainable Wardnet admission capability.
**Architecture:** A pure Rust reputation core consumes immutable canonical evidence. Wardnet adapters own authenticated policy/SOC use cases; a released EgressWeave boundary owns actual safe transport.
**Tech Stack:** Rust workspace, versioned serialized contracts, existing Wardnet management and credential boundaries. No dependency is added by this documentation PR.
**Spec:** [Product and technical design](../specs/2026-09-05-outbound-site-reputation-design.md).

## Global constraints

Use the [ADR](../../adr/2026-09-05-outbound-site-reputation-engine.md) and [source register](../../papers/outbound-site-reputation-sources.md). Start each implementation slice from then-current protected `main`, not a preservation branch. Proposed paths below must be reconciled with protected renames before creation.

No duplicated DNS/redirect/proxy/TLS/resource authority, mutable sibling dependency, raw runtime environment read, WAF-score reuse, or unreviewed detector. No engine implementation, tests, API, or deployment is supplied by this documentation PR. No code coverage or production readiness is claimed.

Tasks 1-3 can develop offline before EgressWeave releases its Rust-consumer boundary. Task 5 and protect deployment require [EgressWeave #237](https://github.com/ContextualWisdomLab/EgressWeave/issues/237) or an immutable compatible successor. Missing contract support must not be replaced with local `reqwest` authorization logic. Configuration/authentication/durable-state prerequisites remain their canonical Wardnet owner lanes (#140, #155, #80/#81); adopt protected implementations rather than copying open PR code.

## Task 1: Versioned domain contracts and fixture harness

**Create:** `crates/wardnet-reputation-core/{Cargo.toml,src/lib.rs,src/model.rs,tests/contract.rs}` and `tests/fixtures/reputation/v1/`.
**Modify:** root `Cargo.toml` workspace membership and lockfile only as required.
**Consumes:** reviewed spec, canonical offline fixtures, injected evaluation time.
**Produces:** `DestinationContextV1`, `EvidenceRecordV1`, `SourcePolicyV1`, `PolicySnapshotV1`, `DecisionEnvelopeV1`, and typed validation errors. No network-facing URL parser.

- [ ] Add RED serialization/validation tests rejecting wrong direction, unknown schema, blank workload/purpose, missing required-source policy, invalid time ordering, and ambiguous subject scope. Assert round-trip stability on a synthetic exact-host fixture.
- [ ] Run `cargo test -p wardnet-reputation-core --test contract`; record the missing-contract failures before adding production models.
- [ ] Implement closed enums, bounded fields, and fallible constructors with injected time. Keep identity verification outside caller-controlled deserialization.
- [ ] Repeat the focused test, then all workspace gates below. Commit only this contract/harness slice.

Fixture convention: every case includes `case_id`, fixed `now_unix`, canonical profile ID, authenticated context, source policy, evidence, expected assessment/action/reason, and expected visibility. Use reserved synthetic domains and test networks only. The integration harness must explicitly allow its loopback fixtures; no live malicious service is contacted.

## Task 2: Source lifecycle and immutable evidence snapshots

**Create:** core `src/evidence.rs`, `tests/evidence_lifecycle.rs`; adapter `src/reputation/{mod.rs,ingest.rs,snapshot.rs}`.
**Consumes:** Task 1 contracts and authenticated source envelopes.
**Produces:** validated source batches, monotonic source versions/tombstones, atomic `EvidenceSnapshotV1` generations with required-source health.

- [ ] Add RED cases for reimport/304 rejuvenation, expiry during cache lifetime, old-version replay after revocation, incomplete pagination, malformed/empty failure response, and failed replacement preserving valid last-known-good records.
- [ ] Add distinct tests for a complete authenticated empty snapshot versus an incomplete delta. Require atomic rejection rather than partially publishing a malformed batch.
- [ ] Implement source-specific admission, validity and lineage rules. Preserve confidence/markings and provenance; reject unsupported indicator syntax. Confirm MISP affirmative `to_ids` plus attribute/object lifecycle and source severity against protected successors to #167/#170 before enabling that adapter.
- [ ] Run focused lifecycle tests and workspace gates. Commit only evidence lifecycle and its adapters. Network refresh remains disabled until Task 5; use imported authenticated fixtures meanwhile.

## Task 3: Matching, policy lattice, and bounded cache

**Create:** core `src/{matching.rs,policy.rs}`, `tests/{matching.rs,policy.rs}`; adapter `src/reputation/cache.rs`.
**Consumes:** validated canonical context, policy, evidence snapshot, injected time.
**Produces:** deterministic `evaluate(context, policy, evidence, now) -> DecisionEnvelopeV1`; cache entries cannot bypass revalidation.

- [ ] Write RED table-driven tests for the acceptance matrix below. In particular, no-match is unknown, business allow cannot defeat hard deny, and duplicate syndicated evidence cannot change a decision by arithmetic accumulation.
- [ ] Implement exact subject matching, explicit subdomain scope, source eligibility, stable reasons, and deny precedence. No substring or registrable-domain widening; no `BLOCK_SCORE` reuse.
- [ ] Implement tenant/context/revision-bound cache keys, finite cardinality, minimum expiry, and invalidation. Add property tests: unrelated tenant evidence never changes a result; record permutation preserves a decision; adding a duplicate never raises confidence.
- [ ] Run focused tests and workspace gates, then commit. Add libFuzzer targets and stable property mirrors for the new untrusted structures in a Wardnet-owned fuzz change; do not copy central workflows.

## Task 4: Authenticated evaluation and accountable policy administration

**Create:** `src/reputation/{api.rs,application.rs,audit.rs}` and `tests/reputation_api.rs`.
**Modify:** `src/lib.rs` only for module/router wiring after the core boundary stabilizes.
**Consumes:** Task 3 evaluator, protected identity/configuration/storage capabilities.
**Produces:** the proposed `/api/v1/egress/reputation/*` surfaces, revisioned policy/exception state, immutable decision records, and separate enforcement-outcome correlation.

- [ ] Add RED tests: forged tenant/workload, evaluator attempting policy mutation, stale If-Match, expired exception, secret-bearing input redaction, and HTTP 200 with deny not yielding a grant.
- [ ] Test 400/401/403/429/503 paths and audit-capacity exhaustion: none may produce protected authorization. A pure evaluation result cannot self-assert actual enforcement.
- [ ] Implement role-scoped handlers and authenticated, audience-bound grant handling at the adapter. Require durable audit reservation before protected allow. Reuse the canonical registry/outbox; do not substitute process-local state for production evidence.
- [ ] Run focused HTTP tests and workspace gates, document operator procedures, and commit this service slice. Keep live protect capability disabled.

## Task 5: Released transport contract and real enforcement

**Create:** `src/reputation/egress_acl.rs`, `tests/reputation_egress_contract.rs`, and `tests/reputation_enforcement.rs`.
**Consumes:** an immutable compatible EgressWeave release, Task 4 decisions, authenticated PEP context.
**Produces:** an owner-backed pre-connect/pre-send gate with actual-peer and per-hop correlation. The exact foreign API is selected by its owner, not invented in this plan.

- [ ] Verify release/schema/artifact identity, provenance, compatibility, end-to-end deadline, and peer-bound execution guarantees. If any is absent, leave integration unavailable; continue offline work only.
- [ ] Port the useful hostile requirements from #136 as black-box consumer vectors, not its local transport implementation. Preserve Wardnet-owned source refresh behavior from #115 through the released ACL, not its direct client.
- [ ] Start controlled DNS/HTTP fixtures and record RED tests for rebinding, mixed peers, malicious second redirect, ambient proxy influence, pool/coalesced-origin reuse, stale/replayed grants, and stalled DNS exceeding the whole operation deadline.
- [ ] Implement the thin ACL and PEP composition. Require zero denied-destination connections/payload hits as appropriate, not merely a deny response after transmission.
- [ ] Verify 60-second maximum protected tunnel lease and denial propagation, transport outage fail-closed behavior, and incompatible release rejection. Run all gates and commit without deploying automatically.

## Task 6: Operations, coverage, and controlled activation

**Create:** `docs/runbooks/outbound-site-reputation.md`, `tests/reputation_rollout.rs`, and reproducible load/replay fixtures under `tests/fixtures/reputation/`.
**Consumes:** Tasks 1-5, deployment egress inventory, reviewed benign/malicious evaluation corpora.
**Produces:** measured protection scope, SLO evidence, rollback procedure, and audited activation decision.

- [ ] Add RED acceptance for audit/outbox saturation, feed outage/recovery, policy rollback without tombstone resurrection, and secret-free exports.
- [ ] Test opaque CONNECT URL-inspection refusal, direct exits, unauthorized DNS/DoH/DoT, QUIC and proxy bypasses against the actual deployment. Unsupported paths remain uncovered or blocked, never implicitly protected.
- [ ] Measure the spec's one-million-indicator/1,000-evaluation-per-second benchmark with hardware, memory and p99 recorded. Separately report detection/false-positive/unknown rates and actual PEP enforcement coverage; shadow events do not count as prevention.
- [ ] Execute offline replay, monitor, and a small protect canary. Expand only after analyst-reviewed false positives, exact-head security evidence, denied-target zero-hit tests, outage drills, and rollback verification.
- [ ] Hand the final feature/evidence links to the existing #130 product-gap ledger owner without editing its path in a competing lane.

## Acceptance matrix

| ID | Hostile or realistic input | Required observation |
| --- | --- | --- |
| REP-01 | Active eligible C2/phishing indicator plus business allow | Hard deny; zero denied-target payload hits |
| REP-02 | No eligible match | Unknown, not safe; protect denies without scoped authorization |
| REP-03 | Expired/revoked evidence reimported or HTTP 304 received | No renewed eligibility; required-source failure cannot allow |
| REP-04 | MISP invalid/missing `to_ids` or deleted enclosing Object | No admitted enforcement indicator |
| REP-05 | Older source version after tombstone; truncated replacement | No resurrection or partial snapshot publication |
| REP-06 | Similar suffix, sibling shared host, CNAME alias | Exact scope respected; no blanket host condemnation |
| REP-07 | Cross-tenant cache or forged context/grant | Deny; no foreign evidence disclosure |
| REP-08 | Good first hop redirects to malicious second hop | No second-hop payload; separately correlated decisions |
| REP-09 | DNS peer changes, mixed A/AAAA, mapped address alias | Actual peer bound; no unchecked fallback |
| REP-10 | Policy/evidence update during cached or pooled request | Revalidation; no stale positive authorization |
| REP-11 | CONNECT without URL visibility | No full-URL claim; URL-required profile denies |
| REP-12 | Evaluator/transport/audit outage or exhausted bound | Stable fail-closed reason; no grant |
| REP-13 | 200 deny envelope, replayed nonce, wrong audience | No authorization based on status or copied receipt |
| REP-14 | Optional feed outage with healthy required sources | Explicit degraded health; policy still deterministic |
| REP-15 | Direct/alternate egress path bypass attempt | Network block or explicit uncovered classification |
| REP-16 | Secret-bearing URL, cookie, source credential | No secret in logs, exports, error text or provider query |
| REP-17 | Newly denied persistent connection | Terminated within supported 60-second lease bound |
| REP-18 | Duplicate/permuted syndicated evidence | No manufactured independent votes or probability |

## Verification and merge discipline

Every code slice must record focused RED then GREEN results and run:

```bash
cargo fmt --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Add the affected stable property tests and libFuzzer evidence, source/dependency/security scans, and deployment conformance where applicable. Re-read the exact PR head, protected base, reviews, unresolved threads, and required checks before any merge. Queued, skipped, stale, or absent evidence is not passing. Do not force-push, self-approve, weaken gates, merge a preservation branch wholesale, or consume a mutable foreign dependency.
