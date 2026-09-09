# Wardnet Test Strategy

This document is the code-current test contract for Wardnet-owned production behavior. It complements `AGENTS.md`, `CLAUDE.md`, `docs/fuzzing.md`, `docs/runbooks/operations.md`, and the security threat model. A successful predecessor head is evidence for that predecessor only; any source, test, fixture, documentation, parent, or protected-base movement requires fresh evidence for the resulting exact head.

## Baseline gates

Every candidate that changes Wardnet Rust production behavior must pass, on one unchanged exact head:

- `cargo fmt --check`;
- `cargo test --locked --workspace`;
- `cargo clippy --locked --workspace --all-targets -- -D warnings`;
- repository Fuzz when `src/**`, `crates/**`, or `fuzz/**` changes;
- all then-applicable centrally owned security, SAST, CodeQL, review, coverage, package, SBOM, provenance, branch-integrity, and unresolved-thread gates when they materialize for that topology.

A queued, skipped when required, cancelled, absent, stale-head, or predecessor-head result is not GREEN. Model or bot review is evidence, not human approval.

## Coverage and rustdoc acceptance

Wardnet's commercial-development contract requires 100% owned production statement, branch, edge-case, and rustdoc coverage. `cargo test` alone does not prove this. A release or issue-close claim that depends on the 100% contract must therefore carry explicit exact-head coverage evidence rather than infer coverage from passing tests.

The Rust toolchain includes `llvm-tools-preview`; coverage verification should use `cargo llvm-cov` or the organization-owned equivalent and must include the Wardnet-owned production paths changed by the candidate. Exclusions may cover generated or genuinely unreachable code only when the exclusion is narrow, documented, and does not remove a buyer/security path from the denominator. Rustdoc acceptance requires zero undocumented owned production API items that are in scope for the published contract, with documentation build warnings treated as failures. Synthetic data may support unit tests but cannot replace the real database/network fixtures required below.

Until explicit exact-head coverage and rustdoc evidence exists, the relevant acceptance item remains open even when format, tests, Clippy, and Fuzz are GREEN.

## PostgreSQL reputation-state integration

PostgreSQL state tests use real `postgres:18.4-bookworm`, canonical migrations and role installation, and an externally managed ordinary runtime LOGIN. Tests must preserve tenant/source identity, transaction-local tenant binding, FORCE RLS behavior, publication attribution, idempotency/conflict semantics, and the rule that started database work is never automatically replayed on another connection.

Network-failure acceptance uses a loopback TCP/protocol fault proxy only around runtime connections. The proxy may delay or withhold PostgreSQL protocol responses, but it must not emulate PostgreSQL or fabricate success. Setup/state-owner access remains direct.

For established-session liveness, `tests/postgres_half_open_liveness.rs` is the executable acceptance boundary. One exact-head run must prove all of the following together:

1. At least two established runtime sessions have distinct PostgreSQL backend PIDs and begin without tenant-context residue.
2. A selected established stream may keep its TCP socket open while backend PostgreSQL protocol responses are withheld. The next checkout must bound the non-mutating pre-operation protocol preflight, retire the unresponsive client before reuse, and continue through unrelated established healthy capacity without replaying Wardnet work.
3. If all existing and replacement streams cannot make PostgreSQL protocol progress, checkout fails closed within the repository-owned readiness window with `PoolUnavailable` or a narrower typed liveness result; it does not report readiness.
4. Clearing the fault permits bounded replacement/recovery without process restart, tenant-context residue, or reconnect storm.
5. A slow-but-valid positive control below the configured liveness bound remains accepted; elapsed time alone is never a success/failure oracle.
6. Once a query, transaction, publication, rollback, or COMMIT has begun, the pre-operation failover rule ends. A transport loss while awaiting COMMIT remains the separate `CommitOutcomeUnknown` contract and requires explicit byte-identical reconciliation rather than automatic replay.
7. Buyer-path performance includes PostgreSQL protocol preflight, the actual probe query, and proxy/network cost. Measure at least 200 unexcluded real samples and require p95 <= 20 ms without reconnect churn or a reduced denominator.

TCP keepalive and TCP user timeout are complementary transport controls, not substitutes for the application-protocol progress check. An intermediary can continue acknowledging TCP while withholding PostgreSQL responses.

## Recovery and operability

`docs/runbooks/operations.md` is the operator-facing session-liveness contract. The PostgreSQL physical-recovery lane additionally uses `scripts/postgres_recovery_drill.sh`, `scripts/postgres_recovery_role_mapping_guard.sh`, and the real recovery tests under `tests/postgres_*recovery*.rs`. Recovery evidence from a Draft stack proves only the tested candidate; it does not create production RPO/RTO, storage-provider, encryption-key, IAM, backup-retention, or immutable-release authority.

Production `StateAuthority::Postgres` stays fail closed until the complete prerequisite lineage reaches protected truth and the release candidate proves the then-live backup/WAL, storage/encryption/IAM, recovery/SLO, security, coverage, package, SBOM, provenance, reproducibility, and rollback contracts on one immutable source/artifact identity.

## Performance evidence

Performance claims must measure the real buyer path rather than a helper-only loop. Do not shrink the sample after seeing failures, exclude slow valid observations, warm an unrealistic cache, or hide database/network setup that production requests must pay. When p95 exceeds 20 ms, profile query, I/O, lock, allocation, runtime, and connection behavior before changing the threshold or architecture.

## Traceability

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2025). *Secure Software Development Framework (SSDF) Version 1.2: Recommendations for mitigating the risk of software vulnerabilities (NIST SP 800-218 Rev. 1, Initial Public Draft).* https://doi.org/10.6028/NIST.SP.800-218r1.ipd — still an Initial Public Draft as of the 2026-09-10 verification; it supplements rather than replaces the final SSDF 1.1 baseline.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Connections and authentication.* https://www.postgresql.org/docs/18/runtime-config-connection.html

tokio-postgres. (2026). *Client in tokio_postgres 0.7.18.* https://docs.rs/tokio-postgres/0.7.18/tokio_postgres/struct.Client.html

Eggert, L., & Gont, F. (2009). *TCP user timeout option (RFC 5482).* RFC Editor. https://www.rfc-editor.org/rfc/rfc5482