# ADR 2026-09-09: Re-converge publication authority separately from publication evidence after rollback/reapply

- Status: Proposed; implementation candidate in Wardnet PR #217, pending stacked integration and protected release
- Date: 2026-09-09
- Parent contract: Wardnet PR #216 exact `7c7b980b7a2f41e2a369a71bb32e945de7f30bfd`
- Issues: #80, #192, #210

## Context

Wardnet's PostgreSQL reputation publication boundary deliberately separates schema migration from deployment-time cluster-role ownership. Migration `0003_reputation_source_publication.sql` creates the publication tables and the `SECURITY DEFINER` outer capability, while `deploy/postgresql/reputation_state_roles.sql` owns the idempotent least-privilege convergence of `wardnet_state_owner` and `wardnet_runtime`.

The rollback contract in PR #209 intentionally removes the 0003 publication function, immutable publication rows and last-known-good head while preserving the 0001 generation identities and 0002 admission capability. A subsequent 0003 reapply therefore recreates the outer function under the migration principal. Merely observing that the schema exists is not sufficient recovery evidence: the bounded state-owner function ownership and runtime EXECUTE grant are absent until deployment authority is reconverged.

There is a second, distinct failure mode. Because the supported 0003 rollback removes publication history and the last-known-good head, authority recovery cannot safely infer or manufacture lost publication evidence from the surviving generation table. A durable generation identity proves only that a token/ordinal/provenance binding was admitted. It does not prove that the corresponding evidence snapshot, completeness proof and producer lifecycle were the last published state. Treating the highest surviving generation as an automatically recovered head would convert incomplete data into security authority.

## Decision

Wardnet separates recovery into two ordered responsibilities.

1. **Schema recovery** applies the supported forward migrations. Each 0001–0003 forward migration owns an explicit transaction and must leave either its complete supported boundary or the preceding supported boundary.
2. **Publication-authority recovery** runs `deploy/postgresql/reputation_state_recovery.sql` after 0003 reapply. The recovery artifact is sequencing only: it enables `ON_ERROR_STOP` and includes the canonical `reputation_state_roles.sql` with psql `\ir`, so role/grant/ownership truth remains single-sourced.
3. The canonical role installer remains one transaction. A deterministic failure before ownership transfer must not be reportable as recovered authority; the recreated outer function remains outside the state-owner boundary and runtime EXECUTE remains absent.
4. Successful authority recovery must restore exactly the #208 least-privilege contract: bounded `NOLOGIN`/`NOSUPERUSER`/`NOBYPASSRLS` state-owner ownership, hardened `SECURITY DEFINER` search path, no PUBLIC execution, runtime bounded reads plus outer EXECUTE only, no direct generation/publication/head mutation, no inner-admission EXECUTE, and no retained schema `CREATE`.
5. **Authority recovery does not restore publication evidence.** If rollback removed publication rows/head, a call that claims an expected prior generation must continue to fail closed until publication evidence is explicitly restored from an authoritative backup/evidence source or replayed through the recovered outer capability with its original evidence/completeness/lifecycle references.
6. Once the prior publication evidence is explicitly restored through the outer capability, the next generation may advance last-known-good state only through the existing exact-prior and monotonic-ordinal transaction contract. Recovery replay must remain idempotent.
7. `StateAuthority::Postgres` remains fail closed. PR #217 does not supply production login/principal membership, repository wiring, pool checkout/reset tenant context, crash/retry, backup/restore orchestration or immutable protected release evidence; those remain #80 completion work.

This order distinguishes **schema exists**, **authority is reconverged**, **publication evidence is restored**, and **production state authority is enabled**. None of those states implies the next one.

## Alternatives considered

**Duplicate role/grant SQL in the recovery script.** Rejected. It creates a second mutable source for a security boundary already owned by `reputation_state_roles.sql` and invites privilege drift. Relative psql inclusion keeps the recovery artifact executable without duplicating that contract.

**Move cluster-role creation into migration 0003.** Rejected. Database-cluster role lifecycle and application-schema evolution require different deployment privileges and rollback semantics. Reapply of an application migration must not silently become credential or cluster-IAM provisioning.

**Infer the last-known-good head from the highest surviving generation ordinal.** Rejected. Generation admission does not contain `evidence_snapshot_ref`, `completeness_ref`, or `producer_lifecycle_ref`, and a generation can exist without proving that it was the last evidence-complete publication. Automatic inference would manufacture authoritative security evidence.

**Permit a post-recovery publication to name a surviving generation as expected prior even when no publication head exists.** Rejected. That weakens exact-prior compare-and-swap semantics precisely during recovery, when provenance requirements should be strongest.

**Restore authority and publication data in one generic SQL script.** Rejected for this slice. Publication data restoration requires an authoritative backup/evidence source and declared RPO/RTO semantics owned by #80; a static deployment artifact does not have enough information to reconstruct those records safely.

## Executed evidence

PR #217 first established the recovery-order RED at exact `3999f0583eddfe87bc07b7ef477998a66fefe246`. Hosted CI `34259899229` / rust job `102174943790` acquired a real `ubuntu-24.04` runner, passed checkout/toolchain/formatting, and failed in `Test` because `deploy/postgresql/reputation_state_recovery.sql` did not exist. That is the causal executable recovery-boundary RED, not runner/bootstrap noise.

The first minimal sequencing candidate `ffbd6adb19a3d239c2c75b851ac3da76429bb67b` added only the recovery script and reused the canonical installer through `\ir`. Hosted CI `34260588614` / rust job `102177249781` proved that ownership and least-privilege grants were restored, then failed when the test attempted to publish generation 2 against `generation-1` as an expected prior even though the supported rollback had intentionally removed publication history/head. PostgreSQL returned `reputation_source_publication_conflict`. This exposed a test-oracle error rather than a reason to synthesize missing evidence.

Exact `9834f74c7c28dfbff121747e94970e3c599b3bf1` corrected the recovery acceptance to keep that evidence gap fail closed: generation 2 must conflict until generation 1 publication evidence is explicitly replayed through the recovered outer capability; generation identity is not duplicated; generation 2 then advances through exact-prior publication; and the role recovery script replays idempotently. Hosted CI `34261138199` / rust job `102179084308` completed SUCCESS through formatting, all locked workspace tests including real PostgreSQL 18.4 recovery, strict Clippy and cleanup.

These are feature-branch receipts. They do not authorize production PostgreSQL state or release until the stack is integrated on protected truth and all then-live gates are freshly successful.

## Consequences and follow-up

The deployment runbook gains an explicit sequencing unit and a clearer failure model: operators can distinguish a recovered schema from recovered privileges and from recovered publication data. The cost is that a destructive rollback of 0003 requires an authoritative publication-data restore/replay step before new exact-prior publications can continue. That cost is intentional; Wardnet does not trade evidence integrity for automatic recovery convenience.

#80 must still define and execute backup/restore artifacts, retention/encryption authority, RPO/RTO, production principal mapping, pooled transaction-local tenant context and crash/retry behavior. A restore drill must prove publication history/head and generation identity are semantically consistent before readiness can become true. #192 remains the reputation-specific durable uniqueness/atomicity contract.

## References

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5), AC-6 Least Privilege and CP-10 System Recovery and Reconstitution. https://doi.org/10.6028/NIST.SP.800-53r5

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: psql*. https://www.postgresql.org/docs/18/app-psql.html — `\ir` resolves a relative include from the script's directory, allowing the recovery sequencer to reuse the canonical adjacent role installer independently of the caller's working directory.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Transactions*. https://www.postgresql.org/docs/18/tutorial-transactions.html — explicit transactions provide the all-or-nothing boundary relied on by the forward migrations and role installer.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html — superusers and `BYPASSRLS` roles bypass row security; the recovered state-owner/runtime contract therefore remains explicitly non-bypass.
