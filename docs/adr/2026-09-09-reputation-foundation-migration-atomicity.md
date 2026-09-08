# ADR 2026-09-09: Keep each reputation forward migration failure-atomic

- Status: Proposed; implementation candidate in Wardnet PR #216, stacked behind #212
- Date: 2026-09-09
- Parent contract: Wardnet PR #212 exact `32b070c3ef2456efc58dc56733531f24fcbaf4f3`
- Issues: #80, #192, #211, #213

## Context

Wardnet's first three PostgreSQL reputation migrations intentionally establish supported boundaries in sequence: 0001 creates immutable tenant-scoped source-generation history and forced RLS, 0002 adds the bounded generation-admission function, and 0003 adds transactional publication history plus the last-known-good head. PR #212 already makes 0003 one explicit transaction.

Fresh review of exact #212 found that 0001 and 0002 still relied on psql's default autocommit behavior. Under PostgreSQL 18, psql commits each successful SQL command when `AUTOCOMMIT` is on unless an explicit transaction block is open. A later statement failure could therefore strand a generation table without its complete RLS/policy contract or an admission function before PUBLIC execution had been revoked. Neither partial state is a supported migration boundary.

This is a schema-evolution invariant owned by Wardnet. It does not move cluster-role lifecycle into migrations, enable PostgreSQL as production state authority, or change EgressWeave, quarantine-sandbox-runtime, contextual-orchestrator, AppGuardrail, Context Graph, or Enterprise Architecture ownership.

## Decision

Each forward reputation migration owns exactly one explicit PostgreSQL transaction:

1. `0001_reputation_source_generation.sql` begins before the generation table is created and commits only after privileges, FORCE RLS, tenant policies, and schema documentation are complete.
2. `0002_reputation_source_generation_admission.sql` begins before the admission function is created and commits only after PUBLIC execution is revoked and the function contract is documented.
3. `0003_reputation_source_publication.sql` retains the transaction boundary established by #212 around its complete publication schema.
4. A failure inside one migration rolls back every object and privilege change owned by that migration while preserving the preceding committed migration boundary.
5. Each migration remains independently replayable from its preceding supported boundary. Recovery does not infer or normalize unknown partial schema.

Migration files remain standalone transaction units. Orchestration must not concatenate them into a caller-owned transaction protocol that changes which `COMMIT` establishes a supported schema boundary.

## Executed RED

PR #216 test-only exact `284ea3c4188f8533416a6ac68cdda6325c5565d6` left production migrations byte-identical to #212 and added deterministic PostgreSQL 18.4 failure injection for 0001 and 0002. Hosted CI `34257768388`, rust job `102167794974`, acquired `ubuntu-24.04`, passed checkout, the pinned Rust toolchain, and `cargo fmt --check`, then failed in `Test`; Clippy was skipped. The parent exact head was already GREEN, so the only child semantic delta was the new hostile migration-atomicity regression.

The 0001 case injects division-by-zero after `CREATE TABLE reputation_source_generation` and requires the table to be absent after failure before clean replay. The 0002 case first applies clean 0001, injects division-by-zero after creation of `wardnet_admit_reputation_source_generation` and before PUBLIC execution revocation, then requires the generation schema to remain while the partial function is absent before clean 0002 replay.

## Alternatives considered

**Rely on `psql -v ON_ERROR_STOP=1`.** Rejected. `ON_ERROR_STOP` stops subsequent commands but does not retroactively roll back prior autocommitted DDL.

**Use `IF NOT EXISTS` or inspect-and-repair partial objects on retry.** Rejected. Presence alone cannot prove exact columns, constraints, RLS policy, grants, function body, ownership, or provenance. Accepting partial state weakens fail-closed migration compatibility.

**Wrap 0001 through 0003 in one cross-file transaction.** Rejected. Each migration is a separately supported schema boundary and recovery prerequisite. Coupling all versions into one transaction would erase the explicit predecessor boundaries used by rollback/reapply and deployment-role reconvergence.

**Move deployment roles into schema migrations.** Rejected. Cluster-role lifecycle remains the separate idempotent deployment boundary established by #208; #210 owns reconvergence after 0003 recovery.

## Consequences

Migration recovery can now reason about complete version boundaries instead of enumerating partial DDL states. The trade-off is that migration runners must respect each file's explicit transaction ownership. The change does not make `StateAuthority::Postgres` production-ready: #80/#192 still own repository wiring, tenant-context pool hygiene, transactional publication integration, crash/retry, backup/restore, and immutable protected release evidence, while #210 owns deployment-role reconvergence after 0003 rollback/reapply.

## References

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Transactions*. https://www.postgresql.org/docs/18/tutorial-transactions.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: BEGIN*. https://www.postgresql.org/docs/18/sql-begin.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: psql*. https://www.postgresql.org/docs/18/app-psql.html

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
