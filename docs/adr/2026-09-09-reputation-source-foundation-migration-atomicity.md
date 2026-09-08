# ADR 2026-09-09: Make every reputation-source foundation migration failure-atomic

- Status: Proposed; implementation candidate in Wardnet PR #214, pending stacked integration and protected release
- Date: 2026-09-09
- Parent decision: `docs/adr/2026-09-08-reputation-source-publication-transaction-boundary.md`
- Parent contract: Wardnet PR #212 exact `32b070c3ef2456efc58dc56733531f24fcbaf4f3`
- Issues: #80, #192, #213

## Context

Wardnet's durable reputation state is introduced as three ordered PostgreSQL migrations: 0001 creates immutable tenant-scoped generation history and forced RLS, 0002 adds the idempotent admission capability, and 0003 adds immutable publication history plus last-known-good advancement. PR #212 already makes 0003 one explicit transaction, but 0001 and 0002 still relied on psql's default autocommit behavior.

That leaves unsupported intermediate states. If 0001 fails after `CREATE TABLE`, the table can survive without its final privilege and forced-RLS boundary. If 0002 fails after `CREATE FUNCTION`, the admission capability can survive before PUBLIC execution is revoked. A retry then starts from a state that is neither the preceding supported migration boundary nor the completed next boundary.

PR #214 established this defect with real PostgreSQL 18.4 tests before changing production migrations. Exact test-only head `cd8e3bba743687a7519be5778712581b0ac95814` ran hosted CI `34253963457` / rust job `102154944649`: checkout, pinned toolchain and formatting passed, then the PostgreSQL failure-injection tests failed in `Test`; Clippy was skipped. The fixtures inject deterministic division-by-zero after the first durable DDL in each migration and require the failed migration to leave no migration-owned partial object behind.

## Decision

Each Wardnet-owned reputation-source forward migration is an independent atomic unit and owns an explicit PostgreSQL transaction boundary.

1. Migration 0001 executes its complete table, privilege, RLS-policy and documentation DDL inside one `BEGIN`/`COMMIT`. Any failure before commit must leave `reputation_source_generation` absent. Clean replay must restore the complete FORCE-RLS generation boundary.
2. Migration 0002 executes its complete admission-function creation, PUBLIC privilege revocation and function documentation inside one `BEGIN`/`COMMIT`. Any failure before commit must preserve committed 0001 while leaving the 0002 admission function absent. Clean replay must restore the function with PUBLIC EXECUTE revoked.
3. Migration 0003 keeps the explicit transaction established by PR #212. A failure in one migration does not roll back an earlier committed migration; it rolls back only the currently executing migration-owned delta.
4. Migration runners must execute each file as its declared atomic unit. They must not strip or reinterpret the transaction boundary, concatenate several migration files into an outer transaction with different commit semantics, or manufacture recovery by accepting unknown partial objects.
5. Production PostgreSQL authority remains fail closed. This decision does not enable `StateAuthority::Postgres`, create cluster roles or credentials, or absorb deployment/recovery responsibilities owned by #80 and the separate role installer.

The minimum causal implementation adds only the missing transaction delimiters to migrations 0001 and 0002. It does not add `IF NOT EXISTS`, partial-state normalization, new privileges, mutable history, cross-service SQL, or foreign-owner behavior.

## Alternatives considered

**Rely on psql autocommit because each DDL statement is individually durable.** Rejected. Individual durability is the defect: a later statement can fail after an earlier object has already committed, leaving a schema state Wardnet never admitted as a supported authority boundary.

**Use `IF NOT EXISTS` or detect-and-repair partial objects on replay.** Rejected. Existence does not prove exact columns, constraints, RLS mode, policies, grants, function body, owner or provenance. Normalizing unknown partial state would turn recovery code into a second schema authority.

**Wrap migrations 0001 through 0003 in one deployment-wide transaction.** Rejected. The ordered migration boundaries are independently durable release/recovery checkpoints. A failure in 0002 must preserve a valid completed 0001, and a failure in 0003 must preserve valid completed 0001/0002.

**Move role installation into migration 0002 or 0003.** Rejected. Cluster-role lifecycle requires different operational authority and remains the separate idempotent deployment artifact established by PR #208.

## Verification

The hostile tests in `tests/postgres_publication_migration_rollback.rs` require two failure/replay invariants against PostgreSQL 18.4:

- injected failure in 0001 leaves the generation table absent, then clean replay yields table-present plus forced RLS;
- clean 0001 followed by injected failure in 0002 leaves 0001 present and the admission function absent, then clean replay yields the function present with PUBLIC EXECUTE revoked.

The causal repair is exact commits `bb2c70363c3e8e4cd355e88f46ac1b82bdad827f` and `33bf0e931358d33841ad0f256b9e272bf8430771`. Hosted CI `34254821314` / rust job `102157829351` is terminal SUCCESS on exact `33bf0e931358d33841ad0f256b9e272bf8430771`: checkout, toolchain, formatting, all locked workspace tests including both PostgreSQL 18.4 failure/replay regressions, and strict Clippy passed.

This evidence proves the bounded migration-atomicity repair only. After this ADR/CHANGELOG doctoring changes the branch head, the new exact documentation-bearing head must reacquire hosted GREEN; predecessor results do not transfer.

## Consequences

Recovery can reason about three supported forward boundaries instead of arbitrary partial DDL combinations: pre-0001, complete 0001, complete 0002 and complete 0003. Operational failures become rollback-and-replay events rather than schema-forensics events. The transaction blocks also make privilege hardening failure-atomic: PUBLIC cannot retain an admission function merely because a later revoke statement was never reached.

The trade-off is that migration orchestration must respect migration-owned transaction boundaries. This constraint is explicit and testable, and it is preferable to accepting partially secured durable state.

This decision remains within Wardnet's security-evidence/state boundary. EgressWeave transport authorization, quarantine execution, contextual-orchestrator model/provider routing, AppGuardrail analysis, Context Graph contracts and Enterprise Architecture authority remain with their canonical owners.

## References

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Transactions*. https://www.postgresql.org/docs/18/tutorial-transactions.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: psql*. https://www.postgresql.org/docs/18/app-psql.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: ROLLBACK*. https://www.postgresql.org/docs/18/sql-rollback.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html
