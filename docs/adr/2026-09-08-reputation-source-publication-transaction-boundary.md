# ADR 2026-09-08: Publish reputation source generations through one least-privilege transaction boundary

- Status: Proposed; implementation candidate in Wardnet PR #207, pending stacked integration and protected release
- Date: 2026-09-08
- Parent contract: Wardnet PR #200 exact `63b2731d7173d24fc15cc1c340fb177727d33251`
- Issues: #80, #192

## Context

Wardnet's reputation bounded context needs durable tenant-scoped source-generation history before PostgreSQL can become production state authority. The preceding slice establishes immutable generation-token and ordinal bindings plus forced row-level security, but publication has a stronger invariant: generation identity, evidence/completeness/lifecycle references and the last-known-good pointer must move together or not move at all.

A second boundary is privilege. A `SECURITY INVOKER` publication function requires the caller to hold the table DML privileges used by the function. Hosted PostgreSQL 18.4 evidence at exact `43c6396e750d27c35f0a071543e81fce4cc788f2` (`CI 34243761631`, rust job `102120327373`) demonstrated that such a runtime role can directly update `reputation_source_publication_head`, bypassing the compare-and-swap and ordinal-monotonicity state machine even though tenant RLS remains in force. RLS answers which tenant rows are visible or mutable; it does not make arbitrary caller DML equivalent to the domain transition.

## Decision

Wardnet models one publication as a PostgreSQL transaction with these invariants:

1. A generation is admitted using tenant/source generation token, ordinal, completion time and provenance identity.
2. Immutable publication history binds that generation to evidence snapshot, completeness/pagination proof and producer lifecycle references.
3. The last-known-good head advances only from the exact expected prior generation and only to a strictly greater ordinal.
4. An exact committed retry returns `replay`; a divergent replay, stale expected prior, non-increasing ordinal or competing writer fails with stable `reputation_source_publication_conflict`.
5. Evidence validation occurs in the same transaction after candidate generation admission so a later failure proves rollback of both candidate binding and publication/head state rather than relying on pre-validation.
6. One tenant/source chain is serialized with a transaction-scoped advisory lock. Hash collision can over-serialize unrelated chains but cannot permit two conflicting transitions to commit.
7. Publication history and head remain FORCE-RLS tenant scoped and default deny when tenant context is absent.

The runtime role does not receive direct INSERT or UPDATE authority over publication history/head. `wardnet_publish_reputation_source_generation(...)` is a `SECURITY DEFINER` capability with PUBLIC execution revoked and a hardened function-local `search_path` of `pg_catalog, pg_temp`. Before production PostgreSQL authority is enabled, deployment transfers this function to a dedicated `NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` state-owner role. That role receives only the underlying table/function privileges needed by the transaction; the runtime receives read access required by its repository plus EXECUTE on the outer publication capability.

Database cluster roles are operational infrastructure, so migration `0003` does not create them. #80 owns executable deployment-role provisioning, migration/upgrade/rollback, pooled-connection tenant-context hygiene, recovery and backup/restore acceptance. Until those contracts are complete, `StateAuthority::Postgres` remains fail closed rather than selecting this schema as production authority.

## Alternatives considered

**Keep `SECURITY INVOKER` and grant runtime DML.** Rejected by the executed hostile RED: the runtime can directly mutate the last-known-good head and bypass domain invariants.

**Use a superuser or `BYPASSRLS` definer.** Rejected. PostgreSQL explicitly states that superusers and `BYPASSRLS` roles bypass row security, undermining the tenant isolation layer this durable authority relies on.

**Create the database state-owner role inside the application migration.** Rejected. Cluster-role lifecycle is an operational/deployment concern with different privileges and rollback semantics from schema evolution. The migration instead states the required owner contract and #80 must provision and verify it before production enablement.

**Keep only application-side compare-and-swap.** Rejected. Concurrent writers, retries, process failure and future repository implementations require the invariant at the authoritative transaction boundary rather than in one caller implementation.

## Evidence and acceptance

Executed RED lineage in PR #207 includes:

- `d8d0cd3ba5c8eca454b1510a745b29b36136fe99`: missing publication migration RED in CI `34237346607` / job `102098369156`;
- `f2ef0b0bbaa5599c9d82dbc54e3e27b71e5d643a`: unused but regressive ordinal accepted, RED in CI `34238906678` / job `102103706051`;
- `43c6396e750d27c35f0a071543e81fce4cc788f2`: direct runtime head mutation bypassed the state machine, RED in CI `34243761631` / job `102120327373`.

The first privilege repair head `80af90273def9f72042ef378d3a74ea31b8a6de6` reached terminal hosted CI `34244982960` with formatting, all workspace/PostgreSQL 18.4 tests and strict Clippy successful. The final documentation-bearing head must reacquire the same exact-head gates; predecessor success does not transfer.

Production enablement additionally requires #80/#192 acceptance for repository wiring, database-role installation, pool checkout/reset hygiene, migration upgrade/rollback, crash/retry behavior, backup/restore survival, and one immutable protected release. This ADR remains Proposed until those integration and release conditions are satisfied.

## Consequences

The database now has an explicit aggregate transition rather than a set of independently writable persistence tables. The runtime loses convenient direct mutation privileges, which narrows the blast radius of SQL mistakes or compromised repository code. Operational setup becomes more explicit because the state-owner capability role must be provisioned and verified before production PostgreSQL authority is enabled.

This decision does not move EgressWeave transport authorization, quarantine execution, Context Graph truth or EA decision authority into Wardnet. Publication records are Wardnet reputation evidence and policy state only.

## References

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5), AC-6 Least Privilege. https://doi.org/10.6028/NIST.SP.800-53r5

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: CREATE FUNCTION*. https://www.postgresql.org/docs/18/sql-createfunction.html — `SECURITY DEFINER` executes with owner privileges; safe use requires a trusted `search_path`, and PUBLIC function execution should be revoked before selective grants.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html — superusers and `BYPASSRLS` roles always bypass RLS; table owners are subject only when FORCE RLS is used.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: CREATE ROLE*. https://www.postgresql.org/docs/18/sql-createrole.html — `NOBYPASSRLS` is the non-bypass role contract used by the publication state owner and runtime acceptance roles.