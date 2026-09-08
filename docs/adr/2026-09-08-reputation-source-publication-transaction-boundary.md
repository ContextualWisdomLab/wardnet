# ADR 2026-09-08: Publish reputation source generations through one least-privilege transaction boundary

- Status: Proposed; implementation candidates in Wardnet PRs #207 and #208, pending stacked integration and protected release
- Date: 2026-09-08
- Parent contract: Wardnet PR #200 exact `63b2731d7173d24fc15cc1c340fb177727d33251`
- Issues: #80, #192

## Context

Wardnet's reputation bounded context needs durable tenant-scoped source-generation history before PostgreSQL can become production state authority. The preceding slice establishes immutable generation-token and ordinal bindings plus forced row-level security, but publication has a stronger invariant: generation identity, evidence/completeness/lifecycle references and the last-known-good pointer must move together or not move at all.

A second boundary is privilege. A `SECURITY INVOKER` publication function requires the caller to hold the table DML privileges used by the function. Hosted PostgreSQL 18.4 evidence at exact `43c6396e750d27c35f0a071543e81fce4cc788f2` (`CI 34243761631`, rust job `102120327373`) demonstrated that such a runtime role can directly update `reputation_source_publication_head`, bypassing the compare-and-swap and ordinal-monotonicity state machine even though tenant RLS remains in force. RLS answers which tenant rows are visible or mutable; it does not make arbitrary caller DML equivalent to the domain transition.

A third boundary is deployment atomicity. The role installer temporarily needs schema `CREATE` so ownership of the outer publication function can move to the bounded state owner. When the installer relied on psql autocommit, a deterministic failure at that ownership transfer left both capability roles present and stranded the temporary schema-creation authority. A least-privilege installer therefore has to make role creation, privilege convergence, ownership transfer and removal of temporary authority one all-or-nothing database transaction.

## Decision

Wardnet models one publication as a PostgreSQL transaction with these invariants:

1. A generation is admitted using tenant/source generation token, ordinal, completion time and provenance identity.
2. Immutable publication history binds that generation to evidence snapshot, completeness/pagination proof and producer lifecycle references.
3. The last-known-good head advances only from the exact expected prior generation and only to a strictly greater ordinal.
4. An exact committed retry returns `replay`; a divergent replay, stale expected prior, non-increasing ordinal or competing writer fails with stable `reputation_source_publication_conflict`.
5. Evidence validation occurs in the same transaction after candidate generation admission so a later failure proves rollback of both candidate binding and publication/head state rather than relying on pre-validation.
6. One tenant/source chain is serialized with a transaction-scoped advisory lock. Hash collision can over-serialize unrelated chains but cannot permit two conflicting transitions to commit.
7. Publication history and head remain FORCE-RLS tenant scoped and default deny when tenant context is absent.
8. Deployment of the capability roles is itself one explicit transaction. A failure anywhere before final `COMMIT` must discard role creation, privilege changes, function ownership transfer and temporary schema authority together.

The runtime role does not receive direct INSERT or UPDATE authority over publication history/head. `wardnet_publish_reputation_source_generation(...)` is a `SECURITY DEFINER` capability with PUBLIC execution revoked and a hardened function-local `search_path` of `pg_catalog, pg_temp`. Before production PostgreSQL authority is enabled, deployment transfers this function to a dedicated `NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` state-owner role. That role receives only the underlying table/function privileges needed by the transaction; the runtime receives read access required by its repository plus EXECUTE on the outer publication capability.

Database cluster roles are operational infrastructure, so migration `0003` does not create them. PR #208 implements the deployment side as the idempotent, non-migration artifact `deploy/postgresql/reputation_state_roles.sql`: it creates or converges the dedicated state-owner and runtime capability roles to `NOLOGIN`, `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOINHERIT`, `NOBYPASSRLS`, and `NOREPLICATION`; removes direct runtime generation/publication/head mutation and inner-admission execution; temporarily grants schema `CREATE` only to transfer ownership of the outer publication function; revokes that schema privilege immediately afterward; and grants the runtime only bounded reads plus outer publication EXECUTE. The complete installer owns one explicit `BEGIN`/`COMMIT` transaction so a mid-flight failure cannot persist a partially converged capability boundary. It creates no login credential or application principal mapping.

#80 still owns production repository wiring, actual deployment-principal mapping, migration/upgrade/rollback, pooled-connection tenant-context hygiene, recovery and backup/restore acceptance. Until those contracts are complete, `StateAuthority::Postgres` remains fail closed rather than selecting this schema as production authority.

## Alternatives considered

**Keep `SECURITY INVOKER` and grant runtime DML.** Rejected by the executed hostile RED: the runtime can directly mutate the last-known-good head and bypass domain invariants.

**Use a superuser or `BYPASSRLS` definer.** Rejected. PostgreSQL explicitly states that superusers and `BYPASSRLS` roles bypass row security, undermining the tenant isolation layer this durable authority relies on.

**Create the database state-owner role inside the application migration.** Rejected. Cluster-role lifecycle is an operational/deployment concern with different privileges and rollback semantics from schema evolution. The migration states the required owner contract; PR #208 supplies a separate idempotent deployment artifact instead.

**Leave role installation as a test fixture or operator prose.** Rejected. The least-privilege design would otherwise be unrepeatable in deployment and could regress to runtime DML grants without an executable acceptance boundary.

**Rely on psql autocommit plus a final privilege cleanup.** Rejected by executed PostgreSQL 18.4 evidence. The cleanup is never reached when an earlier statement fails, and already committed role/grant changes survive. PostgreSQL transactions make the deployment changes visible as one unit only after `COMMIT`; an aborted transaction discards its updates.

**Keep only application-side compare-and-swap.** Rejected. Concurrent writers, retries, process failure and future repository implementations require the invariant at the authoritative transaction boundary rather than in one caller implementation.

## Evidence and acceptance

Executed RED lineage in PR #207 includes:

- `d8d0cd3ba5c8eca454b1510a745b29b36136fe99`: missing publication migration RED in CI `34237346607` / job `102098369156`;
- `f2ef0b0bbaa5599c9d82dbc54e3e27b71e5d643a`: unused but regressive ordinal accepted, RED in CI `34238906678` / job `102103706051`;
- `43c6396e750d27c35f0a071543e81fce4cc788f2`: direct runtime head mutation bypassed the state machine, RED in CI `34243761631` / job `102120327373`.

PR #207 exact `1d45a024f7e6a0cc351eda3b9fb317ccf6e35300` reached terminal hosted CI `34245836806` / rust job `102127456517` with formatting, all locked workspace/PostgreSQL 18.4 tests and strict Clippy successful.

PR #208 moves the role contract into deployable state. Test-only `0cf9fe514047b320a4aae1a9a1f8b96a8fb25053` reached semantic RED in CI `34247087136` / rust job `102131737688` because the deployment artifact did not exist. Candidate `ec93199dc3042f6c519592d300775b1d5f6e678a` then installed and replayed the artifact and exposed only a test-oracle representation mismatch: PostgreSQL unaligned boolean output is `f/t`, not `false/true`. Exact `7167bdcd8e774a9b7f521e80765de1300e32f2ae` corrected that assertion and reached terminal CI `34247844928` / rust job `102134327764` SUCCESS, including idempotent role installation, state-owner/runtime privilege inspection, function-mediated publication, denied runtime direct head mutation, denied state-owner schema DDL, and preserved last-known-good state.

Fresh hostile review then added deterministic mid-flight ownership-transfer failure at exact `282f0fec7ff16b3aa4e1e086900970e154e4f1c0`. Hosted CI `34248558975` / rust job `102137217073` passed formatting and every preceding PostgreSQL 18.4 acceptance, then failed because the autocommit installer left `wardnet_state_owner`, its temporary schema `CREATE`, and `wardnet_runtime` present (`t:t:t`) after the injected failure. Exact causal repair `03af6b3c962ce7d681bd49f5a80487aa94283bc6` wrapped the complete installer in `BEGIN`/`COMMIT`; hosted CI `34248937286` / rust job `102138060537` was terminal SUCCESS with the rollback regression, all locked workspace tests and strict Clippy passing.

Any later documentation-bearing #208 head must reacquire the same exact-head gates; predecessor success does not transfer.

Production enablement additionally requires #80/#192 acceptance for repository wiring, actual deployment principal mapping, pool checkout/reset hygiene, migration upgrade/rollback, crash/retry behavior, backup/restore survival, and one immutable protected release. This ADR remains Proposed until those integration and release conditions are satisfied.

## Consequences

The database now has an explicit aggregate transition rather than a set of independently writable persistence tables. The runtime loses convenient direct mutation privileges, which narrows the blast radius of SQL mistakes or compromised repository code. Operational setup becomes explicit and executable because the state-owner capability role must be installed and verified before production PostgreSQL authority is enabled.

The deployment role installer requires cluster-level role-management authority at installation time, but neither retained state-owner nor runtime roles receive `CREATEROLE`, superuser, RLS-bypass, login or schema-creation capability after convergence. Login credentials and principal membership remain deployment-secret/IAM concerns rather than repository defaults. Because the installer intentionally owns its transaction boundary, deployment orchestration must invoke it as the standalone role-install unit rather than silently treating it as an arbitrary fragment of a caller-owned transaction; migration schema evolution remains separately owned.

This decision does not move EgressWeave transport authorization, quarantine execution, Context Graph truth or EA decision authority into Wardnet. Publication records are Wardnet reputation evidence and policy state only.

## References

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5), AC-6 Least Privilege. https://doi.org/10.6028/NIST.SP.800-53r5

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Transactions*. https://www.postgresql.org/docs/18/tutorial-transactions.html — changes inside a transaction become visible as a unit on commit; rolled-back changes do not become visible.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: ROLLBACK*. https://www.postgresql.org/docs/18/sql-rollback.html — rollback aborts the current transaction and discards its updates.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: CREATE FUNCTION*. https://www.postgresql.org/docs/18/sql-createfunction.html — `SECURITY DEFINER` executes with owner privileges; safe use requires a trusted `search_path`, and PUBLIC function execution should be revoked before selective grants.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html — superusers and `BYPASSRLS` roles always bypass RLS; table owners are subject only when FORCE RLS is used.

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: CREATE ROLE*. https://www.postgresql.org/docs/18/sql-createrole.html — `NOBYPASSRLS` is the non-bypass role contract used by the publication state owner and runtime acceptance roles.
