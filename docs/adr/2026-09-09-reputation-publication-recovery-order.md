# ADR 2026-09-09: Re-converge publication authority separately from publication evidence after rollback/reapply

- Status: Proposed; implementation candidate in Wardnet PR #217, pending stacked integration and protected release
- Date: 2026-09-09
- Parent contract: Wardnet PR #216 exact `7c7b980b7a2f41e2a369a71bb32e945de7f30bfd`
- Issues: #80, #192, #210

## Context

Wardnet's PostgreSQL reputation publication boundary deliberately separates schema migration from deployment-time cluster-role ownership. Migration `0003_reputation_source_publication.sql` creates the publication tables and the `SECURITY DEFINER` outer capability, while `deploy/postgresql/reputation_state_roles.sql` owns the idempotent least-privilege convergence of `wardnet_state_owner` and `wardnet_runtime`.

The rollback contract in PR #209 intentionally removes the 0003 publication function, immutable publication rows and last-known-good head while preserving 0001 generation identities and the 0002 admission capability. A subsequent 0003 reapply therefore recreates the outer function under the migration principal. Merely observing that the schema exists is not sufficient recovery evidence: bounded state-owner ownership and runtime publication authority must be reconverged separately.

A surviving generation identity is also not publication evidence. It proves that a token/ordinal/provenance binding was admitted, but not that the removed evidence snapshot, completeness proof and producer lifecycle constituted the last published state. This creates a second recovery hazard: after reapply, the publication function's normal first-publication path accepts `expected_prior = NULL`. If runtime EXECUTE is restored before historical publication evidence/head is restored, a later surviving generation can be published as a new first head and silently skip the lost last-known-good state.

## Decision

Wardnet separates recovery into four states and does not allow a later state to be inferred from an earlier one.

1. **Schema recovery** applies the supported forward migrations. Each 0001–0003 forward migration owns an explicit transaction and must leave either its complete supported boundary or the preceding supported boundary.
2. **Publication-owner recovery** runs `deploy/postgresql/reputation_state_recovery.sql` after 0003 reapply. The sequencer uses psql `\ir` to invoke the canonical transactional `reputation_state_roles.sql`; role creation, positive grants and function ownership remain single-sourced there.
3. The recovery sequencer then inspects surviving generation chains. If any `(tenant_id, source_id)` has durable generation identity but no publication head, it globally revokes `wardnet_runtime` EXECUTE on the outer publication function. This is a recovery-only safety hold, not a second positive-grant authority. Owner convergence, hardened `SECURITY DEFINER` configuration, bounded reads and denied direct mutation remain intact while runtime publication is held closed.
4. **Publication-evidence recovery** must restore authoritative publication evidence/head from verified backup/evidence or controlled replay under deployment/recovery authority. Wardnet does not infer a head from the highest surviving generation and does not let runtime use `expected_prior = NULL` to skip the gap.
5. Rerunning the recovery sequencer after every generation-bearing source has an authoritative publication head lets the canonical role installer restore bounded runtime EXECUTE. The next runtime generation may then advance only through the existing exact-prior and monotonic-ordinal transaction contract. Recovery replay remains idempotent.
6. A deterministic failure before function-ownership transfer must not be reportable as recovered authority. A missing-evidence hold must likewise not be reportable as runtime-ready publication authority.
7. `StateAuthority::Postgres` remains fail closed. PR #217 does not supply production login/principal membership, repository wiring, pool checkout/reset tenant context, crash/retry, authoritative backup/restore orchestration or immutable protected release evidence; those remain #80 completion work.

This order distinguishes **schema exists**, **owner/least-privilege authority is reconverged**, **publication evidence is restored and runtime publication reactivated**, and **production state authority is enabled**.

## Alternatives considered

**Duplicate the role/grant installer in the recovery script.** Rejected. It would create a second positive-grant source and invite privilege drift. Relative `\ir` keeps the recovery artifact executable while the canonical installer remains authoritative.

**Move cluster-role creation into migration 0003.** Rejected. Database-cluster role lifecycle and application-schema evolution have different deployment privileges and rollback semantics.

**Infer last-known-good from the highest surviving generation ordinal.** Rejected. Generation admission does not prove `evidence_snapshot_ref`, `completeness_ref` or `producer_lifecycle_ref`; automatic inference would manufacture authoritative security evidence.

**Permit runtime `expected_prior = NULL` after recovery when no head exists.** Rejected. A real PostgreSQL 18.4 hostile regression proved this can establish a later surviving generation as a new first head after rollback removed the prior publication evidence.

**Change the normal publication function to reject all first publications when earlier admitted generations exist.** Rejected. Pre-admission before the first legitimate publication is a valid normal path; recovery state must not leak into normal publication semantics.

**Restore publication data in a generic static SQL script.** Rejected for this slice. Authoritative data restoration requires backup/evidence identity and declared RPO/RTO semantics owned by #80; a static script cannot reconstruct removed evidence safely.

**Hold runtime publication globally when any recovered chain lacks a head.** Selected as the minimum safe recovery control. It is operationally conservative, but the runtime capability is role-global already; a partial per-source bypass would require new durable recovery-state schema/function semantics. #80 may later narrow recovery availability only with explicit, tested authority and evidence semantics.

## Executed evidence

PR #217 first established the missing-sequencer RED at `3999f0583eddfe87bc07b7ef477998a66fefe246`. Hosted CI `34259899229` / rust `102174943790` acquired `ubuntu-24.04`, passed checkout/toolchain/formatting, then failed in `Test` because `deploy/postgresql/reputation_state_recovery.sql` did not exist.

Candidate `ffbd6adb19a3d239c2c75b851ac3da76429bb67b` reused the canonical installer through `\ir`. CI `34260588614` / rust `102177249781` restored ownership/least-privilege grants but exposed an invalid test oracle: exact-prior generation 2 correctly conflicted because rollback had removed publication history/head. Exact `9834f74c7c28dfbff121747e94970e3c599b3bf1` corrected that oracle and CI `34261138199` / rust `102179084308` was SUCCESS.

A fresh hostile case then found the remaining bypass. After formatting repair, test-only exact `6a18312c9cc74d4b02daf54dc1033a4335a04a87` ran on a real PostgreSQL 18.4 container in CI `34263214416` / rust `102186066201`. Formatting passed, then `postgres_publication_recovery_evidence_gap` failed because runtime successfully published `generation-2` with `expected_prior = NULL` after rollback/reapply/recovery while generation-1 publication evidence/head was absent. That is the causal recovery-evidence RED.

The minimum causal repair leaves normal publication semantics unchanged. The recovery sequencer reconverges the canonical role owner/grants, detects any surviving generation chain without a head, and revokes runtime outer-function EXECUTE until controlled evidence restoration closes every gap. The controlled recovery principal restores generation-1 evidence, the sequencer is rerun, and only then does runtime exact-prior generation-2 publication resume. Code/test exact `5bf5c86feaf2f66f449d46e9874832cf8322712f` completed CI `34263760519` / rust `102187885532` SUCCESS through formatting, all locked workspace tests including the PostgreSQL 18.4 hostile recovery cases, strict Clippy and cleanup.

These are feature-branch receipts. They do not authorize production PostgreSQL state or release until the stack is integrated on protected truth and then-live gates are freshly successful.

## Consequences and follow-up

Recovery now fails closed at the capability boundary rather than relying on callers to remember an expected-prior value. During a destructive publication-data recovery, all runtime publication is held until every surviving generation-bearing source has an authoritative head. The temporary availability cost is intentional: Wardnet does not trade security-evidence integrity for partial automatic recovery.

#80 must define and execute authoritative backup/restore artifacts, retention/encryption authority, RPO/RTO, production principal mapping, pooled transaction-local tenant context and crash/retry behavior. A restore drill must prove publication history/head and generation identity are semantically consistent before readiness can become true. #192 remains the reputation-specific durable uniqueness/atomicity contract.

## References

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5), AC-6 Least Privilege and CP-10 System Recovery and Reconstitution. https://doi.org/10.6028/NIST.SP.800-53r5

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: psql*. https://www.postgresql.org/docs/18/app-psql.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Transactions*. https://www.postgresql.org/docs/18/tutorial-transactions.html

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html
