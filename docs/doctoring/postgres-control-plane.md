# Doctoring — PostgreSQL control plane

This note grounds issue #80 (PostgreSQL is the production authority; the JSON
file adapter remains loopback/community only). IEEE/ACM PDFs are not
redistributed.

## Adopted standards and literature

PostgreSQL Global Development Group. (2026). *PostgreSQL 18 documentation: Row
security policies*. https://www.postgresql.org/docs/18/ddl-rowsecurity.html

- **Design impact:** Every tenant table uses `ENABLE` + `FORCE ROW LEVEL
  SECURITY` and a default-deny policy keyed on `wardnet.tenant_id`. Missing
  tenant context yields no rows.

PostgreSQL Global Development Group. (2026). *PostgreSQL documentation:
Constraints*. https://www.postgresql.org/docs/current/ddl-constraints.html

- **Design impact:** Primary keys include `tenant_id`. Foreign keys point at
  `tenant_account`. Two-word snake_case names.

PostgreSQL Global Development Group. (2026). *PostgreSQL documentation:
Transaction isolation*. https://www.postgresql.org/docs/current/transaction-iso.html

- **Design impact:** Snapshot replace (routes, indicators, DNSBL, events, audit)
  commits in one transaction so a policy mutation cannot land without its audit
  records.

The current control plane intentionally owns one mutex-protected PostgreSQL
connection, so handlers, health checks, and the outbox worker serialize database
work. This is a bounded correctness-first ceiling, not a pool; adopt a role-aware
pool when measured queue latency requires concurrent database operations.

PostgreSQL Global Development Group. (2026). *PostgreSQL documentation: Table
partitioning*. https://www.postgresql.org/docs/current/ddl-partitioning.html

- **Design impact:** `security_event` is `PARTITION BY HASH (tenant_id)` with
  eight children so tenant-scoped SOC queries prune and high-volume appends do
  not share one btree. The partition key is part of the primary key. Logical
  backups stay a tenant snapshot; HASH is an on-disk layout, not a restore
  schema bump that voids prior artifacts.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** PW.1 — fail closed when a production bind has no
  control-plane URL, when the URL is not `postgres://`, or when
  `sslmode=allow` / `prefer` could silently drop to plaintext. `require` /
  `verify-full` use rustls with Mozilla roots; certificates are always
  verified.

## Operator next action

Set `CONTROL_PLANE_DATABASE_URL` (or credentials-file key `control_plane_url`)
before binding a non-loopback address. Use `sslmode=require` or
`sslmode=verify-full` for rustls. `/healthz.persistence` reports `postgres`.
Loopback still uses `WAF_IDS_STATE_PATH` or in-memory state.

After migrations, the session `SET ROLE`s to `wardnet_runtime` (NOSUPERUSER,
NOBYPASSRLS, not table owner) so FORCE RLS binds. Provision that role and
`GRANT` it to the login user if the URL user cannot `CREATE ROLE`. Missing
`wardnet.tenant_id` yields no rows.

`GET /api/backup` (admin read) exports a hashed logical snapshot stamped with
the current `MIGRATION_VERSION`. `POST /api/backup` restores after schema-version
and payload-hash checks. Role-only migrations (v3 `wardnet_runtime`) and HASH
layout (v4) do not change the logical snapshot shape, so `verify()` accepts
schema versions `MIN_RESTORABLE_SCHEMA_VERSION` (2) through the current version
rather than rejecting pre-upgrade snapshots. `POST /api/backup/drill` restores into an
isolated tenant, compares invariants, and drops the drill rows. Declared RPO:
last successful export (`on-demand-logical-snapshot`). Declared RTO: 60 seconds.
`/healthz.backup` is `ready` on PostgreSQL.

National Institute of Standards and Technology. (2010). *Contingency planning
guide for federal information systems* (NIST SP 800-34 rev. 1).
https://doi.org/10.6028/NIST.SP.800-34r1
(`docs/papers/nist-sp-800-34r1-contingency-planning.pdf`, public domain)

- **Design impact:** CP-2 / CP-4 — declared RPO/RTO and an automated restore
  drill into an isolated environment. The artifact is application-level (not
  `pg_dump`) so RLS tenant context is preserved and secrets (admin tokens,
  database URL) are never copied.

`security_event` is HASH-partitioned by `tenant_id` (8 children) so tenant
queries prune and high-volume appends do not share one btree. Existing
unpartitioned tables convert under `pg_advisory_lock`; rows keep unmasked
client IPs and paths. `/healthz.event_partitions` reports the child count.

Remaining: optimistic concurrency.

Management mutations currently persist one transactionally consistent tenant
snapshot: they replace the tenant's management rows and retained
`security_event` rows, then enqueue one snapshot outbox message. Event ingest
itself remains incremental. This makes an administrative write O(retained
events); operators should keep `EVENT_LIMIT` bounded and monitor transaction
latency. A future measured scaling step is table-specific management upserts
that preserve the same atomic outbox contract.
