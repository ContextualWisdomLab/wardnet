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

`GET /api/backup` (admin read) exports a hashed logical snapshot. `POST /api/backup`
restores after schema-version and payload-hash checks. `POST /api/backup/drill`
restores into an isolated tenant, compares invariants, and drops the drill
rows. Declared RPO: last successful export (`on-demand-logical-snapshot`).
Declared RTO: 60 seconds. `/healthz.backup` is `ready` on PostgreSQL.

National Institute of Standards and Technology. (2010). *Contingency planning
guide for federal information systems* (NIST SP 800-34 rev. 1).
https://doi.org/10.6028/NIST.SP.800-34r1
(`docs/papers/nist-sp-800-34r1-contingency-planning.pdf`, public domain)

- **Design impact:** CP-2 / CP-4 — declared RPO/RTO and an automated restore
  drill into an isolated environment. The artifact is application-level (not
  `pg_dump`) so RLS tenant context is preserved and secrets (admin tokens,
  database URL) are never copied.

Remaining: non-owner runtime role, HASH partitioning for `security_event`,
optimistic concurrency.
