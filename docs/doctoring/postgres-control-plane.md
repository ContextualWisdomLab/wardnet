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
  control-plane URL, when the URL is not `postgres://`, or when TLS
  `sslmode=require` is requested before rustls is wired.

## Operator next action

Set `CONTROL_PLANE_DATABASE_URL` (or credentials-file key `control_plane_url`)
before binding a non-loopback address. `/healthz.persistence` reports
`postgres`. Loopback still uses `WAF_IDS_STATE_PATH` or in-memory state.
Remaining: rustls, non-owner runtime role, backup/restore drill, HASH
partitioning for `security_event`, optimistic concurrency.
