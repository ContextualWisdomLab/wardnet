# Doctoring — transactional outbox and leased workers

This note grounds issue #81 (external effects leave the PostgreSQL control plane
through a transactional outbox, not request-path retry loops). IEEE/ACM PDFs
are not redistributed.

## Adopted standards and literature

PostgreSQL Global Development Group. (2026). *PostgreSQL documentation: Explicit
locking*. https://www.postgresql.org/docs/current/explicit-locking.html

- **Design impact:** Workers claim `outbox_message` rows with
  `FOR UPDATE SKIP LOCKED`. Expired leases are reclaimable. Unrelated tenants
  and aggregates are not globally serialized.

PostgreSQL Global Development Group. (2026). *PostgreSQL documentation:
Transaction isolation*. https://www.postgresql.org/docs/current/transaction-iso.html

- **Design impact:** The security event (or policy snapshot) and its outbox row
  commit in one transaction. A crash after domain commit but before dispatch
  leaves a pending message; it cannot invent extra authority.

Hohpe, G., & Woolf, B. (2003). *Enterprise integration patterns: Designing,
building, and deploying messaging solutions*. Addison-Wesley.

- **Design impact:** Transactional outbox. Downstream stdout SIEM export is
  **at-least-once**. The `outbox_receipt` unique `(tenant_id, idempotency_key)`
  is the exactly-once business acknowledgement. Do not call transport delivery
  exactly once.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** PW.1 / PW.7 — durable retry, dead-letter, and authorized
  replay with audit. Replay is a write (`X-Admin-Token`).

## Operator next action

Production binds already require `CONTROL_PLANE_DATABASE_URL`. On that path:

- `GET /healthz` reports `outbox=ready` plus pending/leased/dead-letter counts
- `GET /api/outbox` (admin read) lists at most `EVENT_LIMIT` messages
  (dead letters, then pending, then leased, then processed)
- `POST /api/outbox/{message_id}/replay` (admin write) requeues dead letters

Processed `outbox_message` rows are pruned to the operator `EVENT_LIMIT` on
append, snapshot save, and worker ack. `outbox_receipt` rows stay; they are
the exactly-once ack. Dead letters are never pruned.

Loopback file/memory adapters keep in-process stdout SIEM and report
`outbox=disabled`. Remaining: HASH partitioning and additional consumers
(TAXII poll, Clearfolio, contextual-orchestrator) on the same
message/receipt contract. Backup/restore drill is on the PostgreSQL plane.
