# ADR 0002: Optional JSON state for standalone durability

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`README.md` run notes;
  `docs/architecture.md` security boundaries; `docs/runbooks/operations.md`
  persistence behavior)

## Context

The gateway must keep operator-managed routes, threat indicators, DNSBL
entries, events, and license metadata across a local restart when an
operator asks for durability. Many lab and smoke runs do not need a
file at all.

JSON is the Internet Standard data interchange format for this class of
text documents (Bray, 2017, RFC 8259 / STD 90). A single pretty-printed
object is enough for a standalone process. It is not a multi-operator
database, a backup system, or an audited change workflow.

## Decision

1. `WAF_IDS_STATE_PATH` is **optional**. When unset, the process uses
   seeded in-memory state. Health reports `persistence: memory`.
2. When the path is set, load JSON from that file (or seed and create
   it). Persist with a **temporary sibling file** and **atomic rename**
   onto the configured path. Health reports `persistence: file`.
3. If a management write cannot replace the state file, **roll back**
   the in-memory mutation and return an operator-visible error.
4. Treat this JSON file as **baseline standalone durability only**. It
   is not a production control-plane database, not a backup plan, and
   not an audited change-management system.

A production database is **not** an accepted architecture decision on
current `main`.

## Consequences

- `scripts/smoke.sh` can prove restart persistence with a temporary
  JSON file and no external datastore.
- Parse failures on a configured path fail startup rather than silently
  ignoring a corrupt file (`docs/security/threat-model.md`).
- Concurrent writers and disaster recovery remain out of scope until a
  later durable store is accepted.
- Schema evolution is the application's JSON shape, not a migration
  framework.

## References

Bray, T. (Ed.). (2017). *The JavaScript Object Notation (JSON) data
interchange format* (RFC 8259). RFC Editor.
https://doi.org/10.17487/RFC8259

*(Internet Standard, STD 90. Live-checked 2026-08-25 via
https://www.rfc-editor.org/info/rfc8259 and the DOI above.)*
