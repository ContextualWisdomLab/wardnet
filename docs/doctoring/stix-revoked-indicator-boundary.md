# STIX revoked indicator boundary

## Observed defect

The shared STIX importer (`src/stix_import.rs`) never read the STIX common property
`revoked`. An indicator with `"revoked": true` and pattern
`[ipv4-addr:value = '203.0.113.66']` was projected into an enforceable critical `client_ip`
threat row plus a DNSBL `127.0.0.2` entry. The rows were persisted, survived reload and made
the gateway return HTTP403 for that client on a block-mode route.

The same parser serves three ingress paths:

- `POST /api/threat-intel/stix` (bundle, indicator or array);
- `POST /api/threat-intel/taxii/poll` (TAXII 2.1 envelope normalized to a STIX bundle);
- `POST /api/threat-intel/opencti` for native STIX indicators and OpenCTI `Indicator`
  entities.

For the OpenCTI entity shape, `materialize_node` (`src/opencti_import.rs`) rebuilt a fresh
indicator object and dropped `revoked` before the STIX parser ran.

## Standard

OASIS, *STIX Version 2.1*, OASIS Standard, 10 June 2021, section 3.2 (common properties),
property `revoked` (boolean): "Revoked objects are no longer considered valid by the object
creator. Revoking an object is permanent ... The default value of this property is false."
Section 3.6 adds: "This specification does not address how implementations should handle
revoked data." <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>

Wardnet's policy decision is therefore explicit, not inherited from the standard: an
enforcement gateway must not admit evidence that its creator has declared invalid.

## Actual RED

`tests/stix_revoked_indicator_boundary.rs` drives the real Axum app with synthetic
credentials and a temporary state file, across the `stix` bundle, OpenCTI native-indicator
array and OpenCTI entity shapes:

- mixed bundle: one `revoked: true`, one `revoked: false`, one with `revoked` absent;
- all-revoked and malformed (`"false"`, `1`, `null`) documents, each with an unauthenticated
  401/no-mutation control first.

Before the repair, `cargo test --locked --test stix_revoked_indicator_boundary` failed both
tests (exit101): the mixed bundle reported `upserted_threats: 3, upserted_dnsbl: 3`, and the
all-revoked document returned HTTP201 instead of HTTP400.

## Repair

- `src/stix_import.rs`: after the `type == indicator` check, an object is admitted only when
  `revoked` is absent or exactly the JSON boolean `false`. Any other value is counted in
  `skipped_objects` (fail closed for malformed lifecycle data).
- `src/opencti_import.rs`: the synthesized entity-shape indicator carries the node's `revoked`
  value (default `false`).

After the repair, the mixed bundle stores and enforces only the two live indicators (HTTP403
for them after reload), the revoked address scores 0/HTTP200, and all-revoked or malformed
documents return HTTP400 with byte-identical persisted state.

## Limits

- This stops new admission of revoked indicators. It does not retract rows previously
  imported under the same STIX id. Same-feed refresh reconciliation and DNSBL snapshot
  ownership remain with issue #172.
- STIX version ordering by `modified`, `valid_from`/`valid_until` windows and non-STIX
  `pattern_type` values are not handled by this slice.
- The reputation `EvidenceRecordV1` lifecycle in issue #184 is a separate, unmerged code
  path. This repair is related but does not close that issue.
- Synthetic local fixtures only: no live TAXII server, OpenCTI instance or deployed incident.
