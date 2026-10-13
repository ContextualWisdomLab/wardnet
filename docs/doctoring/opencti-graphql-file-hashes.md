# OpenCTI GraphQL file-hash import boundary

## Observed defect

The existing `/api/threat-intel/opencti` adapter accepted GraphQL connection
exports but interpreted `hashes` only as an algorithm-to-value JSON object.
The upstream GraphQL schema defines `StixFile` and `Artifact` hashes as an
array of `Hash` objects. Each object has an algorithm string and a nullable
hash string.[1] Consequently, a file with two hashes could silently import
only its hash-shaped `observable_value`, or be rejected when that display
value was a filename. The regression reproduced the two-hash input producing
one threat before the repair; a second fixture uses a filename display value.

## Narrow repair

For the existing file, StixFile and artifact mappings, the adapter now reads
explicit array entries from `algorithm` and `hash`. It trims both strings,
ignores absent, non-string or empty members, and preserves each usable pair
as a threat indicator with the existing lowercase convention, source, TTL
and severity. An explicit empty or unusable array does not fall back to the
display value. A file node with no usable pairs follows the existing skipped
object path. Mixed usable/unusable pairs retain usable evidence; this does
not introduce per-hash skipped counts.

The old JSON object mapping and hash-shaped display fallback when there is
no array are unchanged. Algorithm names retain their existing spelling apart
from ASCII lowercase, including `SHA-256` becoming `sha-256`. This repair does
not define new hash algorithms, digest validation, scoring or malware policy.
It does not make all malformed non-array hash shapes fail closed. No file
observable recognition, STIX parser or generic threat validation is widened.

## Regression evidence

- Unit regression: two GraphQL hashes are retained with either a hash-like or
  filename display value. Original single-hash RED and repaired GREEN are
  retained outside the repository.
- Unit controls: null, missing, blank and wrongly typed pair fields, explicit
  empty arrays, mixed usable/unusable pairs and existing object-map imports.
- Actual Axum consumer: unauthenticated POST is denied without changing rows;
  authenticated GraphQL POST creates both threats, reports two imported
  threats and no DNSBL entries, and readback preserves metadata. A subsequent
  unusable-array POST is rejected without replacing rows or feed metadata.

These are synthetic documents against real parser/HTTP code, not a live
OpenCTI pull or proof of upstream permissions, marking enforcement, deployed
persistence, complete STIX conformance, hosted CI, protected merge or release.
The OpenCTI import API remains an authenticated export-ingest adapter.

## Sources

[1] OpenCTI Platform. *OpenCTI GraphQL schema*, commit
`183acbc7f8f541f9af013722d41a1b95b320e314`,
`opencti-platform/opencti-graphql/config/schema/opencti.graphql`.
Sections `Hash`, `HashedObservable`, `Artifact` and `StixFile`.
Retrieved October 3, 2026 through the actual GitHub contents API and a
separate web retrieval. Immutable source:
https://raw.githubusercontent.com/OpenCTI-Platform/opencti/183acbc7f8f541f9af013722d41a1b95b320e314/opencti-platform/opencti-graphql/config/schema/opencti.graphql

This is a schema compatibility repair, not a detection-model or routing-policy
feature. The authoritative schema is linked and summarized, not redistributed
as a claimed academic paper or new engine.
