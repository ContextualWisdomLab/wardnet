# OpenCTI known-digest admission boundary

## Observed defect and root cause

The authenticated export-import route accepted an `MD5` observable whose value
was `status`. The actual repository regression observed HTTP201 where HTTP400
was required. A valid 32-character hexadecimal MD5 positive returned HTTP201
and retained lowercase value, source, severity and TTL across reload.

The direct digest branch and explicit file-hash array/map branches checked
nonempty strings but not algorithm-specific digest syntax. The existing generic
threat validator does not impose that syntax either. Generic request scoring
uses non-IP indicators as text. This repair prevents malformed known digests
from entering that consumer; it does not change scoring policy or compute file
hashes. No unauthenticated attack, live upstream corruption or deployed impact
was observed.

## Minimal boundary repair

`src/opencti_import.rs` shares one private predicate across direct MD5/SHA1/
SHA256/SHA512 and explicit file hash arrays/maps. After existing value trimming,
known algorithms require ASCII hexadecimal characters and exact textual lengths:
MD5 32; SHA1/SHA-1 40; SHA256/SHA-256 64; SHA512/SHA-512 128. These lengths follow
the specified digest bit widths and four bits per hexadecimal digit.[1][2]

Malformed known pairs follow the existing skipped-object path. An explicit
invalid array or map never substitutes the display hash. If nothing maps, the
existing no-mappable response is HTTP400 before feed upsert. Mixed input retains
valid rows and the existing object-level skip count, not a new per-pair count.
Unknown algorithm strings retain the existing nonempty/lowercase compatibility
policy. Their validity is not certified by this predicate. Direct hyphenated
entity recognition, unsupported hash shapes, STIX patterns/bundles, MISP, generic
threat validation, feed ownership, TTL expiry and request scoring are unchanged.

This is a deliberate compatibility restriction for malformed known digests.
An operator's arbitrary keyword is not an MD5 digest. It must not be represented
as a known digest just because a nonempty string previously passed ingestion.
The repair does not endorse MD5 or SHA-1 for collision-resistant security use.

## Actual regression boundaries

Three separate intended HTTP201-versus400 RED receipts are retained outside the
repository: direct MD5; explicit array; explicit map after the array was fixed.
Each repair was followed by the same real Axum control. The direct case pairs
invalid rejection with valid-digest acceptance and an explicit block route.

Eight integration tests additionally cover known lengths, short/long/nonhex/
UTF-8/internal-space denials, hyphenated algorithm spelling, uppercase and outer
whitespace normalization, unknown-algorithm compatibility, mixed valid evidence,
unauthenticated denial, five management projections and persisted-byte nonmutation,
normal gateway admission, and fresh application reload. Fixtures allocate
exclusive owned directories and remove only those directories.

The two follow-up tests characterize existing behavior; they do not repair a new
production defect. For direct, explicit-array and explicit-map MD5 documents,
missing and wrong tokens return HTTP401 and a read-only RBAC token returns
HTTP403 for both valid and invalid digests. A read-only read and an authorized
writer import provide positive controls. Every denial preserves the five
management projections and complete persisted bytes. For each of those three
input shapes with MD5/SHA1/SHA256/SHA512, fresh application loads preserve
normalized digest metadata and the exact feed source, counts, TTL and timestamp.
Invalid imports after reload preserve the same projections and persisted bytes
through a second load. These are sequential observations, not concurrent-read
or complete authentication-matrix guarantees.

These are synthetic documents through actual parser, management API, persistence
and gateway code. They are not live OpenCTI pull, deployed authentication, file
malware detection, complete STIX conformance, atomic concurrent-read guarantees,
coverage100%, hosted security, counted approval, protected merge or release.
The older GraphQL hash-array compatibility document describes its historical
repair; the present digest restriction supersedes only its then-excluded digest
validation limitation, without retrospectively changing that repair's evidence.

## Primary references

[1] R. Rivest. The MD5 Message-Digest Algorithm. RFC1321, April1992,
section1 (128-bit output) and appendixA.4 (`MDPrint` hexadecimal representation).
https://www.rfc-editor.org/rfc/rfc1321

[2] National Institute of Standards and Technology. Secure Hash Standard (SHS).
FIPS PUB180-4, August2015, section1 and algorithm summary table/sections6.1–6.4.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

RFC1321 section1/MDPrint and FIPS180-4 Figure1 support the widths and
representation cited above. Reference verification occurred after implementation
and the initial freeze; earlier draft retrieval claims are excluded. This
reference check does not attest prior research or upstream OpenCTI enforcement.
This is standards-grounded input validation, not a new detection engine.
Sources are cited and summarized; redistribution permission is not asserted.

Sources:
[1] https://www.rfc-editor.org/rfc/rfc1321 — Rivest: The MD5 Message-Digest Algorithm, RFC1321, April1992
[2] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf — NIST: Secure Hash Standard, FIPS PUB180-4, August2015
