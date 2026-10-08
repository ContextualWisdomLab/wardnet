# UTF-8-safe engine enforcement reasons

## Observed product defect

The existing authenticated Coraza audit and Suricata EVE ingest routes share
`apply_engine_enforcement_hints`. For a block-grade hit it derived a shorter
DNSBL reason from the full engine event. When the trimmed reason exceeded 200
bytes, it sliced at byte 199 and appended an ellipsis. A long Korean reason
caused both actual Axum import routes to panic at that slice before completing
the import. The retained final RED contains two product failures at the same
source line. Earlier fixture preassertion failures are separate and excluded
from product RED acceptance.

Rust string offsets count bytes. A string slice endpoint must coincide with a
UTF-8 character boundary; otherwise indexing panics. `is_char_boundary` checks
that boundary.[1] Engine messages are valid UTF-8 text but need not be ASCII.

## Narrow repair and unchanged policy

For trimmed input longer than 200 bytes, move the existing 199-byte cutoff
backward to the closest character boundary, then retain the existing ellipsis.
For valid UTF-8 this requires at most three one-byte steps. ASCII output stays
byte-identical. No new dependency, unsafe conversion or language-specific
message filtering is introduced.

The existing threshold, trim behavior, short-message behavior and blank-message
fallback are unchanged. The budget remains at most 199 prefix bytes followed
by the three-byte UTF-8 ellipsis: up to 202 bytes, not a newly imposed 200-byte
cap. This truncates scalar values safely; it is not grapheme-cluster-aware.
Full event reasons are retained unchanged. Source tags, scores, block/monitor
policy, DNSBL answer codes, 3600-second hint TTL, path selection, authorization
and persistence transaction logic are unchanged.

## Verification boundary

- Actual Axum Coraza and Suricata import regressions use synthetic Korean and
  emoji messages, require CREATED, full event readback, exact bounded DNSBL
  reason, hint counts, TTL/code preservation and unauthorized nonmutation.
- Unit controls assert independent literal results at ASCII 199/200/201 bytes,
  two-, three- and four-byte scalar cutoffs, a valid cutoff before a multibyte
  tail, whitespace trimming, blank fallback and low-score monitor nonmutation.
- The sibling engine call paths share the same repaired projection; the engine
  adapters are not reimplemented or replaced with synthetic detections.

These fixtures execute real parser/router/domain code; they do not run live
Coraza/CRS or Suricata, deploy a gateway, prove all failure rollback paths,
complete 100% coverage, hosted review, protected merge or release acceptance.
The previously preserved runtime processes and other owners are outside scope.

## Reference

[1] Rust project. *Primitive type str*: `len`, `is_char_boundary`, and
`SliceIndex<str> for RangeTo<usize>` panic conditions. Official standard library
API, retrieved October 3, 2026 through actual web open/find results.
https://doc.rust-lang.org/std/primitive.str.html#method.is_char_boundary

This is a string-boundary correctness repair, not a detection-model, scoring
or routing-policy feature. The official language contract is cited rather
than attaching unrelated detection research.
