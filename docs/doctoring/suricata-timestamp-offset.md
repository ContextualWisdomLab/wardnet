# Suricata event occurrence time and numeric UTC offsets

## Observed defect

The EVE adapter parsed only the first 19 timestamp characters. It interpreted
local wall time as UTC regardless of the numeric offset in the suffix. The
actual authenticated `/api/ids/suricata/eve` route stored two records for the
same instant with different Unix seconds: the `+0100` record was 3600 seconds
late and the `-0530` record was 19800 seconds early. Both represent UTC
`2024-06-15T12:34:56Z`, or Unix second 1718454896.

Official Suricata EVE documentation includes numeric offsets such as `+0100`
in its alert examples.[1] Numeric offsets express local time minus UTC, so
conversion to UTC subtracts the signed offset.[2] Treating the suffix as inert
text corrupts event chronology. The retained unit RED also demonstrates that
an invalid `+2400` suffix was silently accepted as UTC.

An earlier integration-test compilation error tried importing a private
module. Another fixture failed on an unauthenticated audit-log read. Both are
harness failures, not product RED. The corrected unit tests and authenticated
route produced the timestamp assertion failures before production edits.

## Narrow repair

Keep the existing date/time prefix parser, second-level precision, whitespace
trimming and timezone-less lab interpretation. Parse an optional nonempty
ASCII fractional-seconds component, then require either no timezone, `Z`, or
a signed `HHMM`/`HH:MM` numeric offset. Require offset hours at most 23 and
minutes at most 59, and consume the entire suffix. Subtract the offset using
signed checked arithmetic before converting to nonnegative Unix seconds.
This also allows a pre-epoch local wall time whose negative offset places the
actual UTC instant at or after the epoch.

Malformed suffixes and UTC instants before the epoch return `None`. The
existing route then uses its existing ingest-time fallback; it does not drop
the alert or change HTTP admission. No dependency or public API is added.
The private adapter module stays private. Scores, alert actions, enforcement
hints, original reason text, source tags, DNSBL codes/TTLs, authorization and
persistence transaction boundaries are unchanged.

This is not full RFC 3339 validation. Calendar-day validity and leap-second
handling retain the existing prefix parser's limitations. Fractional seconds
are validated but discarded because the existing event model stores seconds.
Timezone-less timestamps remain a lab compatibility convention, not an
inferred local timezone. The existing zero-offset instant handling is retained;
no extra timezone provenance is introduced into the event model.

## Verification

- Unit controls compare `Z`, positive/negative compact and colon offsets to an
  independent literal Unix instant, including fractional seconds, epoch
  crossings and a negative UTC result.
- Malformed suffix controls include oversized hours/minutes, incomplete or
  nonnumeric offsets, empty/nonnumeric fractions, trailing garbage and Unicode.
  Existing timezone-less and zero-offset forms remain positive controls.
- An actual authenticated Axum array import must retain identical occurrence
  times for positive and negative offsets, original policy scores/actions,
  hint counts, DNSBL code/TTL and unauthorized event/threat/DNSBL/audit
  nonmutation.
- Full workspace tests, formatting, warning-fatal Clippy and the real external
  gateway smoke are separate parent-run gates. A former passing source review
  does not approve this new delta; the complete original-base union needs a
  fresh source-bound independent verdict.

Fixtures are offline synthetic EVE records through actual Rust parser/router
code. They do not run Suricata, establish incident chronology in deployed data,
certify clock synchronization, complete coverage, pass hosted security gates,
authorize protected merge or establish whole-product acceptance.

## References

[1] Open Information Security Foundation. *Suricata User Guide: Eve JSON
Format*, current documentation, alert timestamp example. Retrieved through
actual web open on October 4, 2026.
https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

[2] Klyne, G., and Newman, C. (2002). *Date and Time on the Internet:
Timestamps* (RFC 3339), section 4.2, numeric offsets. RFC Editor. Retrieved
through actual web open on October 4, 2026.
https://www.rfc-editor.org/rfc/rfc3339.html

The official protocol/producer contracts ground this timestamp-conversion
repair. It introduces no detection model or load-balancing algorithm; unrelated
research PDFs are not attached.
