# STIX comparison projection boundary

## Observed defect

The shared STIX importer searched for the first `=` and then discarded the
property name. It projected `domain-name:value != 'status.example'` and
`domain-name:x_note = 'status.example'` into a positive domain indicator.

A native gateway diagnostic used synthetic authorized documents on exclusive
loopback fixtures. Both STIX and OpenCTI imports returned HTTP201 for those
inputs instead of rejecting unsupported projection semantics. The saved critical
indicator caused score100/HTTP403 on the literal domain path and survived an
actual stop/restart. The two ordinary equality controls worked, and all six
unauthenticated imports returned HTTP401 without changing stored state. No
production incident or upstream service corruption was observed.

The repository integration regression then observed two intended
HTTP201-versus400 failures before the source repair. The three-form success
control passed. This is separate from a private parser experiment, which was
not a shipped regression or complete HTTP acceptance.

## Minimal shared repair

`src/stix_import.rs` preserves the object/property distinction with
`split_once(':')`. For existing value-mapped IPv4, IPv6, domain, hostname and URL
types, the property must be exactly `value` after existing whitespace trimming.
The parser rejects operator remnants ending in `!`, `<` or `>` before the first
`=` and a second leading `=` on the right. This prevents `!=`, `<=`, `>=` and
malformed `==` from being projected as ordinary equality. `value NOT` is not
accepted as a literal value property either.

The OASIS standard distinguishes equality and non-equality and defines object
paths as part of comparison expressions.[1] Its domain object has a distinct
`value` property.[1] These meanings justify retaining the property/operator
boundary; they do not prescribe Wardnet's limited projection policy or prove
complete conformance. Reference verification for this source change occurred
after initial implementation and the focused RED/GREEN. Prior receipt-only
retrieval chronology claims are excluded.

The same parser is called by STIX import, OpenCTI pure-STIX delegation, OpenCTI
Indicator conversion and TAXII material conversion. There is no per-endpoint
replacement detector or new dependency. Unsupported-only input follows the
existing no-mappable response. Existing mixed-document skip behavior is not
changed into whole-document rejection.

## Verified regression scope and limitations

Three actual Axum tests cover direct STIX, OpenCTI pure-STIX and OpenCTI entities.
Across those forms they reject four operator variants and five unrelated or
modified property variants, preserve five management projections and complete
persisted bytes, reload the application and check score0/HTTP200 on the normal
gateway path. The ordinary uppercase-domain equality preserves normalized value,
source, severity and TTL across reload.

This is a narrow repair. Unknown object/property projections, compound Boolean
patterns, qualifiers, escaped literals, unquoted-token compatibility, nested
bracket grammar and non-STIX pattern types are not comprehensively validated by
this change. File hash paths and general threat scoring are not redesigned.
It does not establish full STIX grammar, live TAXII/OpenCTI pulls, concurrent
persistence guarantees, deployed authentication, coverage100%, hosted security,
counted approval, normal merge or release. The native diagnostic's restart
observations do not expand the integration tests into crash-durability evidence.

## Sources

[1] STIX Version 2.1. Edited by Bret Jordan, Rich Piazza, and Trey Darley.
10 June 2021. OASIS Standard. Sections6.4.1,9.6,9.6.1.
https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

The reference is cited and summarized, not copied or redistributed as a PDF.
