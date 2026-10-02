# DNSBL TXT aggregate RDATA limits

## Root cause and reproduced boundary

Per-string 255-byte chunking is necessary but not sufficient for a TXT RR.
Before this repair, admission accepted 65,280 ASCII payload bytes and the
exporter emitted 256 strings. The 256 length octets made RDATA 65,536 bytes.
The actual compiled Rust exporter fed dnspython 2.8.0: text loading and raw
RDATA serialization succeeded, but RR serialization failed with `FormError`.
The independently counted RDATA exceeded the unsigned 16-bit field. A 65,279-byte payload produced 65,535 RDATA bytes and
serialized successfully. The distinction matters: parsing text alone did not
prove that an RR could be encoded.

## Primary contract and derived boundary

Paul Mockapetris, RFC 1035, *Domain Names — Implementation and Specification*,
November 1987, §§3.2.1, 3.3, 3.3.14 and 4.1.3,
<https://www.rfc-editor.org/rfc/rfc1035.txt>.
RDLENGTH is an unsigned 16-bit count of RDATA octets. TXT has one or more
character strings; each string has one length octet plus at most 255 data
bytes. Therefore the sum of decoded payload and all string-length octets
must be at most 65,535. This is a derived application boundary, not a new
DNS protocol limit or a complete DNS-message-size guarantee.

## Minimal publication policy

The payload is the existing `reason + " source=" + source`, in UTF-8.
Admission counts each scalar at the encoder's UTF-8-safe chunk boundaries,
without allocating an escaped copy, and stops at the wire ceiling. Oversized
metadata returns `DNSBL TXT metadata exceeds 65535 wire bytes`.
Escaped quotes, backslashes and controls count by decoded bytes, not their
longer master-file spelling. UTF-8 boundaries can use extra length octets:
16,316 emoji plus the separator/source occupies 65,536 wire bytes even
though an ASCII payload with the same decoded length could fit.

Persisted input bypasses admission. An oversized entry is omitted from both
A/TXT publication and the shared-owner minimum-TTL projection. Its stored
evidence is not changed, truncated or clamped. Other valid entries retain
normal ordering, metadata and default/explicit TTL spelling. Existing IPv6,
prefix, response-code and feed-expiry policies are not expanded here.

## Executed verification and limits

Permanent tests use literal 65,535/65,536 controls, independent decoded TXT
lengths, UTF-8/escape cases and a valid shared owner alongside an oversized
low-TTL sibling. Real authenticated API admission/readback/export verifies
that rejection preserves the previous entry and exact zone bytes. Independent
oracle sensitivity includes otherwise-valid legal strings whose aggregate
RDATA exceeds the field. Stable boundary properties supplement short arbitrary
inputs; the fuzz oracle keeps its arbitrary-input path and uses independent
input-derived eligibility.

Actual RR serialization does not establish UDP/TCP message fit, truncation,
authoritative DNS service deployment, traffic protection, a coverage-guided
fuzz campaign, whole-workspace 100% coverage or UI/locale acceptance. The
65,535-byte RDATA positive control itself can exceed a whole DNS message's
available payload after owner/header overhead; serving policy remains separate.
