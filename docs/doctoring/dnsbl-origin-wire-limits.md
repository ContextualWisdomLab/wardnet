# DNSBL origin and owner wire limits

## Publication defect

The origin sanitizer removed injection characters but accepted interior empty
labels, labels longer than 63 bytes, and origins that left no wire space for a
reversed IPv4 owner. The actual Rust exporter fed to dnspython 2.8.0 reproduced
`LabelTooLong`, `EmptyLabel`, and `NameTooLong`. A positive control with a
255-byte fully qualified owner parsed; the otherwise identical 256-byte owner
failed. These are publication defects, not authoritative-server deployment
observations.

## Bounded repair and compatibility

Keep the existing ASCII filtering, surrounding-dot trimming and ordinary
origin spelling. After filtering, use the existing `dnsbl.invalid` fallback
when any label is empty or longer than 63 bytes, or when the origin exceeds
237 textual bytes. The fallback changes the published origin, not stored
entries, their metadata, response codes, order or cache lifetimes. It is not
an operator configuration-admission error or a new public API.

For a nonempty dotted ASCII name without its final root dot, encoded length
is textual length plus two: separators become length octets, the first label
adds one length octet, and the root adds one zero octet. Four reversed IPv4
labels require at most sixteen more octets. Therefore the bound is
`237 + 2 + 16 = 255`. Reserving the maximum preserves a stable origin for all
IPv4 entries rather than changing it with the current address set.

The shared package-local test oracle independently sums label lengths and
length octets rather than using the sanitizer's textual threshold. Fixed
63/64-byte label and 255/256-byte owner controls, arbitrary-input properties,
the synchronized fuzz oracle, and the actual configured HTTP export route
exercise this boundary. Scratch compilation is not a fuzz campaign.

## Scope and remaining gaps

This repair is in DNSBL publication, not the separately owned runtime config
registry or feed-refresh work. It does not establish SOA/NS completeness,
authoritative loading, aggregate TXT RDLENGTH, IPv6/CIDR publication, UI locale
rendering, production rollout or full-workspace 100% coverage. Local tests and
source review do not replace current-head hosted security gates or counted
GitHub approval.

## Source

Mockapetris, P. (November 1987). *Domain names — implementation and
specification*. RFC 1035, sections 2.3.4 and 3.1.
https://www.rfc-editor.org/rfc/rfc1035.txt

The RFC defines 63-octet labels, a 255-octet encoded domain name, label-length
fields and the terminating root label. The sixteen-octet IPv4 reserve and
237-character publication threshold above are Wardnet's derived boundary,
not verbatim RFC limits. The official text permits unlimited distribution;
no third-party paper or implementation is copied by this repair.
