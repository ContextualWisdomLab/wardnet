# DNSBL TXT character-string publishing boundary

## Finding and owned repair

At protected Wardnet `f8260f1e03836039ff9463dd99fa982e4e270c4b`,
`validate_dnsbl` accepts nonempty reasons and sources without a per-string
length restriction, but `export_dnsbl_zone` encloses their combined metadata in
one TXT character string. A valid entry with 600 ASCII reason bytes and source
`unit` generates a 612-byte string that dnspython 2.8.0 rejects as `string too
long`. A 255-byte positive control is accepted by the same real parser. The
primary DNS Rdata API is documented by the parser project.[2]

This slice belongs to Wardnet's DNSBL publishing domain, not feed snapshot
ownership, MISP translation, egress, identity, deployment or source acquisition.
Existing PR #167 retains the MISP and shared DNSBL ownership fixes; it is not
copied or replaced. The other open-PR export-source comparisons found no TXT
chunking repair; the official-source preservation PR #115 changes CIDR export
selection and is left untouched.

## Protocol contract

RFC 1035 section 3.3 defines a character string with a one-octet length and at
most 255 data octets. Section 3.3.14 permits one or more character strings in
TXT RDATA.[1] The exporter now splits the combined reason/source metadata at
UTF-8 character boundaries before exceeding 255 decoded bytes. Escaped quotes,
backslashes and decimal control-byte syntax count as their decoded bytes, not
the number of master-file characters. Short output stays byte-for-byte
compatible; long output uses adjacent quoted strings in the same TXT record.

No metadata is truncated. Admission, stored fields, address/code selection,
feed ownership and the HTTP API shape remain unchanged. This is not complete
DNS zone validation: aggregate RDATA size, origin/name syntax limits, IPv6/CIDR
publication and authoritative SOA/NS provisioning remain separate concerns.
In particular, this repair does not assert that arbitrarily large total TXT
RDATA fits the protocol's two-octet RDLENGTH.

## Executed regression chain

- Before any production edit, `dnsbl_txt_chunks` failed with exit 101 on
  `TXT character string exceeds 255 bytes: 612`.
- The same regression passed after a byte-counted UTF-8-safe split was added to
  the existing escape function.
- Stable tests cover 254/255/256/510/511-byte boundaries, long metadata,
  multibyte UTF-8, quote/backslash/control escapes and short-output compatibility.
- An HTTP regression drives the real router from authenticated DNSBL admission
  to `/dnsbl/zone`, checking metadata bytes and absence of forged record lines.
- Extracted crate testing exposed a candidate packaging regression: the shared
  test decoder initially lived outside the core crate. Its implementation now
  resides in `crates/waf-ids-core/tests/support/`, with a test-only wrapper for
  the separate fuzz workspace. The root HTTP test carries the same independent
  decoder in its own `tests/support/` so each package includes its test source
  without exporting a production API or adding a production shared kernel.
- Unit, stable proptest and the libFuzzer target use a test-only independent
  quoted-string decoder. Chunk delimiters are parsed as grammar, rather than
  mistakenly treating all interior quotes as injection. The decoder does not
  call the production encoder or share its limit constant.
- An isolated Rust harness compiled the exact protected source and the repaired
  source separately; real dnspython master-file parsing and TXT wire encoding
  rejected the baseline 256/612-byte and UTF-8 fixtures and accepted every
  repaired fixture with lossless bytes. No DNS server or deployment was changed.

Full workspace gates, exact coverage and independent review are recorded in
the execution ledger. These regressions are protocol fixtures, not business
acceptance, detection-quality measurements, rendered UX or performance evidence.

## Sources

[1] https://www.rfc-editor.org/rfc/rfc1035.txt — Mockapetris (1987), RFC 1035, sections 3.3 and 3.3.14
[2] https://dnspython.readthedocs.io/en/latest/rdata.html — Dnspython DNS Rdata API
