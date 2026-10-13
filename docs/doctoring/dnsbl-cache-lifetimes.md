# DNSBL cache lifetimes at the publication boundary

## Reproduced product defect

The management API stored `DnsblEntry.ttl_seconds`, but the DNSBL exporter
omitted every record TTL and supplied `$TTL 300`. An admitted 1-second entry
therefore published A and TXT records with 300-second effective cache lifetimes.
The observed regression failed with `[300, 300]` instead of `[1, 1]` before the
production repair. This is DNS publication, not threat-feed expiry enforcement.

## Contract and minimal repair

DNS TTLs are unsigned values from zero through 2147483647. The high wire bit
must be zero. Wardnet already rejects zero at DNSBL admission; this repair adds
the upper-bound rejection without changing the separate threat-indicator or
feed-status lifetime contracts.[1]

An isolated DNSBL owner's A and TXT records preserve the admitted lifetime.
Entries sharing an IPv4 owner form A and TXT RRsets. All records in each RRset
must use the same TTL; Wardnet selects the shortest valid published lifetime,
independent of input order, without changing source-owned stored evidence.[1]
Invalid loopback codes, IPv6 entries and invalid TTLs do not contribute to this
minimum. This publication projection does not adopt another feed owner's work.

Persisted state is an untrusted boundary that bypasses admission. The exporter
omits entries with zero or out-of-range TTLs rather than silently clamping them.
For an effective 300-second owner, existing zone bytes remain unchanged; other
lifetimes are explicit on both record types. Metadata escaping/chunking and the
existing response-code safeguards remain intact.

## Verification and acceptance limits

The new core regression covers 1/60/299/300/301/86400/2147483647 seconds,
upper-range admission rejection, invalid persisted TTL omission, byte-identical
300-second output and shared-owner minimum TTL under both input orders.
The HTTP regression exercises authenticated admission, readback, upsert and
zone export, including rejected mutations preserving the previous valid entry.
Stable property tests retain arbitrary u64 TTLs and add valid-range and default
controls; the synchronized fuzz oracle recognizes explicit TTL syntax.

This repair does not establish authoritative DNS deployment, SOA/NS provisioning,
DNS name limits, aggregate TXT RDLENGTH bounds, CIDR or IPv6 publishing,
threat/feed expiration, complete product coverage, performance or business
acceptance. A local review is not a counted GitHub approval or protected merge.

## Sources

[1] https://www.rfc-editor.org/rfc/rfc2181.html — Elz & Bush (1997). Clarifications to the DNS Specification (RFC 2181), sections 5.2 and 8
