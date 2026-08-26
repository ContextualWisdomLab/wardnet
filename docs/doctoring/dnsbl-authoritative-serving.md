# Authoritative DNSBL serving

## Decision

Wardnet's existing bounded UDP/TCP DNS listener answers IPv4 DNSBL queries
inside `DNSBL_ORIGIN` before entering recursive egress resolution. A query name
uses RFC 5782 reversed-octet form, for example
`99.2.0.192.dnsbl.example`. Listed addresses receive authoritative A and TXT
records; unlisted, malformed, and zone-apex names receive authoritative
`NXDOMAIN` with an RFC 2308 SOA for negative caching and are never forwarded
upstream. Listed names queried for unsupported types return the same SOA with
empty `NOERROR` (NODATA).

The implementation reuses the live `AppState` DNSBL entries,
`waf_ids_core::dnsbl_matches`, persisted-entry validation, per-entry TTLs, and
the existing 64-request UDP/TCP concurrency bounds. It adds no daemon or
dependency. CIDR entries are evaluated at query time, so every address in a
listed range receives the required record without materializing an entire zone.

```mermaid
sequenceDiagram
    participant C as DNSBL client
    participant D as Wardnet DNS listener
    participant S as Validated DNSBL state
    participant R as Egress resolver
    C->>D: A or TXT 99.2.0.192.dnsbl.example
    D->>D: Match exact DNSBL origin and decode IPv4
    D->>S: Validate entries and match address/CIDR
    alt listed
        S-->>D: code, reason, source, TTL
        D-->>C: AA=1, A 127/8 or bounded TXT
    else unlisted or malformed
        D-->>C: AA=1, NXDOMAIN plus SOA
    else outside DNSBL origin
        D->>R: Existing destination-policy resolution
    end
```

## Security and operability

- The origin comparison is label-boundary exact; suffix lookalikes do not enter
  the authoritative path.
- Persisted rows are revalidated before publication. Invalid response codes,
  empty provenance, invalid prefixes, and zero TTLs cannot become DNS answers.
- TXT character strings are bounded to DNS's 255-octet wire limit on a UTF-8
  boundary.
- DNSBL answers set the authoritative bit and do not advertise recursion.
- Unsupported types for a listed name return authoritative empty `NOERROR`;
  both NODATA and NXDOMAIN include the zone SOA for bounded negative caching.
  Non-DNSBL names retain the existing A/AAAA resolver contract.
- IPv6 nibble-reversed DNSBL publication remains a documented gap; the existing
  zone exporter and this runtime slice intentionally cover the current IPv4
  publication contract.

## Verification

`src/egress_dns.rs` tests cover A/TXT content, CIDR membership, TTL propagation,
authoritative `NXDOMAIN`/NODATA SOA records, malformed names, and real loopback
UDP/TCP exchanges through the production server loop. Repository readiness still requires
protected-branch checks and deployed port-53 evidence.

## References

Levine, J. (2010). *DNS blacklists and whitelists* (RFC 5782). Internet
Research Task Force. https://doi.org/10.17487/RFC5782

Vixie, P., Andrews, M., Lindqvist, M., & Wassenaar, E. (1998). *Negative
caching of DNS queries (DNS NCACHE)* (RFC 2308). Internet Engineering Task
Force. https://doi.org/10.17487/RFC2308
