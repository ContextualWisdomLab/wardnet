# ADR 0004: RFC 5782-style DNSBL zone export

- Status: Accepted
- Date: 2026-08-25
- Recorded from: current `main` (`README.md` DNSBL notes;
  `docs/architecture.md` `/dnsbl/zone` and DNSBL serving follow-up;
  `docs/fuzzing.md` zone-export invariants)

## Context

Operators publish listed addresses so mail and gateway scorers can
query a DNS blacklist. Levine (2010) describes DNS blacklists and
whitelists as **IRTF Informational** practice: this is **not** an
Internet Standards Track specification. The conventional listing
record is an A resource record whose address is a **response code**,
not a destination to connect to. Those A values SHOULD lie in
`127.0.0.0/8` so a mistaken use as an IP address stays on loopback
(Levine, 2010, RFC 5782).

Zone and resource-record structure follows DNS concepts and the DNS
implementation specification (Mockapetris, 1987a, RFC 1034 / STD 13;
Mockapetris, 1987b, RFC 1035 / STD 13).

## Decision

1. Export an **RFC 5782-style DNSBL zone** at `GET /dnsbl/zone` using
   the configured `DNSBL_ORIGIN`. The `dnsbl.local` default is for local
   development only; authoritative deployments must explicitly configure a
   non-`.local` origin because `.local.` is reserved for mDNS.
2. Require every published DNSBL **response code** to be an IPv4
   loopback-style address in **`127.0.0.0/8`**. Reject codes outside
   that range at the management API.
3. Treat the export as **zone text suitable for an authoritative DNS
   server**. This process does **not** serve DNS on port 53.
4. **Hickory DNS authoritative serving is a follow-up**, to be
   considered after zone-export semantics stabilize. It is not
   accepted on current `main`.

## Consequences

- Management upserts stay keyed by listed `address`; the A-record
  payload is the validated `127.0.0.0/8` code.
- Fuzz and property tests require every published A-record code to
  remain a loopback literal and every TXT payload to stay escaped
  (`docs/fuzzing.md`).
- RFC 5782 remains Informational. Local validation is stricter
  (`MUST` in this gateway) than the RFC `SHOULD` on A values.
- IPv6 DNSxL layout in RFC 5782 is not an accepted serving mode here.

## References

Cheshire, S., & Krochmal, M. (2013). *Multicast DNS* (RFC 6762).
RFC Editor. https://doi.org/10.17487/RFC6762

Levine, J. (2010). *DNS blacklists and whitelists* (RFC 5782). RFC
Editor. https://doi.org/10.17487/RFC5782

*(IRTF Informational; not Standards Track. Also
https://www.rfc-editor.org/info/rfc5782. Live-checked 2026-08-25.)*

Mockapetris, P. (1987a). *Domain names—concepts and facilities*
(RFC 1034). RFC Editor. https://doi.org/10.17487/RFC1034

*(Internet Standard, STD 13.)*

Mockapetris, P. (1987b). *Domain names—implementation and
specification* (RFC 1035). RFC Editor. https://doi.org/10.17487/RFC1035

*(Internet Standard, STD 13.)*
