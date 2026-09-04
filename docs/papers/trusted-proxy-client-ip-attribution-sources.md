# Trusted proxy client IP attribution sources

This note records the standards, operational guidance, and peer-reviewed
security evidence that ground Wardnet's trusted-proxy client IP attribution
behavior. The implementation anchors trust in the direct transport peer and
considers forwarded metadata only when that peer belongs to an explicitly
configured trusted range.

## Evidence synthesis

RFC 7239 defines forwarding metadata as information added by intermediaries; it
is not self-authenticating client truth. NGINX documents the trusted-proxy rule
explicitly and resolves recursive address chains to the last non-trusted hop.
Envoy documents the same right-to-left trust model for `X-Forwarded-For` with
trusted CIDR lists.

Pletinckx, Kruegel, and Vigna's NDSS 2025 Internet-scale measurement provides
independent empirical security evidence for the same boundary. Their study
shows that backends accepting proxy-supplied source identity from arbitrary
network sources can permit access-control bypass and other security failures.
For Wardnet, that supports direct-peer verification before forwarded metadata
can affect rate limiting, DNSBL decisions, or event attribution. The paper does
not prescribe Wardnet's exact HTTP malformed-chain algorithm; Wardnet's choice
to reject an incomplete or unparsable `X-Forwarded-For` chain and fall back to
the direct peer is a conservative fail-closed policy derived from the broader
untrusted-metadata threat.

## References

- Nottingham, M. (Ed.), & Kamp, P. H. (Ed.). (2014). *Forwarded HTTP
  extension* (RFC 7239). Internet Engineering Task Force.
  https://datatracker.ietf.org/doc/html/rfc7239
- NGINX, Inc. (n.d.). *Module ngx_http_realip_module*.
  https://nginx.org/en/docs/http/ngx_http_realip_module.html
- Envoy contributors. (n.d.). *HTTP header manipulation*.
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers
- Pletinckx, S., Kruegel, C., & Vigna, G. (2025). A large-scale measurement
  study of the PROXY protocol and its security implications. *Network and
  Distributed System Security Symposium 2025*.
  https://doi.org/10.14722/ndss.2025.242247
  Open-access paper: https://www.ndss-symposium.org/wp-content/uploads/2025-2247-paper.pdf

## Redistribution note

The IETF, NGINX, Envoy, and NDSS source locations are linked directly so the
repository preserves authoritative origin and version context. The NDSS paper
is openly readable from the symposium site, but this repository does not vendor
a copy until redistribution terms for storing a derivative repository copy are
explicitly verified. Linkability and free access are not treated as permission
to redistribute a binary artifact.
