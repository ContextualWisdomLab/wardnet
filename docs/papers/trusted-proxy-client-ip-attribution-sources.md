# Trusted proxy client IP attribution sources

This note records the operational sources that ground Wardnet's trusted-proxy
client IP attribution behavior. The current implementation anchors trust in the
direct peer, then evaluates forwarded metadata only when that peer belongs to a
configured trusted range.

## Source summary

The sources below converge on the same boundary. RFC 7239 defines forwarding
metadata as proxy-supplied information, not client truth. NGINX documents the
trusted-proxy rule explicitly and resolves recursive chains to the last
non-trusted hop. Envoy documents the same right-to-left trust model for
`X-Forwarded-For` and trusted CIDR lists.

## References

- Nottingham, M. (Ed.), & Kamp, P. H. (Ed.). (2014). *Forwarded HTTP
  extension* (RFC 7239). Internet Engineering Task Force.
  https://datatracker.ietf.org/doc/html/rfc7239
- NGINX, Inc. (n.d.). *Module ngx_http_realip_module*.
  https://nginx.org/en/docs/http/ngx_http_realip_module.html
- Envoy contributors. (n.d.). *HTTP header manipulation*.
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers

## Redistribution note

These sources are publicly linkable. This repository currently stores the URLs
and summaries instead of vendoring local PDFs because the authoritative source
formats for these documents are HTML pages rather than project-hosted PDF
artifacts.
