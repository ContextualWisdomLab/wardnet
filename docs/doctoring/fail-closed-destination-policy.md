# Doctoring — fail-closed destination policy

This note grounds issue #79 (every outbound `http`/`https` call is mediated by
one destination-policy component). IEEE PDFs are not redistributed.

## Adopted standards and literature

OWASP Foundation. (n.d.). *Server-Side Request Forgery Prevention Cheat Sheet*.
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

- **Design impact:** Parse URLs structurally, disable redirects, ignore ambient
  proxy variables, and deny internal address classes unless an operator
  allowlist names them. Deny-overrides (`DESTINATION_DENYLIST`) win.

OWASP Foundation. (2025). *OWASP Application Security Verification Standard
5.0.0*. https://owasp.org/www-project-application-security-verification-standard/

- **Design impact:** ASVS V13 SSRF and V4 access control — administrative
  route upserts and request-time proxying both call the same checker.

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE*, *63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939

- **Design impact:** Fail-safe defaults. A mixed public+private DNS answer set
  is deny, not allow. Unresolvable hosts are deny.

Jackson, C., Barth, A., Bortz, A., Truelove, W., & Boneh, D. (2007). Protecting
browsers from DNS rebinding attacks. *Proceedings of the 14th ACM Conference on
Computer and Communications Security*, 421–431.
https://doi.org/10.1145/1315245.1315298

- **Design impact:** CIDR allowlist exceptions apply per resolved address so a
  private-range answer cannot exempt a sibling metadata or link-local record.
  Blocking OS DNS is offloaded from Tokio workers with a two-second timeout.
  After evaluation succeeds, the HTTP client connects only to those addresses
  (original Host/SNI preserved) so a rebinding answer cannot reach a denied
  class. The ACM paper is not redistributed.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** PW.1 — well-secured software. Kubernetes NetworkPolicy
  remains defense in depth; application checks are mandatory.

## Operator next action

If a legitimate internal origin is denied, add it to `DESTINATION_ALLOWLIST`
(`host`, `*.suffix`, or `CIDR`) and restart. A CIDR entry also authorizes
non-default ports on matching addresses. To block a previously allowed name,
put it in `DESTINATION_DENYLIST`. Loopback development still permits
loopback-class destinations so local fixtures work; production non-loopback
listeners use the strict class list. `/healthz.destination_mode` reports
`production` or `development`. CIDR prefixes outside `/32` (IPv4) or `/128`
(IPv6) fail startup. Deprecated IPv6 site-local (`fec0::/10`) is a denied
class. Hostnames that merely contain `0x` (for example `0x0.st`) are not
treated as hex IP literals. Outbound HTTP does not re-query OS DNS: it
connects to the evaluated addresses only.
