# Threat Model

## Assets

- Gateway route configuration
- Threat indicators and DNSBL entries
- Security event history
- License and tenant metadata
- Admin token
- Upstream service availability
- State file integrity

## Trust Boundaries

- Public HTTP clients enter through `/gateway/{path}`.
- Operators use management APIs and the embedded admin console.
- Upstream services are outside the process trust boundary.
- The state file is trusted only after JSON deserialization succeeds.
- A non-loopback listener is untrusted until a write-capable admin principal exists in the credential registry. This follows the fail-secure and authenticator-management posture documented in the production guide and runbook: start closed, bootstrap secrets into the registry, then expose the listener only after a usable write credential exists.
- Threat feed import payloads are untrusted operator-supplied data.

## Security Grounding

The startup gate and secret-handling path in this PR are aligned with NIST guidance that authentication secrets need lifecycle control and protected handling, and that authenticators should fail securely instead of silently degrading to weaker access. Wardnet applies that by preferring `WAF_IDS_CREDENTIALS_PATH`, allowing env only as bootstrap transport, and refusing non-loopback readiness when no usable write credential can be presented through `X-Admin-Token`. The operator recovery path is documented in [docs/deployment/production.md](../deployment/production.md), and the accepted bootstrap sources and RBAC shapes are documented in [docs/runbooks/operations.md](../runbooks/operations.md).

### Research artifact redistribution assessment

The authentication-specific NIST SP 800-57 Part 1 Rev. 5 and NIST SP 800-63B sources below remain linked to their authoritative publication records and summarized here; this PR does not republish copies of those two PDFs because the exact retrieved artifacts were not independently assessed for redistribution during this change. Separately, the branch retains `docs/papers/nist-sp-800-218-ssdf.pdf` as redistributable NIST SP 800-218 Version 1.1 evidence for the secure-development and credential-bootstrap boundary. Its authoritative source, redistribution basis, attribution, and final-versus-draft status are recorded in [docs/doctoring/fail-closed-management-auth.md](../doctoring/fail-closed-management-auth.md). The repository copy is evidence only and does not supersede NIST's publication.

## Primary Threats

| Threat | Impact | Current Control | Required Hardening |
| --- | --- | --- | --- |
| Unauthorized management write | Route takeover or false blocking | `X-Admin-Token` write gate; multi-token RBAC with actor labels and readonly role; fail-closed startup on non-loopback bind without a write-capable principal; `401` vs `403` without revealing the expected role; audit log for successful writes | SSO/OIDC, mTLS or identity proxy, SCIM |
| Malicious threat feed import | False positives or broad blocks | Validation, route-scoped enforcement | Source signing, feed confidence, staged promotion |
| State file corruption | Startup failure or stale policy | JSON parse failure surfaces startup error | Database, backup, schema migration |
| Upstream SSRF through routes | Internal network exposure | Upstream scheme validation | Upstream allowlists, egress policy |
| Gateway DoS | Availability loss | Rust memory safety, event retention limit | Rate limits, body limits, async event sink |
| DNSBL abuse | Reputation damage | Loopback response-code validation | Authoritative DNS service, signing, publisher workflow |
| Secret disclosure | Admin compromise | Support bundle excludes admin token; secrets bootstrapped into credential registry (`WAF_IDS_CREDENTIALS_PATH` preferred over long-lived env); health exposes source label only | External secret manager / SSO, rotation, access review |

## Human Approval Boundary

AI SOC recommendations may explain, summarize, or suggest actions, but enforcement-changing decisions must remain human-approved until audit trails, rollback, and policy simulation are implemented.

## References

Barker, E. (2020). *Recommendation for key management: Part 1 - General* (NIST SP 800-57 Part 1 Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Grassi, P. A., Garcia, M. E., & Fenton, J. L. (2020). *Digital identity guidelines: Authentication and lifecycle management* (NIST SP 800-63B). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-63b

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
