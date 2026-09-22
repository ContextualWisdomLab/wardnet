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
- A configured Coraza sidecar is an external security-decision authority. Wardnet accepts it only over loopback with redirects and ambient proxies disabled, forwards a complete bounded credential-minimized request envelope, rejects unrepresentable or truncated allowlisted headers before sidecar authorization, and requires every accepted clean or disruptive verdict to echo the current request's Wardnet correlation identifier plus matching method/URI. An unconfigured engine and malformed, oversized, stale, uncorrelated, timed-out, or unreachable evidence is `engine_unavailable`; block-mode routes fail closed.

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
| WAF authority confusion, stale verdict replay, or sidecar spoofing | Attack bypass or false block | Loopback-only/no-redirect/no-ambient-proxy Coraza sidecar; process-distinguishable request correlation echoed by every accepted verdict; exact method/URI context; bounded response/time; explicit `engine_unavailable` evidence | Pin/inventory production Coraza + CRS release identity and expose configuration through the Runtime Configuration owner lane |
| DNSBL abuse | Reputation damage | Loopback response-code validation | Authoritative DNS service, signing, publisher workflow |
| Secret disclosure | Admin compromise | Support bundle excludes admin token; secrets bootstrapped into credential registry (`WAF_IDS_CREDENTIALS_PATH` preferred over long-lived env); health exposes source label only | External secret manager / SSO, rotation, access review |

The Coraza correlation identifier is not an authentication credential. Its purpose is to prevent Wardnet from applying a valid verdict to the wrong request. Transport locality, no-proxy/no-redirect behavior, explicit sidecar deployment authority, and pinned Coraza/CRS identity remain separate controls; the correlation field must not be treated as a substitute for them.

## Human Approval Boundary

AI SOC recommendations may explain, summarize, or suggest actions, but enforcement-changing decisions must remain human-approved until audit trails, rollback, and policy simulation are implemented.

## References

Barker, E. (2020). *Recommendation for key management: Part 1 - General* (NIST SP 800-57 Part 1 Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-57pt1r5

Grassi, P. A., Garcia, M. E., & Fenton, J. L. (2020). *Digital identity guidelines: Authentication and lifecycle management* (NIST SP 800-63B). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-63b

National Institute of Standards and Technology. (2007). *Guide to intrusion detection and prevention systems (IDPS)* (NIST Special Publication 800-94). https://doi.org/10.6028/NIST.SP.800-94

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308. https://doi.org/10.1109/PROC.1975.9939
