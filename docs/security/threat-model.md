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
- Threat feed import payloads are untrusted operator-supplied data.

## Primary Threats

| Threat | Impact | Current Control | Required Hardening |
| --- | --- | --- | --- |
| Unauthorized management write | Route takeover or false blocking | `X-Admin-Token` write gate | SSO/RBAC, audit log, mTLS or identity proxy |
| Malicious threat feed import | False positives or broad blocks | Validation, route-scoped enforcement | Source signing, feed confidence, staged promotion |
| State file corruption | Startup failure or stale policy | JSON parse failure surfaces startup error | Database, backup, schema migration |
| Upstream SSRF through routes | Internal network exposure | Upstream scheme validation | Upstream allowlists, egress policy |
| Gateway DoS | Availability loss | Rust memory safety, event retention limit | Rate limits, body limits, async event sink |
| DNSBL abuse | Reputation damage | Loopback response-code validation | Authoritative DNS service, signing, publisher workflow |
| Secret disclosure | Admin compromise | Support bundle excludes admin token | Secret manager, redaction tests, access review |

## Human Approval Boundary

AI SOC recommendations may explain, summarize, or suggest actions, but enforcement-changing decisions must remain human-approved until audit trails, rollback, and policy simulation are implemented.
