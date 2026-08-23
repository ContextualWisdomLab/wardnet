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
| Unauthorized management write | Route takeover or false blocking | `X-Admin-Token` write gate; multi-token RBAC with actor labels and readonly role; audit log for successful writes | SSO/OIDC, mTLS or identity proxy, SCIM |
| Malicious threat feed import | False positives or broad blocks | Validation, route-scoped enforcement | Source signing, feed confidence, staged promotion |
| State file corruption | Startup failure or stale policy | JSON parse failure surfaces startup error | Database, backup, schema migration |
| Upstream SSRF through routes | Internal network exposure | Scheme validation plus fail-closed destination policy (`src/destination.rs`): deny loopback/private/link-local/metadata unless allowlisted; denylist wins; no ambient HTTP proxy; no redirects. After evaluation, HTTP connects only to those IPs (Host/SNI preserved). Coraza sidecar URLs use the same policy. | Kubernetes NetworkPolicy egress as defense in depth |
| Gateway DoS | Availability loss | Rust memory safety, event retention limit | Rate limits, body limits, async event sink |
| DNSBL abuse | Reputation damage | Loopback response-code validation | Authoritative DNS service, signing, publisher workflow |
| Secret disclosure | Admin compromise | Support bundle excludes admin token; secrets bootstrapped into credential registry (`WAF_IDS_CREDENTIALS_PATH` preferred over long-lived env); health exposes source label only | External secret manager / SSO, rotation, access review |

## Human Approval Boundary

AI SOC recommendations may explain, summarize, or suggest actions, but enforcement-changing decisions must remain human-approved until audit trails, rollback, and policy simulation are implemented.
