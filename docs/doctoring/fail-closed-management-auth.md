# Doctoring — fail-closed management authentication

This note grounds the issue #78 implementation (non-loopback listeners refuse to
become ready without a write-capable admin principal; `401` vs `403`;
constant-time secret compare). IEEE PDFs are not redistributed; freely licensed
standards are cited by URL.

## Adopted standards and literature

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE*, *63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939

- **Design impact:** Fail-safe defaults — a missing access rule is deny, not
  allow. Wardnet previously treated an empty credential registry as “auth
  disabled” for management writes. That violates fail-safe defaults as soon as
  `BIND_ADDR` is not loopback-only. Startup now refuses readiness in that case.

OWASP Foundation. (2025). *OWASP Application Security Verification Standard
5.0.0*. https://owasp.org/www-project-application-security-verification-standard/

- **Design impact:** ASVS V6 authentication and V4 access control require
  authentication for administrative functions and distinct authorization
  outcomes. Management writes use `401` when no valid principal is presented and
  `403` when a readonly principal attempts a mutation. Bodies do not name the
  expected secret or role.

National Institute of Standards and Technology. (2022). *Secure Software
Development Framework (SSDF) version 1.1* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** PW.1 / PW.5 — produce well-secured software and protect
  authentication data. Secrets bootstrap into `CredentialRegistry`; health
  exposes `credentials_source` and `auth_mode` labels only.

MITRE. (n.d.). *CWE-306: Missing authentication for critical function*.
https://cwe.mitre.org/data/definitions/306.html

- **Design impact:** Management APIs that mutate routes, threat indicators,
  DNSBL, license, and feeds are critical functions. The CWE-306 anti-pattern is
  “auth optional on a reachable listener.” The shipped gate is
  `require_write_auth_for_bind` in `src/credentials.rs`, invoked from
  `run_from_env` before `TcpListener::bind`.

## Exact-head binding

| Decision | Implementation |
| --- | --- |
| Fail closed on public bind | `require_write_auth_for_bind` + `run_from_env` |
| Loopback development remains usable | `listen_is_loopback_only`; `/healthz.auth_mode=development` |
| 401 vs 403 | `reject_management_write` |
| Constant-time compare | `constant_time_eq` mixes a length-inequality flag, not `(len ^ len) as u8` |
| Blank credentials path | empty/whitespace `WAF_IDS_CREDENTIALS_PATH` is unset |
| Smoke-test token | `scripts/smoke.sh` generates a per-process secret (CWE-798) |
| Ambiguous token registry | `parse_admin_tokens_strict` (duplicate / blank / unknown role) |

PII is **not** masked on security events: SOC operators cannot do their job if
client IPs, paths, and indicator values are redacted. Access control, audit,
and encryption-at-rest (when a durable store lands) are the alternatives to
masking. See `docs/product-technical-gap-baseline.md`.
