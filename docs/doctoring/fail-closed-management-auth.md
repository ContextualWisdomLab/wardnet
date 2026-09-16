# Doctoring — fail-closed management authentication

This note grounds the issue #78 implementation: non-loopback listeners refuse to become ready without a write-capable administrator principal, authentication and authorization failures remain distinct, and presented administrator secrets are compared without early-exit content comparison. IEEE PDFs are not redistributed; freely accessible standards are cited by stable locators.

## Adopted standards and literature

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308. https://doi.org/10.1109/PROC.1975.9939

- **Design impact:** Fail-safe defaults require missing access authority to deny rather than silently enable management writes. Wardnet therefore refuses readiness when a non-loopback listener lacks a write-capable administrator credential.

OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/

- **Design impact:** Administrative functions require authentication and authorization. Wardnet returns `401` for an unauthenticated management request and `403` when an authenticated readonly principal attempts a mutation, without disclosing the expected secret or role.

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

- **Design impact:** Authentication data is loaded through the credential bootstrap boundary rather than embedded in distributable assets. Health output exposes only non-secret configuration state such as authentication mode and credential source.

MITRE. (n.d.). *CWE-306: Missing authentication for critical function*. https://cwe.mitre.org/data/definitions/306.html

- **Design impact:** Management APIs that mutate routes, threat indicators, DNSBL entries, license state, or feeds are critical functions. The runtime gate rejects the unsafe combination of a reachable non-loopback listener and missing write-capable authentication.

## Redistributable research artifact

`docs/papers/nist-sp-800-218-ssdf.pdf` is the NIST SP 800-218 Version 1.1 PDF published by the National Institute of Standards and Technology. Authoritative source: https://doi.org/10.6028/NIST.SP.800-218 (NIST publication record and official PDF). NIST states that SP 800-series publications are not subject to copyright in the United States and that attribution is appreciated; NIST's Technical Series policy also grants a worldwide royalty-free right to reprint covered NIST works. The repository therefore retains the exact PDF as research evidence with this attribution: “Republished courtesy of the National Institute of Standards and Technology.” The publication remains authoritative at NIST; the repository copy is evidence only and does not supersede the official source.

NIST SP 800-218 Rev. 1 / SSDF 1.2 is still an Initial Public Draft as of this doctoring update, so the implemented control continues to cite final SP 800-218 Version 1.1 rather than presenting the draft as a final standard.

## Implementation binding

| Decision | Implementation boundary |
| --- | --- |
| Fail closed on public bind | `require_write_auth_for_bind` before listener readiness |
| Loopback development remains usable | loopback-only listener detection and `/healthz.auth_mode=development` |
| Authentication vs authorization | management write rejection distinguishes `401` and `403` |
| Constant-time credential handling | administrator-token comparison uses a bounded constant-work comparison path |
| Blank credential path | an empty or whitespace credentials-path bootstrap value is treated as unset |
| Smoke-test credential | `scripts/smoke.sh` creates a per-process administrator token instead of shipping a repository credential |
| Ambiguous token registry | strict administrator-token parsing rejects duplicate, blank, or unknown-role entries |

PII is not blanket-masked from security evidence when doing so would make incident response unusable. Purpose-bound authorization, least privilege, auditability, retention controls, and encryption are the preferred controls for operationally necessary security data.
