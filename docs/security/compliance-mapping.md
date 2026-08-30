# Compliance Mapping

This document maps the commercial baseline to common enterprise security review expectations. It is not a certification claim.

| Area | Baseline Evidence | Gap Before Regulated Production |
| --- | --- | --- |
| Secure SDLC | Rust implementation, tests, clippy, smoke script, tagged keyless Cosign + SPDX SBOM + SLSA attestations | Admission that rejects unsigned tags, hermetic reproducible builds |
| Access Control | `ADMIN_TOKEN` / multi-token RBAC (`token:actor:role`, including readonly) for write APIs and audit-log read | SSO/OIDC, SCIM, MFA enforcement |
| Auditability | Security events and support bundle | Immutable admin audit log |
| Data Protection | No default external telemetry, no secrets in support bundle | Encryption at rest, retention policy |
| Change Control | Route-scoped monitor/block modes | Approval workflow and rollback attestations |
| Availability | Health endpoint, Kubernetes probes | HA storage, multi-replica state backend |
| Incident Response | Operations runbook and support bundle | On-call process, SLA/SLO reporting |
| Threat Intelligence | Feed import API, STIX/MISP/OpenCTI document ingest, TAXII 2.1 poll, feed status | Signed feeds, live MISP REST / OpenCTI GraphQL pull |
| DNSBL | Zone export and response-code validation | Authoritative DNS service and publication controls |
| AI Governance | Human approval boundary documented | Model evals, prompt audit, recommendation traceability |

## Review Position

The project can support buyer lab validation and paid pilot discussions after this baseline. It should not be represented as fully compliant for PCI DSS, ISO 27001, SOC 2, or regulated production without the remaining controls above.

## Standards grounding

NIST. (2022). *Secure software development framework (SSDF) version 1.1:
Recommendations for mitigating the risk of software vulnerabilities*
(SP 800-218). https://doi.org/10.6028/NIST.SP.800-218

- Design impact: the Secure SDLC row is evidence-bound to build, test, and
  attestation artifacts rather than a policy-only claim, and the regulated
  production gap stays explicit until signed release admission and hermetic
  verification are proven on protected `main`.

American Institute of Certified Public Accountants. (2017). *Trust services
criteria for security, availability, processing integrity, confidentiality,
and privacy*.

- Design impact: the table is organized around buyer-review control families
  such as access control, auditability, availability, and change control, but
  it remains a gap map instead of a certification statement.
