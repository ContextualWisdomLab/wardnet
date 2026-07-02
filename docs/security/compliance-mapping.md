# Compliance Mapping

This document maps the commercial baseline to common enterprise security review expectations. It is not a certification claim.

| Area | Baseline Evidence | Gap Before Regulated Production |
| --- | --- | --- |
| Secure SDLC | Rust implementation, tests, clippy, smoke script | Signed releases, SBOM, SAST/DAST gates |
| Access Control | `ADMIN_TOKEN` for write APIs | SSO, RBAC, SCIM, MFA enforcement |
| Auditability | Security events and support bundle | Immutable admin audit log |
| Data Protection | No default external telemetry, no secrets in support bundle | Encryption at rest, retention policy |
| Change Control | Route-scoped monitor/block modes | Approval workflow and rollback attestations |
| Availability | Health endpoint, Kubernetes probes | HA storage, multi-replica state backend |
| Incident Response | Operations runbook and support bundle | On-call process, SLA/SLO reporting |
| Threat Intelligence | Feed import API and feed status | Signed feeds, TAXII/MISP/OpenCTI adapters |
| DNSBL | Zone export and response-code validation | Authoritative DNS service and publication controls |
| AI Governance | Human approval boundary documented | Model evals, prompt audit, recommendation traceability |

## Review Position

The project can support buyer lab validation and paid pilot discussions after this baseline. It should not be represented as fully compliant for PCI DSS, ISO 27001, SOC 2, or regulated production without the remaining controls above.
