# Agent Artifact Admission threat model

This document is scoped to the **Agent Artifact Admission** bounded context recorded in ADR-0012. It does not replace Wardnet's gateway threat model. The admission controller decides whether a structured package-install intent is admissible; it never installs a package or executes a command.

## Protected assets and authority

The protected assets are the reviewed admission policy, approved workspace-manifest digests, approved artifact coordinates and digests, the administrator credential, the minimized audit trail, and the integrity of each allow/block receipt.

Authority is deliberately narrow. Untrusted web pages, `llms.txt`, retrieved documents, issue comments, model output, tool output, package metadata, and an artifact's mere presence in a registry are evidence inputs only. None can grant execution authority. The reviewed `AdmissionPolicy` is the local authority for v0.1. Registry identity, signing identity, transparency-log inclusion, TUF metadata, and SLSA provenance remain external authorities and must enter through explicit adapters or an Anti-Corruption Layer rather than becoming domain entities.

## Trust boundaries

1. An execution broker or AI coding agent submits an authenticated HTTP request to the loopback-only service.
2. The HTTP delivery adapter authenticates the request and deserializes a bounded `InstallIntent`.
3. The domain kernel validates provenance, command shape, workspace manifest, exact artifact coordinates, registry, owner and SHA-256 evidence against the immutable policy.
4. The application path builds a minimized audit fact and must durably append it before any admission response is returned.
5. A downstream execution broker may act on an `allow` receipt. Wardnet itself still does not execute the command.

The credential file, policy/configuration file and audit file are local deployment dependencies. A future remote deployment must remain behind authenticated TLS/mTLS or an equivalent identity-aware proxy; v0.1 binds only to loopback.

## Threats and required behavior

| Threat | Failure mode | Required control | Failure response |
| --- | --- | --- | --- |
| Prompt-to-code dependency confusion | Untrusted text names an attacker-controlled or newly claimed package | Exact reviewed ecosystem/name/version/registry/owner/digest match; source text has no authority | `decision=block` |
| Unpinned or mutable dependency | Version range, missing digest or changed artifact is admitted | Exact version and SHA-256 are mandatory | `decision=block` |
| Registry substitution | Look-alike or alternate registry serves a package with the same name | Exact HTTPS registry identity is part of the approved artifact coordinate | `decision=block` |
| Direct download-and-execute | Agent bypasses package policy using curl/wget/shell/runtime evaluation | Structured `argv`; shells, direct downloaders, package executors and runtime inline evaluation remain blocked by invariant | `decision=block` |
| Alternate install-root escape | An otherwise approved package-manager command adds global, user, prefix, target or root flags so writes escape the broker-selected workspace boundary | Reject explicit package-manager install-root overrides before returning `allow`; runtime filesystem isolation remains the execution broker/quarantine responsibility | `decision=block`, reason `alternate_install_root` |
| Malformed or missing provenance | Remote instruction source lacks HTTPS or content digest | Strict source-kind validation and SHA-256 requirement | `400` with audited block receipt |
| Authentication bypass | Caller omits, duplicates or manipulates the admin token | One bounded visible-ASCII token from the credentials file; constant-time comparison; no environment-variable secret path | `401` |
| Oversized request | Memory/CPU pressure or parser bypass using excessive body size | Axum body limit plus bounded configuration | `413`, and the rejection must be audited before response |
| Audit suppression | Allow response is returned without durable evidence | Audit append is ordered before response | `503`, `decision=block`, reason `audit_unavailable` |
| Audit data exfiltration | Raw command text, token or unbounded source material leaks to logs | Audit only normalized source URI, command hash, artifact coordinates, decision and reason codes | Fail closed if a valid minimized audit record cannot be built |
| Policy/provider schema coupling | Sigstore/TUF/SLSA DTO changes alter domain semantics implicitly | Translate provider evidence at explicit adapters/ACLs; domain depends only on stable admission concepts | Reject unsupported evidence until an accepted adapter exists |
| Cross-context authority leakage | Main gateway, SIEM exporter or orchestrator mutates admission policy by reaching into internals | Published API/package contract only; no foreign application-table access; no provider SDK in domain modules | Integration rejected by architecture fitness gate |
| Confused transport vs policy denial | Downstream treats a policy block as network failure and retries/works around it | Valid policy denials are successful admission responses with `decision=block`; transport/config/audit failures use HTTP errors | Stable receipt semantics |

## Abuse cases

A document can legitimately mention `npm install`, a package name, a CVE, or a URL. Those strings are not executable instructions at this boundary. An agent must first construct a structured intent, and the intent must independently satisfy policy. A package with valid Sigstore/SLSA evidence is still not locally authorized unless the reviewed policy allows its exact coordinates. Conversely, an approved coordinate without the required digest or provenance remains blocked.

The controller must not repair typos, prepend package scopes, infer maintainers, search for a similarly named package, downgrade HTTPS, transform a blocked command into an allowed one, or reinterpret an approved workspace install as permission to write into a global/user/alternate install root. Any such behavior would convert untrusted input into authority or widen the reviewed command capability.

## Operational security invariants

- `0.0.0.0`, `::`, non-loopback addresses and port `0` are invalid service configuration for v0.1.
- The administrator token is loaded from the configured credentials file. It is never returned in health, error or audit payloads.
- The deny-all example configuration is safe to start without granting package authority.
- Audit records are append-only from this process's point of view. Corruption, write failure or task failure cannot be converted into an allow response.
- Policy is immutable for the lifetime of the v0.1 process. Runtime mutation requires a future explicit policy-lifecycle aggregate and authorization contract; it must not be smuggled into the current HTTP adapter.
- Domain modules remain independent of Axum, Tokio, filesystem paths, provider SDKs and concrete storage adapters. `ddd_architecture_contract.rs` is the executable fitness gate.
- Package-manager destination overrides are admission capability changes, not ordinary argument detail. The admission kernel rejects explicit alternate-root flags, while the downstream execution broker/quarantine runtime still owns actual filesystem, mount and process isolation.

## Residual risk and future adapters

SHA-256 equality proves byte identity, not publisher trust. Registry and owner strings in a reviewed policy are local assertions until backed by independently verified provenance. Future Sigstore, TUF and SLSA support should verify external evidence and translate only the verified properties needed by the admission domain. The controller also does not sandbox an allowed installer; the execution broker remains responsible for process isolation, filesystem/network capability limits, least privilege and post-install verification. Rejecting explicit alternate-root flags narrows the command capability but does not substitute for that runtime isolation boundary.

## Primary references

- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218
- Booth, H., Souppaya, M., Vassilev, A., Ogata, M., Stanley, M., & Scarfone, K. (2024). *Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile (NIST SP 800-218A).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218A
- SLSA Community. (2025). *SLSA specification, version 1.2.* https://slsa.dev/spec/v1.2/
- The Update Framework. (2026). *Specification, version 1.0.33.* https://theupdateframework.io/spec/
- Sigstore. (2026). *Sigstore documentation: Overview and security model.* https://docs.sigstore.dev/ ; https://docs.sigstore.dev/about/security/

NIST SP 800-218 Rev. 1 / SSDF 1.2 is still a draft as of this document's 2026-09-01 verification and is tracked as informative rather than binding: https://csrc.nist.gov/Projects/ssdf/publications
