# Changelog

All notable changes to Wardnet are documented in this file.

## [Unreleased]

### Added

- Preserved LiteLLM credential-guard evidence for a future released
  Contextual Orchestrator consumer, including the versioned runtime-configuration
  contract, stable rejection codes, bounded header grammar, approved header
  projection, streaming relay invariants, and property/fuzz coverage.
- Added a runtime contract test proving SOC analysis emits
  `orchestration_mode: "auto"` without serializing a concrete provider or model.

### Security

- Removed the standalone distributable `litellm-virtual-key-proxy` entrypoint.
  Wardnet now preserves the boundary evidence without shipping a direct
  provider-specific proxy from this repository.
- Reject telephone-shaped, missing, duplicate, wrong-scheme, malformed, non-ASCII, excessive-whitespace, and oversized credentials before LiteLLM upstream I/O.
- Bound the complete Authorization value before UTF-8 conversion, delimiter lookup, or whitespace scanning.
- Prevent rejected credentials and masked fragments from entering response bodies or structured proxy events.
- Strip cookies, trace baggage, forwarding-chain headers, proxy credentials, host routing, transfer framing, caller-controlled LiteLLM extensions, and arbitrary caller metadata at the LLM proxy boundary.
- Reject upstream URLs containing credentials, path prefixes, queries, or fragments; require HTTPS for operational configuration; disable ambient system proxies and redirect following.
- Convert upstream redirects to a local cache-safe 502 without returning or following the redirect target.
- Reject CONNECT, TRACE, and extension methods before upstream I/O.
- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.

### Operations

- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
