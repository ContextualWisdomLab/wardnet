# Changelog

## Unreleased

### Security

- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.
- Forwarded client IP headers are now ignored unless the direct peer matches `TRUSTED_PROXY_CIDRS`. Trusted chains are parsed right to left, malformed chains fail closed to the peer address, and IPv4-mapped trusted peers normalize correctly before rate limiting and DNSBL attribution.

### Operations

- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
