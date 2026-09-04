# Changelog

## Unreleased

### Security

- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.

### Operations

- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
- Clarified the public `RuntimeConfiguration` bootstrap contract after the September 2026 removal of `credentials_path`: external callers now keep credential-file selection in `CredentialRegistry` and use `RuntimeConfiguration` only for non-secret runtime settings.
