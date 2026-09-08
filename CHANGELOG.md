# Changelog

## Unreleased

### Security

- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.

### Operations

- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
- Clarified the public `RuntimeConfiguration` bootstrap contract after the
  September 2026 removal of `credentials_path`: external callers now keep
  credential-file selection in `CredentialRegistry` and use
  `RuntimeConfiguration` only for non-secret runtime settings. This separation
  follows least privilege and fail-safe bootstrap boundaries rather than
  treating process env as long-lived application authority; see Saltzer and
  Schroeder (1975), NIST SP 800-57 Part 1 Rev. 5, and the repository copy at
  `docs/papers/nist-sp-800-57-part-1-rev-5.pdf`.
