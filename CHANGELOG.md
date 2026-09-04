# Changelog

## Unreleased

### Security

- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.

### Operations

- Renamed the hardened Kubernetes deployment asset from `deploy/kubernetes/waf-ids-ai-soc.yaml` to `deploy/kubernetes/wardnet.yaml` without renaming in-cluster resources. Operators and GitOps/package references must use the new repository path; rollback to a pre-migration source revision uses that revision's old path.
- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
