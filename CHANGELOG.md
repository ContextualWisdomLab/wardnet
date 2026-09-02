# Changelog

## Unreleased

### Security

- Added the independently deployable Agent Artifact Admission Controller for authenticated, loopback-only, fail-closed pre-execution package-install admission. Reviewed policy binds workspace manifests and exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 evidence, structured argv, minimized append-before-response audit evidence, and deny-all defaults without taking over hostile-workload execution from the quarantine runtime.
- Hardened package-manager command admission so approved artifacts cannot be widened through alternate package sources or destinations: pip source/root short and long forms, uv index/environment selectors, Cargo registry/Git/path/config/root selectors, npm-family global/prefix/location/workspace-scope controls, and contradictory lifecycle-script Boolean flags fail closed with stable reason codes.
- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.

### Operations

- Documented Agent Artifact Admission deployment, incident response, immutable policy rollout, audit durability, external provenance authority, and package-manager trust/destination controls with current primary-source traceability.
- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
