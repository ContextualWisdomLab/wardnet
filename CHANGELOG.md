# Changelog

## Unreleased

### Security

- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.
- Added a source-bound release-evidence workflow that produces a deterministic release archive, SHA-256 evidence, SPDX JSON SBOM, and protected-main GitHub/Sigstore provenance and SBOM attestations without granting the workflow publication authority.

### Operations

- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
- Added an executable release-workflow architecture contract and supply-chain decision record. Full immutable publication, OCI promotion, production-shaped attack verification, and rehearsed rollback remain tracked by issue #84.
