# Changelog

## Unreleased

### Security

- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.
- Added an explicit runtime deployment/state-authority contract: standalone operation may select memory or JSON-file state, while production requires `WARDNET_STATE_AUTHORITY=postgres` and never infers production from the listener address. Until #80 wires the durable PostgreSQL repository/RLS/migration adapter, selecting PostgreSQL fails before listener startup instead of silently downgrading to a weaker state backend.
- Added the first durable PostgreSQL source-generation schema: immutable tenant/source generation and ordinal identities, default-deny forced RLS, transaction-local tenant admission, and credential-free provenance references. The production repository adapter remains disabled until its separate port and transaction contracts are complete.
- Added the next durable PostgreSQL publication boundary: immutable publication evidence, exact-prior compare-and-swap, strictly increasing source-generation ordinals, atomic last-known-good advancement, rollback-safe failure semantics, tenant-scoped forced RLS, and a least-privilege `SECURITY DEFINER` capability so the runtime role does not receive direct publication mutation authority. Production PostgreSQL selection remains disabled pending #80 deployment-role, repository, pooling, migration/recovery, and backup/restore acceptance.

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
- Documented the production state-authority boundary in `docs/architecture.md`, including the explicit #80 durable-adapter prerequisite and the distinction between current final NIST SP 800-218 / SSDF 1.1 and the December 2025 SP 800-218 Rev. 1 / SSDF 1.2 Initial Public Draft.