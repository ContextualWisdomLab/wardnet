# Changelog

## Unreleased

### Security

- Added the independently deployable Agent Artifact Admission Controller for authenticated, loopback-only, fail-closed pre-execution package-install admission. Reviewed policy binds workspace manifests and exact artifact ecosystem/name/version/HTTPS registry/owner/SHA-256 evidence, structured argv, minimized append-before-response audit evidence, and deny-all defaults without taking over hostile-workload execution from the quarantine runtime.
- Hardened package-manager command admission so approved artifacts cannot be reinterpreted by a different package-manager ecosystem or widened through alternate package sources, destinations, executable install hooks, parser boundaries, or opaque runtime configuration: standalone `--` option terminators are rejected so required safety flags cannot move behind a downstream CLI parsing boundary; npm-family commands bind to npm artifacts, pip/uv pip to PyPI, Cargo to Cargo, and Docker/Podman to OCI; npm caller-selected `--userconfig`/`--globalconfig` files and `--ca`/`--cafile`/`--strict-ssl` TLS trust overrides, pip source/root short and long forms, uv index/environment selectors, Cargo registry/Git/path/config/root selectors, npm workspace controls, pnpm `--dir`/`-C` working-directory, filter/recursive/workspace-root selectors, `--config.<key>=<value>` runtime overrides, and pnpmfile hooks not suppressed by `--ignore-scripts`, Yarn Classic `-W`/`--ignore-workspace-root-check`, Bun `--cwd`/`--filter`/`-F` workspace selectors and caller-supplied `--config`, and contradictory lifecycle-script Boolean flags fail closed with stable reason codes. Admitted pnpm installs now require both `--ignore-scripts` and `--ignore-pnpmfile`.
- Removed the distributable Kubernetes administrator `Secret` and historical placeholder credential. Production deployments must provision `waf-ids-ai-soc-admin` / `ADMIN_TOKEN` through the external secret-management control plane; the workload's `secretKeyRef` is explicitly non-optional.
- Added a structural regression contract that rejects shipped administrator Secret objects, placeholder credentials, decoy workloads, init-container false positives, and optional administrator Secret references.

### Operations

- Documented Agent Artifact Admission deployment, incident response, immutable policy rollout, audit durability, external provenance authority, package-manager ecosystem binding, package-manager trust/destination/parser controls, and current primary-source traceability.
- Documented administrator credential provisioning, rotation, rollout verification, rollback, evidence handling, and the boundary with the separate runtime-authentication fail-closed work tracked in issue #78.
