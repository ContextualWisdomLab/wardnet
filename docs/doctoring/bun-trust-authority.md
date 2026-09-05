# Bun trust and integrity authority in Agent Artifact Admission

## Decision

Wardnet treats Bun's `--trust` install flag as an admission-time trust-authority mutation, not as ordinary package-manager argument detail. An otherwise approved command such as `bun install @cwl/example@1.2.3 --ignore-scripts --trust` must fail closed with `alternate_trust_root`.

The immediate `--ignore-scripts` flag suppresses lifecycle scripts for that invocation, but it does not make `--trust` harmless. Bun documents `--trust` as adding the package to `trustedDependencies` in the project's `package.json`. Bun also documents `trustedDependencies` as the allow list that permits dependency lifecycle scripts to execute on later installs. Therefore accepting `--trust` would allow one admitted request to persistently widen future code-execution authority beyond the reviewed `ApprovedArtifact` contract.

Wardnet also rejects Bun's `--no-verify` option. Bun documents this option as skipping integrity verification of newly downloaded packages. An admission policy that binds an exact artifact SHA-256 must not authorize the caller to disable a package-manager integrity control on the same install path. The downstream execution broker/quarantine path still independently verifies retrieved bytes; retaining Bun's native integrity verification is defense in depth rather than a transfer of runtime-isolation ownership.

Wardnet does not own Bun's package lifecycle policy and does not try to model or rewrite `package.json`. It prevents callers from changing persistent trust or disabling integrity verification through an admitted command. The execution broker and quarantine runtime remain responsible for independently verifying retrieved bytes and enforcing filesystem, process, mount and network isolation.

## TDD evidence

- RED `e88429e37f5c4680e061a93941436ce90224143c`: `bun_trust_authority_contract.rs` requires an approved Bun install that appends `--trust` to be blocked as `alternate_trust_root`.
- Causal repair `8f7c4775822f40f9bdbe1773281ef5ab2125650a`: `requests_alternate_trust_root` rejects Bun `--trust` through the same bounded CLI-flag parser used for other trust-root selectors.
- RED `af3341e533d89423f00a0a749343286e694bd4b6`: `bun_integrity_verification_contract.rs` requires `--no-verify` to block rather than disable Bun's registry integrity verification.
- Causal repair `26eca37817f91b8537ff9e33216059b2bb8925d3`: Bun safety validation treats `--no-verify` as an explicit failure of the mandatory hardening baseline and emits `missing_safety_flag`.
- Exact-head execution remains fail-closed/non-passing until the repository runner acquires the current head and executes both regressions; predecessor workflow results do not satisfy this evidence requirement.

## Primary-source traceability

Bun's current package-manager documentation states that lifecycle scripts are arbitrary code and that installed dependencies run them only when trusted. The `trustedDependencies` field is the project allow list for that behavior. The `bun install` CLI contract states that `--trust` adds packages to `trustedDependencies` in `package.json`, while `--ignore-scripts` skips lifecycle scripts for the current install. The same CLI contract states that `--no-verify` skips integrity verification of newly downloaded packages. These controls affect distinct authorities: immediate script execution, persistent future script trust, and downloaded-package integrity.

### References

Bun Contributors. (2026). *bun install*. Bun documentation. https://bun.com/docs/pm/cli/install

Bun Contributors. (2026). *Lifecycle scripts*. Bun documentation. https://bun.com/docs/pm/lifecycle
