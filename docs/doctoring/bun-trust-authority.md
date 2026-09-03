# Bun trust authority in Agent Artifact Admission

## Decision

Wardnet treats Bun's `--trust` install flag as an admission-time trust-authority mutation, not as ordinary package-manager argument detail. An otherwise approved command such as `bun install @cwl/example@1.2.3 --ignore-scripts --trust` must fail closed with `alternate_trust_root`.

The immediate `--ignore-scripts` flag suppresses lifecycle scripts for that invocation, but it does not make `--trust` harmless. Bun documents `--trust` as adding the package to `trustedDependencies` in the project's `package.json`. Bun also documents `trustedDependencies` as the allow list that permits dependency lifecycle scripts to execute on later installs. Therefore accepting `--trust` would allow one admitted request to persistently widen future code-execution authority beyond the reviewed `ApprovedArtifact` contract.

Wardnet does not own Bun's package lifecycle policy and does not try to model or rewrite `package.json`. It only prevents the caller from changing that external authority through an admitted command. The execution broker and quarantine runtime remain responsible for independently verifying retrieved bytes and enforcing filesystem, process, mount and network isolation.

## TDD evidence

- RED `e88429e37f5c4680e061a93941436ce90224143c`: `bun_trust_authority_contract.rs` requires an approved Bun install that appends `--trust` to be blocked as `alternate_trust_root`.
- Causal repair `8f7c4775822f40f9bdbe1773281ef5ab2125650a`: `requests_alternate_trust_root` rejects Bun `--trust` through the same bounded CLI-flag parser used for other trust-root selectors.
- Exact-head execution remains fail-closed/non-passing until the repository runner acquires the current head and executes the regression; predecessor workflow results do not satisfy this evidence requirement.

## Primary-source traceability

Bun's current package-manager documentation states that lifecycle scripts are arbitrary code and that installed dependencies run them only when trusted. The `trustedDependencies` field is the project allow list for that behavior. The `bun install` CLI contract states that `--trust` adds packages to `trustedDependencies` in `package.json`, while `--ignore-scripts` skips lifecycle scripts for the current install. The combination therefore separates immediate execution suppression from persistent future trust mutation.

### References

Bun Contributors. (2026). *bun install*. Bun documentation. https://bun.com/docs/pm/cli/install

Bun Contributors. (2026). *Lifecycle scripts*. Bun documentation. https://bun.com/docs/pm/lifecycle
