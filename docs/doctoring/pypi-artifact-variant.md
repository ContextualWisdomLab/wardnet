# PyPI artifact and build-variant admission traceability

Verified 2026-09-04 against the current pip documentation. This note records why caller-selected pip compatibility and source-build controls are security-artifact identity inputs in Wardnet. It does not claim that Wardnet executes pip, verifies downloaded bytes, or owns the hostile execution runtime.

## Decision

An approved PyPI coordinate currently binds ecosystem, package name, version, registry, publisher label, SHA-256, and the exact package operand. It does not bind wheel compatibility tags, source-distribution selection, build isolation, or PEP 517 backend settings. Until the policy schema represents those dimensions explicitly, an untrusted install intent must not add pip options that can select a different distribution artifact or change source-build behavior.

Wardnet therefore fails closed as `artifact_not_approved` when submitted `pip install` / `pip3 install` argv contains `--platform`, `--python-version`, `--implementation`, `--abi`, `--no-binary`, `--only-binary`, `--prefer-binary`, `--no-build-isolation`, or `-C` / `--config-settings`. The execution broker remains responsible for independently verifying the retrieved artifact digest/provenance before installation; an admission `allow` receipt is not execution authority.

## Evidence

The pip install reference states that `--platform`, `--python-version`, `--implementation`, and `--abi` change the set of compatible wheels considered during installation. It also documents `--no-binary` and `--only-binary` as controls over source versus binary distributions. `--no-build-isolation` disables the isolated environment normally used while building a modern source distribution, while `-C` / `--config-settings` passes caller-selected settings to the build backend. These controls can therefore change which bytes or build path a name/version request resolves to without changing Wardnet's current artifact coordinate.

This follows the same least-authority rule already applied to OCI platform selection: approval for an abstract coordinate is not approval for a caller-selected artifact variant that the policy does not encode. NIST SSDF requires software integrity and secure development controls to be explicit and verifiable; Wardnet applies that principle by refusing to infer missing artifact/build dimensions.

## RED → GREEN

RED commit `9f11a7f90902c83f796aeda990f33425739b9c46` added hostile regressions proving that the previously accepted PyPI command could carry caller-selected wheel compatibility selectors or source-build/backend controls. Production repair `a23583a533babf256ad81e9c882759662fe33f2b` generalized the artifact-variant predicate beyond OCI, and `b3336704f346a174a7ea9fcc4b0403ef22a8c06b` routed admission through the generalized guard. Exact-head hosted CI/security evidence must still execute on the resulting branch head before this candidate is integration-ready.

## References

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

pip developers. (2026). *pip install: pip documentation.* Retrieved September 4, 2026, from https://pip.pypa.io/en/latest/cli/pip_install/

pip developers. (2026). *Repeatable installs: pip documentation.* Retrieved September 4, 2026, from https://pip.pypa.io/en/latest/topics/repeatable-installs/
