# PyPI artifact and build-variant admission traceability

Verified 2026-09-04 against the current pip and Astral uv documentation plus local parser/help probes. This note records why caller-selected compatibility/build controls and resolver-driven dependency expansion are security-artifact identity inputs in Wardnet. It does not claim that Wardnet executes installers, verifies downloaded bytes, or owns hostile execution isolation.

## Decision

An approved PyPI coordinate currently binds ecosystem, package name, version, registry, publisher label, SHA-256, and the exact package operand. It does not bind wheel compatibility tags, source-distribution selection, build isolation, PEP 517 backend settings, or an undeclared transitive dependency closure. Until the policy schema represents those dimensions explicitly, an untrusted install intent must not widen them.

For `pip install` / `pip3 install`, Wardnet fails closed as `artifact_not_approved` when argv carries caller-selected `--platform`, `--python-version`, `--implementation`, `--abi`, `--no-binary`, `--only-binary`, `--prefer-binary`, `--no-build-isolation`, or `-C` / `--config-settings`. The `-C` guard covers separated and attached required-value spellings such as `-Cbackend-mode=unsafe`.

`uv pip install` is a separately supported command path, not an alias that may inherit pip approval implicitly. Wardnet therefore also fails closed on uv target/build selectors that can change the selected distribution or build path, including `--python-platform`, binary/source selection, build disabling/isolation controls, and `-C` / config-setting controls. The exact reviewed artifact set is additionally dependency-cardinality bounded: `pip`, `pip3`, and `uv pip install` must carry the exact `--no-deps` safety flag, alongside the existing hash-checking requirement, so the installer cannot resolve extra transitive artifacts absent from `InstallIntent.artifacts`.

The downstream execution broker remains responsible for independently verifying every retrieved artifact byte sequence against the admitted digest/provenance before installation. An admission `allow` receipt is not execution authority.

## Evidence

The pip install reference documents compatibility selectors that alter the wheel set, binary/source controls that change distribution choice, build-isolation/config-setting controls that change source-build behavior, and `--no-deps` as the switch that suppresses dependency installation. pip's repeatable-install guidance recommends pinning the full dependency graph and notes that `--no-deps` provides additional assurance that nothing outside the explicitly supplied set is installed.

Astral's current `uv pip install` reference likewise exposes `--python-platform`, `--no-binary`, `--no-build`, `--no-build-isolation`, package-scoped build controls, `-C` / `--config-setting`, and `--no-deps`. Those controls are semantically relevant even though uv's option vocabulary differs from pip's. A provider-neutral Wardnet approval therefore cannot treat `uv` as automatically safe merely because the requested package name/version matches a reviewed PyPI coordinate.

Local parser probes confirmed pip accepts attached short `-Cbackend-mode=unsafe`, and current uv help/parser behavior accepts the guarded `uv pip install` target/build controls and `--no-deps`. Parser probing is evidence about command interpretation only; it is not a substitute for exact-head repository tests or downstream artifact verification.

This follows the same least-authority rule already applied to OCI platform selection: approval for an abstract coordinate is not approval for a caller-selected artifact variant or undeclared artifact expansion that the policy does not encode. NIST SSDF requires software-integrity controls to be explicit and verifiable; Wardnet applies that principle by refusing to infer missing artifact/build/dependency authority.

## RED → GREEN

The earlier PyPI lineage established pip compatibility/build-variant rejection (`9f11a7f90902c83f796aeda990f33425739b9c46` -> `a23583a533babf256ad81e9c882759662fe33f2b` -> `b3336704f346a174a7ea9fcc4b0403ef22a8c06b`) and then closed the attached `-C` parser spelling (`aaecfe6bc6bb7cb7a26f7db7db61bfb8465f7b8b` -> `c8546f4db70dc8cbc86bedf1d050a0eb5974073f`).

RED `2b78613d742a48aef1f9f0bda085a18be076219e` added hostile `uv pip install` target/build selectors that the preceding implementation did not inspect. GREEN `c655cbcc491b3be51bddaac737722888e10444ab` made PyPI artifact-variant admission distinguish pip-compatible command shapes and fail closed on uv-specific target/build authority.

A second review found that exact approved operands still permitted pip/uv resolvers to introduce undeclared transitive artifacts. RED `55224399ca0a4f20d6617fb811e4ec96cb3dcbbc` requires missing `--no-deps` to block for pip, pip3, and uv. Production commits `3069570736bdc4f1975bd698a3849b84cc4b2ba4` and `3eb2a3213bf276bc27997b62d0e738d856cacc7a` add and route the dependency-cardinality guard; `28333cd95bcfebb2066812baba43cf63cb8c226b` updates positive artifact-variant fixtures so the allowed path remains explicitly dependency-bounded. Hosted exact-head CI/security evidence is still required before integration readiness is claimed.

## References

Astral Software, Inc. (2026). *uv CLI reference: uv pip install.* Retrieved September 4, 2026, from https://docs.astral.sh/uv/reference/cli/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities (NIST SP 800-218).* https://doi.org/10.6028/NIST.SP.800-218

pip developers. (2026). *pip install: pip documentation.* Retrieved September 4, 2026, from https://pip.pypa.io/en/latest/cli/pip_install/

pip developers. (2026). *Repeatable installs: pip documentation.* Retrieved September 4, 2026, from https://pip.pypa.io/en/latest/topics/repeatable-installs/
