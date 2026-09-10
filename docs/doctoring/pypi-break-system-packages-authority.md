# PyPI externally-managed environment override authority

## Decision

Wardnet Agent Artifact Admission rejects caller-selected `pip`/`pip3 install` options that disable pip's externally-managed-environment protection. A reviewed artifact receipt authorizes the exact package installation represented by the structured intent; it does not authorize the caller to override an interpreter-level installation safety boundary.

The classifier is intentionally syntactic and limited to supported direct pip installs. Wardnet does not inspect the effective interpreter environment, remove or rewrite an `EXTERNALLY-MANAGED` marker, create a virtual environment, or decide which runtime filesystem paths are writable.

## Problem and threat

At exact upstream `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/cli/cmdoptions.py` defines `--break-system-packages` as the `override_externally_managed` Boolean option with the help contract `Allow pip to modify an EXTERNALLY-MANAGED Python installation`. `InstallCommand.run` checks the externally-managed environment when installing into the current environment unless that override is set.

PEP 668 defines the `EXTERNALLY-MANAGED` marker specifically so Python-specific installers refuse interpreter-wide mutation by default when another package manager owns the environment. The PEP requires any override to be explicit and to communicate that the operation is risky.

Before this repair, an otherwise exact approved direct pip request could retain the reviewed artifact, manifest, `--require-hashes`, `--no-deps`, registry and source authority while adding `--break-system-packages`. Because the Boolean option begins with `-`, Wardnet's positional artifact scan did not classify it as another artifact operand and no dedicated guard named the override.

## Executed RED

Test-only exact `510457b5584b910bcf39403f2efa5d1ab4fcae70` is exactly one commit above canonical Agent Artifact Admission parent `3ded67b28a991fbe8604f0d73aa7d5d36932ef63` and changes only `crates/agent-artifact-admission/tests/pypi_break_system_packages_authority_contract.rs`; production source is byte-identical to the parent.

Hosted CI `34519122876`, rust job `103011915969`, acquired a GitHub-hosted Ubuntu 24.04 runner, completed checkout, pinned Rust toolchain, and `cargo fmt --check`, then failed in the workspace `Test` step. The new contract requires the approved control to remain `Allow` and the same request with `--break-system-packages` to return `Block`. The parent had exact-head CI/Fuzz/Security/SAST GREEN, so this test-only execution is the causal semantic RED rather than bootstrap or formatting noise.

## Minimum causal repair

The repair adds one Wardnet-local direct-pip classifier and maps the override to the existing stable `missing_safety_flag` reason. No new runtime environment policy or reason-code namespace is introduced.

Pip builds the install parser with Python `optparse`, which accepts an unambiguous prefix of a long option. At the reviewed upstream option set, `--b` is ambiguous because `pip install` also accepts `--build-constraint`, while `--br` is the shortest unique prefix of `--break-system-packages`. Wardnet therefore recognizes the exact accepted prefix family from `--br` through `--break-system-packages`. A future pip parser or option-set change requires re-review rather than broad `--b*` matching.

## Ownership boundary

Wardnet owns the pre-execution decision that unreviewed installer argv cannot disable a safety boundary and inherit Agent Artifact Admission authority. `quarantine-sandbox-runtime` remains canonical owner of effective filesystem, mount, workspace, privilege, environment and hostile-execution isolation. EgressWeave remains canonical owner of executable outbound destination/DNS/peer/redirect/proxy/TLS/resource authorization. AppGuardrail remains canonical owner of static package/security analysis.

Wardnet therefore rejects the override but does not infer whether a particular runtime interpreter is externally managed, does not modify that interpreter, and does not duplicate quarantine runtime enforcement.

## Alternatives considered

Relying only on the runtime sandbox was rejected because admission would still authorize a side-effect scope not represented by the reviewed intent. Matching only the full option spelling was rejected because the pinned parser accepts unique long-option abbreviations. Rejecting every `--b*` option was rejected because `--build-constraint` is a distinct parser option and broad prefix matching would not represent the reviewed grammar.

## Verification contract

Exact approved direct `pip` and `pip3` controls with reviewed artifact coordinates, `--require-hashes`, and `--no-deps` remain `Allow`. Every accepted unambiguous spelling from `--br` through `--break-system-packages` must return `Block` with `missing_safety_flag`. Tests execute only the pure admission function; they do not execute pip or mutate the filesystem.

Every production or doctoring change invalidates predecessor workflow evidence. Integration requires exact-current CI/Fuzz success, fresh clean review/thread inventory, and ordinary expected-head merge into canonical Agent Artifact Admission before protected-main consideration. Issue #274 remains open until the effective delta reaches protected `main`.

## Traceability

- Python Packaging Authority. (2026). *pip command options* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). `src/pip/_internal/cli/cmdoptions.py` defines `--break-system-packages` and `--build-constraint`; `src/pip/_internal/commands/install.py` adds both to the install parser and checks `override_externally_managed` before installation. GitHub.
- Python Packaging Authority. (2021). *PEP 668: Marking Python base environments as externally managed*. Python Enhancement Proposals. https://peps.python.org/pep-0668/
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- Wardnet issue #274 and Draft PR #275 retain the hostile RED, repair, exact-current verification, and protected-main adoption criteria.
