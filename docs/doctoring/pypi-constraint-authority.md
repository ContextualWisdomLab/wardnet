# PyPI constraint authority

## Decision

Wardnet's Agent Artifact Admission boundary rejects caller-supplied constraint documents for direct `pip install`, `pip3 install`, and `uv pip install` requests. The reviewed intent binds an exact artifact set and exact package-source coordinates; a constraint or build-constraint document is an additional dependency/build selection authority that is not represented by those coordinates.

This applies to pip `-c` / `--constraint` and `--build-constraint`, and to uv `-c` / `--constraint` / `--constraints` plus `-b` / `--build-constraint` / `--build-constraints`. Both separate-value and attached-value spellings fail closed. The stable evidence reason is `artifact_not_approved`.

Wardnet does not fetch or interpret the constraint document, execute the package manager, authorize network transport, inspect an effective runtime environment, or own build isolation. Those remain downstream executor/quarantine/EgressWeave responsibilities. Admission only decides whether the submitted structured argv stays inside the reviewed artifact authority.

## Threat and causal evidence

pip documents constraints as files that influence which requirement version is selected and separately documents build constraints for isolated build dependencies. uv exposes equivalent install-time constraint and build-constraint options; its compatibility documentation also notes that constraints can reference direct URL dependencies. A caller-controlled constraint document can therefore change dependency or build inputs independently of the reviewed artifact coordinate.

The hostile regression uses attached option values so the value cannot be rejected accidentally as an extra positional artifact. Before the repair, an otherwise admissible exact PyPI intent remained `allow` when supplied with attached constraint/build-constraint authority. The minimum repair classifies only the supported direct pip-compatible install grammars and leaves the control request without constraint authority admissible.

## Acceptance

- exact `pip`, `pip3`, and `uv pip install` controls without constraint authority remain admissible when every other invariant holds;
- pip short/long constraint and build-constraint forms fail closed;
- uv singular/plural short/long constraint and build-constraint forms fail closed;
- attached values are covered explicitly so positional-argument counting cannot masquerade as the causal control;
- no environment/config-file discovery is introduced into Wardnet;
- no quarantine, outbound transport, artifact retrieval, or build execution logic is copied into this bounded context.

## Traceability

Python Packaging Authority. (2026). *pip install — pip documentation*. https://pip.pypa.io/en/latest/cli/pip_install/

Python Packaging Authority. (2026). *User guide: Constraints files and build constraints*. https://pip.pypa.io/en/latest/user_guide/#constraints-files

Astral Software, Inc. (2026). *uv command reference: uv pip install*. https://docs.astral.sh/uv/reference/cli/#uv-pip-install

Astral Software, Inc. (2026). *Compatibility with pip*. https://docs.astral.sh/uv/pip/compatibility/
