# PyPI constraint authority

## Decision

Wardnet's Agent Artifact Admission boundary rejects caller-supplied constraint documents for direct `pip install`, `pip3 install`, and `uv pip install` requests. The reviewed intent binds an exact artifact set and exact package-source coordinates; a constraint or build-constraint document is an additional dependency/build selection authority that is not represented by those coordinates.

This applies to pip `-c` / `--constraint` and `--build-constraint`, including the pinned pip parser's accepted unambiguous long-option prefixes from `--cons` and `--build-c`, and to uv `-c` / `--constraint` / `--constraints` plus `-b` / `--build-constraint` / `--build-constraints`. Both separate-value and attached-value spellings fail closed. The stable evidence reason is `artifact_not_approved`. Shorter ambiguous pip prefixes are not guessed, and pip abbreviation semantics are not applied to uv.

Wardnet does not fetch or interpret the constraint document, execute the package manager, authorize network transport, inspect an effective runtime environment, or own build isolation. Those remain downstream executor/quarantine/EgressWeave responsibilities. Admission only decides whether the submitted structured argv stays inside the reviewed artifact authority.

## Threat and causal evidence

pip documents constraints as files that influence which requirement version is selected and separately documents build constraints for isolated build dependencies. uv exposes equivalent install-time constraint and build-constraint options; its compatibility documentation also notes that constraints can reference direct URL dependencies. A caller-controlled constraint document can therefore change dependency or build inputs independently of the reviewed artifact coordinate.

pip's pinned CLI implementation uses Python `optparse`, which accepts an unambiguous prefix of a long option. At `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, the shared option definitions contain both `--constraint` and `--config-settings`, so `--con` remains ambiguous while `--cons` uniquely selects `--constraint`; the same source defines `--build-constraint`, for which `--build-c` is an accepted unique prefix in the relevant option surface.

The original hostile regression used attached option values so the value could not be rejected accidentally as an extra positional artifact. A later parser-semantic regression at exact `e2007957cb5b1409d32df9753d2d3d037781068a` added `--cons=https://x.invalid/c.txt` and `--build-c=https://x.invalid/b.txt`. Hosted CI `34606386616`, rust job `103285721803`, passed checkout, toolchain and formatting, then failed in `Test`, proving the previously repaired exact-option classifier still allowed pip's accepted abbreviated spellings. The minimum repair extends only direct pip/pip3 constraint classification to those verified prefix ranges and adds separate-value coverage; uv retains exact-option semantics.

## Acceptance

- exact `pip`, `pip3`, and `uv pip install` controls without constraint authority remain admissible when every other invariant holds;
- pip short/long constraint and build-constraint forms, including verified unambiguous `optparse` prefixes, fail closed;
- shorter ambiguous pip prefixes are not classified as constraint authority;
- uv singular/plural short/long constraint and build-constraint forms fail closed without inheriting pip's prefix grammar;
- attached and separate values are covered explicitly so positional-argument counting cannot masquerade as the causal control;
- no environment/config-file discovery is introduced into Wardnet;
- no quarantine, outbound transport, artifact retrieval, or build execution logic is copied into this bounded context.

## Traceability

Python Packaging Authority. (2026). *pip CLI option definitions* (Commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/cli/cmdoptions.py`). https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/cmdoptions.py

Python Packaging Authority. (2026). *pip install — pip documentation*. https://pip.pypa.io/en/latest/cli/pip_install/

Python Packaging Authority. (2026). *User guide: Constraints files and build constraints*. https://pip.pypa.io/en/latest/user_guide/#constraints-files

Python Software Foundation. (2026). *optparse — Parser for command line options*. https://docs.python.org/3/library/optparse.html

Astral Software, Inc. (2026). *uv command reference: uv pip install*. https://docs.astral.sh/uv/reference/cli/#uv-pip-install

Astral Software, Inc. (2026). *Compatibility with pip*. https://docs.astral.sh/uv/pip/compatibility/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
