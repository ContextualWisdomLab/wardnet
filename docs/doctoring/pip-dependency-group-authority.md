# pip dependency-group authority

## Decision

Wardnet's Agent Artifact Admission boundary rejects `pip install` and `pip3 install` requests that add `--group`. The reviewed install intent binds an exact artifact set; a dependency group imports a list of requirements from `pyproject.toml`, optionally from another project path, and therefore represents artifact-selection authority outside that reviewed set.

Both `--group=<value>` and the separate-value form fail closed with `artifact_not_approved`. The attached-value form is security-significant because it is not an extra positional operand and therefore cannot rely on generic operand-cardinality rejection.

Wardnet does not read `pyproject.toml`, resolve or fetch dependency-group members, execute pip, authorize network egress, or own filesystem/runtime isolation. It only rejects structured installer argv that attempts to widen reviewed artifact authority. Runtime execution and isolation remain downstream canonical-owner responsibilities.

## RED / GREEN evidence contract

The hostile regression uses an otherwise admissible exact PyPI artifact request with `--require-hashes`, `--no-deps`, and `--no-input`, then appends `--group=developer-tools`. The test-only head must demonstrate semantic RED after successful checkout/formatting. The minimum production repair recognizes `--group` only for direct `pip install` / `pip3 install` grammar and preserves the exact direct install control path.

Acceptance requires:

- attached and separate `--group` spellings fail closed;
- `pip` and `pip3` are covered;
- an exact direct install with no dependency-group authority remains allowed when all other policy invariants hold;
- no pyproject discovery, dependency resolution, package retrieval, transport enforcement, or quarantine logic is copied into Wardnet.

## Traceability

Python Packaging Authority. (2026). *pip install — pip documentation*. https://pip.pypa.io/en/latest/cli/pip_install/

Python Packaging Authority. (2026). *User guide: Dependency Groups*. https://pip.pypa.io/en/latest/user_guide/#dependency-groups
