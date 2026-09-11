# PyPI upgrade mutation authority

Verified 2026-09-12 against pip commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`. This note records the narrow evidence behind Wardnet's Agent Artifact Admission rule for direct `pip` / `pip3` upgrade semantics. Wardnet classifies pre-execution intent only; it does not execute pip, resolve versions, inspect or mutate the effective Python environment, or own filesystem/session isolation.

## Problem

A reviewed PyPI artifact coordinate authorizes one exact package identity. pip's install command separately defines `-U` / `--upgrade` as authority to upgrade the specified packages to the newest available version. The same command implementation documents that a target install combined with upgrade authority may replace existing packages in the target directory.

Before this repair, Wardnet's existing PyPI install-mutation classifier rejected `--ignore-installed` and `--force-reinstall`, but an otherwise approved direct `pip` / `pip3 install` could add `-U` or `--upgrade` and still receive `Allow`. That lets caller-controlled argv request package/environment mutation beyond the reviewed exact artifact authority.

## Boundary and decision

The existing `pypi_install_mutation_authority` remains the single classifier for this bounded concern. The minimum repair adds only the two reviewed pip selectors:

- `-U` fails closed as `artifact_not_approved`;
- exact `--upgrade` fails closed as `artifact_not_approved`;
- `--upgrade-strategy` remains outside this change because it is a distinct resolver-policy selector and needs its own evidence and acceptance criteria before Wardnet changes its treatment;
- guessed long-option prefixes such as `--up` are not classified by this repair because the reviewed upstream command also defines `--upgrade-strategy`, so prefix semantics must not be inferred without an exact parser acceptance proof;
- existing ignore-installed, force-reinstall, artifact/source/hash/dependency/trust/config/output/cache/system-package/install-root and audit contracts remain unchanged.

The rule does not authorize or implement installation, package selection, interpreter-environment mutation, target-directory mutation, rollback, quarantine, egress policy, or sandbox behavior. Those concerns remain with their canonical owners and downstream execution boundary.

## RED → repair evidence

The formatter-clean test-only RED head is `39f25a6d6e2416ecb0fd106d25b6503a74f2d1ff`. Hosted CI run `34654851862`, job `103444903328`, passed checkout, Rust toolchain setup and `cargo fmt --check`, then reached `cargo test --locked --workspace`. The new hostile contract failed exactly because `pip -U` returned `Allow` where `Block` was required. Existing workspace tests before that assertion remained green.

The minimum production repair was introduced at `c6308e69eb164395709a21ee8b16387068484aa3`. It extends the existing mutation classifier with exact `-U` / `--upgrade` matching and adds precision unit tests that reject conflation with `--upgrade-strategy`, guessed prefixes, lowercase `-u`, pluralized variants, unrelated options, and artifact operands. Exact-head GREEN remains a hosted evidence requirement and is recorded only after the current documentation-bearing head completes CI successfully.

## Primary-source trace

At pip commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/commands/install.py` registers `-U` / `--upgrade` as the Boolean `upgrade` option with the documented effect of upgrading specified packages to the newest available version. The same command separately registers `--upgrade-strategy`, which is why this repair does not use a broad `--up...` prefix matcher.

## APA 7 references

Python Packaging Authority. (2026). *pip install command* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`) [Source code]. GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/commands/install.py

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218
