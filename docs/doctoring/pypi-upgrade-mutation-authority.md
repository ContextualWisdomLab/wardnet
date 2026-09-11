# PyPI install mutation authority

Verified 2026-09-12 against pip commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`. This note records the narrow evidence behind Wardnet's Agent Artifact Admission rule for direct `pip` / `pip3` mutation semantics. Wardnet classifies pre-execution intent only; it does not execute pip, resolve versions, inspect or mutate the effective Python environment, or own filesystem/session isolation.

## Problem

A reviewed PyPI artifact coordinate authorizes one exact package identity. pip's install command separately defines `-I` / `--ignore-installed` as authority to ignore an existing installation and `-U` / `--upgrade` as authority to upgrade specified packages. Those selectors can therefore request mutation outside the reviewed artifact identity.

Wardnet already rejected the documented long forms and exact short forms, but direct pip uses `ConfigOptionParser`, derived from Python `optparse.OptionParser`. For short options that do not take a value, the parser processes the remaining characters in the same token as additional short options. Pip's `-v`, `-q`, `-I`, and `-U` are no-value options, so mutation-bearing forms such as `-Ivv`, `-vI`, `-qI`, `-Uv`, `-vU`, `-IU`, and `-UI` are parser-valid. The previous exact-form classifier therefore allowed parser-equivalent mutation authority through alternate argv spellings.

Value-taking short options are a different grammar. `optparse` consumes the remainder of the token as the option value when the current short option takes a value. Wardnet must therefore not invent embedded `I` or `U` semantics for tokens such as `-iI`, `-rI`, or `-tI`.

## Boundary and decision

The existing `pypi_install_mutation_authority` module remains the single Wardnet classifier for this bounded concern. The repair recognizes only one reviewed direct-pip short-cluster language:

- every character after the leading `-` must be one of the reviewed no-value options `v`, `q`, `I`, or `U`;
- ignore-installed authority is present only when that bounded cluster contains `I`;
- upgrade authority is present only when that bounded cluster contains `U`;
- exact and clustered `I`/`U` combinations therefore fail closed as `artifact_not_approved` without conflating the two semantic predicates;
- value-taking or unknown short-option characters make the cluster classifier return false rather than guessing parser behavior;
- existing long-option behavior for unambiguous `--ignore-i` through `--ignore-installed`, `--force-reinstall`, and exact `--upgrade` is preserved;
- `--upgrade-strategy`, guessed ambiguous long prefixes, lowercase `-u`, unrelated options, and artifact operands do not inherit upgrade semantics.

The rule does not authorize or implement installation, package selection, interpreter-environment mutation, target-directory mutation, rollback, quarantine, egress policy, or sandbox behavior. Those concerns remain with their canonical owners and downstream execution boundary.

## RED → repair evidence

The earlier exact-form upgrade repair is preserved by lineage: test-only head `39f25a6d6e2416ecb0fd106d25b6503a74f2d1ff` produced hosted semantic RED in CI `34654851862` / job `103444903328` because `pip -U` was allowed, and production commit `c6308e69eb164395709a21ee8b16387068484aa3` repaired exact `-U` / `--upgrade` handling.

The clustered-option finding is tracked by Wardnet issue #343 and Draft child #344. Test-only head `12b5f1f45a773c080d60910f84480160745a2d46` produced the first hosted semantic RED in CI `34657138688` / job `103451886561`: checkout, toolchain setup and formatting passed, then the hostile `pip -Ivv` contract returned `Allow` instead of required `Block`.

A separate production-unchanged head `c59272398d2cdcfe0f16d35ae4efe674a6e3d1d2` exposed the upgrade side directly at the classifier boundary. Hosted CI `34658434263` / job `103455722023` acquired Ubuntu 24.04, passed checkout, stable Rust setup, and `cargo fmt --check`, compiled the workspace, passed the root/runtime suites, and then failed exactly in `pypi_install_mutation_authority::tests::direct_pip_upgrade_matcher_accepts_only_reviewed_mutation_selectors` because `-Uv` was not classified. This is the required second semantic RED, not runner or bootstrap noise.

Minimum production repair commit `56f0c7791d159b1bca3752fa836a5aa5ddf3a8c9` replaces special-cased direct-pip short forms with one bounded no-value short-cluster classifier and adds precision tests for mutation-bearing clusters, value-taking spellings, malformed clusters, lowercase `-u`, long-option near-misses, and unrelated operands. Exact-current repository CI/fuzz remains a merge requirement after every subsequent evidence/documentation commit; predecessor conclusions are not promoted to a moved head.

## Primary-source trace

At pip commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/commands/install.py` registers `-I` / `--ignore-installed` and `-U` / `--upgrade` as Boolean install options and separately registers `--upgrade-strategy`. Pip's parser configuration is built on its `ConfigOptionParser`, which derives from Python `optparse.OptionParser`; `optparse` short-option processing iterates a short cluster until it encounters an option that takes a value, at which point the remaining token becomes that value. This is the parser distinction encoded by Wardnet's bounded classifier.

## APA 7 references

Python Packaging Authority. (2026). *pip install command* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`) [Source code]. GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/commands/install.py

Python Software Foundation. (2026). *optparse—Parser for command line options*. Python documentation. https://docs.python.org/3/library/optparse.html

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218
