# PyPI hash-mode authority

## Problem

Wardnet's Agent Artifact Admission Controller treats hash checking as a required safety condition for approved direct PyPI installation. The policy previously recognized the literal positive `--require-hashes` token but did not separately reject pip's negative `--no-require-hashes` option. That let one structured intent carry contradictory hash-mode instructions while Wardnet still considered the positive token sufficient.

This is a parser/authority-boundary defect even when a particular pip version rejects the contradictory combination at execution time. Admission must not depend on a downstream parser rejecting an ambiguity that Wardnet can recognize before execution, and an admission `allow` receipt must not be produced for an intent that explicitly asks the installer to relax the required hash mode.

## Constraint and ownership

Wardnet owns pre-execution admission policy and minimized decision evidence. It does not download the distribution, generate a requirements lock, prove the downloaded bytes, or execute pip. The downstream executor remains responsible for consuming a reviewed material set and independently proving that retrieved bytes or equivalent provenance match the approved SHA-256 before execution.

The current v0.1 direct PyPI path therefore keeps these independent controls:

- exact reviewed package name and `==` version coordinate;
- reviewed registry/owner/SHA-256 identity;
- exact `--no-deps` dependency-cardinality guard;
- positive hash-checking requirement;
- explicit rejection of `--no-require-hashes` for pip/pip3 install requests;
- separate downstream material/provenance verification before execution.

## TDD evidence

- RED `032d74e060e778add00a2cc757ce3582c1135232` adds `pip_boolean_override_cannot_disable_required_hash_checking`. The hostile intent is otherwise the approved direct PyPI shape (`==` pin, `--require-hashes`, `--no-deps`) and adds `--no-require-hashes`.
- Causal classifier `4c0de8a3445d6b062b69440507cd3c81a3323308` isolates this installer-specific authority check in `pypi_hash_mode.rs` rather than broadening the generic policy parser.
- Admission wiring `bba656c1d776da38a7315d9ec8e6cb5bdfd621d1` returns the existing stable `missing_safety_flag` denial and never promotes the contradictory request to `allow`.

Remote executable GREEN is not inferred from source inspection. The exact-head hosted workflows must execute on the resulting candidate before merge or release authority exists.

## Primary-source traceability

pip documents `--require-hashes` as requiring a hash for every requirement and documents `--no-require-hashes` as disabling automatic activation of the all-requirements hash mode when hashes are encountered. pip's secure-install guidance further states that hash-checking mode is an all-or-nothing mechanism intended to protect exact distribution material and recommends SHA-256 or stronger algorithms. Those semantics make the two options different authority statements; Wardnet therefore accepts only an unambiguous safety request.

### References

Python Packaging Authority. (2026). *pip install — pip documentation (v26.2.1)*. https://pip.pypa.io/en/stable/cli/pip_install/

Python Packaging Authority. (2026). *Secure installs — pip documentation*. https://pip.pypa.io/en/stable/topics/secure-installs/

Python Packaging Authority. (2026). *Requirements file format — pip documentation*. https://pip.pypa.io/en/stable/reference/requirements-file-format/
