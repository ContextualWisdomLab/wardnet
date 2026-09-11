# PyPI target install-root abbreviation authority

## Decision

Wardnet Agent Artifact Admission rejects direct `pip` and `pip3 install` intents that select pip's `--target` destination through the pinned parser's verified unambiguous long-option prefix language from `--ta` through canonical `--target`.

Wardnet classifies only the caller-selected argv authority. It does not create, inspect, mount, validate, clean, or otherwise own the effective destination path. Filesystem, mount, workspace-isolation, cleanup, and recovery remain canonical `quarantine-sandbox-runtime` responsibilities.

## Problem and threat

The reviewed artifact receipt binds an approved package coordinate and bounded installer intent. Pip's `--target <dir>` changes where installed package material is written. The existing Wardnet install-root policy already rejects canonical `--target` and short `-t`, but its generic cross-package-manager flag matcher intentionally uses exact option spelling.

Pinned direct pip uses Python `optparse` long-option abbreviation semantics. On the reviewed parser surface `--ta` uniquely identifies `--target`, while the shorter `--t` prefix is ambiguous and is not claimed. An attached argument such as `--ta=/tmp/wardnet-pip-target` therefore carries real alternate-install-root authority while bypassing the exact-spelling guard. Because the attached token begins with `-`, the positional artifact scan does not independently reject it as an extra artifact operand.

## Executed hostile RED

Test-only exact `6c494569e58cb41bab8b2d554def59c5258f278b` was based on canonical Agent Artifact Admission parent `#129@6538faf2d60d64335f910b7770276ad32717aac7`; production policy bytes were unchanged.

Hosted CI run `34644738040`, rust job `103412682854`, acquired a GitHub-hosted Ubuntu 24.04 runner, completed checkout, toolchain setup, and `cargo fmt --check`, then ran the locked workspace tests. `pypi_target_abbreviation_authority_contract` failed on direct `pip install ... --ta=/tmp/wardnet-pip-target`: Wardnet returned `Allow` where the contract requires `Block`. The exact reviewed direct-pip positive control passed before the hostile selector was added. The contract also retains `--t=...` as a negative precision control so Wardnet does not invent ambiguous pip parser semantics.

An earlier test-only commit `faa98040b223393c75901fe77c086c1af6bcc6bb` failed only `cargo fmt --check` and is not semantic RED. Formatter-only successor `6c494569e58cb41bab8b2d554def59c5258f278b` is the causal RED authority.

## Minimum causal repair

The production repair adds one direct-pip-only classifier for the verified `--target` long-option language. It requires exact `pip` or `pip3`, exact `install`, strips only an attached `=` value for option-name comparison, and matches only option names whose length is at least `--ta` and that are prefixes of canonical `--target`.

The matcher therefore accepts `--ta`, `--tar`, `--targ`, `--targe`, and `--target`; it excludes ambiguous `--t`, superstrings such as `--targeted`, unrelated `--timeout`, and short-option `-t` grammar already owned by the existing generic install-root guard. A match adds stable `alternate_install_root` evidence and blocks the intent.

The repair does not execute pip, parse ambient configuration, perform filesystem I/O, resolve paths, or import pip abbreviation semantics into uv or other package managers.

## Alternatives considered

Broadening the generic cross-manager flag matcher to accept arbitrary prefixes was rejected because pip's `optparse` grammar is not a universal package-manager contract and would create false authority claims for uv, npm, pnpm, Cargo, and OCI clients. Treating every `--t*` token as target was rejected because the pinned pip option surface makes shorter prefixes ambiguous. Deferring the decision to quarantine cleanup was rejected because the admission receipt would still authorize caller-selected installer destination semantics that were absent from the reviewed intent.

## Verification and integration contract

The exact approved direct `pip` and `pip3` installs must remain `Allow`. Attached `--ta=/tmp/wardnet-pip-target` must return `Block` with `alternate_install_root`; ambiguous `--t=/tmp/wardnet-pip-target` must not be reinterpreted as target by this classifier. Existing canonical `--target` / `-t` controls and the separate-value evidence repair from #318 must remain unchanged.

Every source or doctoring movement invalidates predecessor GREEN evidence. The serialized child requires exact-current Wardnet CI/Fuzz plus fresh review/thread inventory before ordinary expected-head integration into still-exact #129. After integration, canonical #129 must reacquire its own exact-current repository and default-branch security gates before protected-main consideration. Issue #337 remains open until this effective delta reaches protected `main` or a verified complete successor.

## Traceability

- Python Packaging Authority. (2026). *pip install command*, commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`. `--target <dir>` installs packages into the supplied directory.
- Python Software Foundation. (2026). *optparse — Parser for command line options*. Unambiguous long-option prefixes are accepted as abbreviations.
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- MITRE. (2025). *CWE-15: External Control of System or Configuration Setting*. Common Weakness Enumeration.
- Wardnet issue #337 and Draft PR #338 retain the exact parser finding, hostile RED, repair lineage, and integration evidence.
