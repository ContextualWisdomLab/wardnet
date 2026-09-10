# PyPI cache-directory write authority

## Decision

Wardnet Agent Artifact Admission rejects caller-selected `pip`/`pip3 install` cache-directory authority before execution. The reviewed artifact receipt authorizes the exact package installation represented by the structured intent; it does not authorize pip to place HTTP or package cache state in an additional caller-selected filesystem location.

The classifier is intentionally syntactic and bounded to direct supported pip installs. Wardnet does not create, resolve, canonicalize, inspect, open, clean, or authorize the requested path.

## Problem and threat

An otherwise exact approved PyPI install can retain the same artifact ecosystem, name, version, registry, publisher, digest, reviewed manifest digest, `--require-hashes`, and `--no-deps` while adding `--cache-dir=/tmp/wardnet-pip-cache`. Because the attached token begins with `-`, Wardnet's positional artifact-operand guard does not treat the pathname as another package operand.

At exact upstream `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/cli/cmdoptions.py` defines `--cache-dir` as a `PipOption` of type `path`, defaulting to the normal user cache and described as `Store the cache data in <dir>`. The option is part of pip's `general_group`, so install commands receive it. At the same commit, `src/pip/_internal/cli/index_command.py` reads `options.cache_dir` and gives `PipSession` an HTTP cache rooted at `os.path.join(cache_dir, "http-v2")` when caching is enabled.

This is external control of a filesystem path and maps to CWE-73. The correct Wardnet response is to deny the unreviewed argv capability, not to sanitize or simulate the effective runtime filesystem.

## Executed RED

Test-only exact `4bea25c1433a61e7f8e4d3d7e2ef3ea94718e981` is exactly one commit above canonical Agent Artifact Admission parent `5cad3b13a074afe71b664da3fadd942dc886c7fb` and changes only `crates/agent-artifact-admission/tests/pypi_cache_dir_authority_contract.rs`; production source is byte-identical to the parent.

Hosted CI `34515963018`, rust job `103001328011`, acquired a GitHub-hosted Ubuntu 24.04 runner, completed checkout, the pinned Rust toolchain, and `cargo fmt --check`, then failed in the workspace `Test` step while the new contract required the otherwise-approved install plus attached `--cache-dir=/tmp/wardnet-pip-cache` to be blocked. This is the causal semantic RED for the missing cache-directory admission boundary rather than runner/bootstrap/format noise.

## Minimum causal repair

The repair adds one Wardnet-local classifier and connects it to the existing stable `alternate_install_root` reason. No new filesystem policy or reason-code namespace is introduced.

Pip builds its parser on Python `optparse`, which accepts an unambiguous prefix of a long option. At the reviewed pip option set, `--ca` is the shortest unambiguous prefix of `--cache-dir`; other `pip install` long options beginning with `c` diverge through forms such as `--cert`, `--client-cert`, `--constraint`, `--config-settings`, and `--check-build-dependencies`. Wardnet therefore recognizes only the bounded accepted family `--ca`, `--cac`, `--cach`, `--cache`, `--cache-`, `--cache-d`, `--cache-di`, and `--cache-dir`, including attached `=value` and separated value forms. A future pip parser or option-set change requires re-review rather than a broad `--c*` heuristic.

## Ownership boundary

Wardnet owns the pre-execution decision that an unreviewed installer argument cannot inherit Agent Artifact Admission authority. `quarantine-sandbox-runtime` remains canonical owner of effective filesystem, mount, workspace, privilege, cleanup, and hostile-execution isolation. EgressWeave remains canonical owner of executable outbound destination/DNS/peer/redirect/proxy/TLS/resource authorization. AppGuardrail remains canonical owner of static package/security analysis.

Wardnet therefore rejects the cache-directory selector but does not duplicate runtime path containment, create a package cache, inspect cached bytes, or infer transport authorization from cache placement.

## Alternatives considered

Allowing arbitrary cache placement and relying only on sandbox containment was rejected because admission would still grant a side effect absent from the reviewed intent. Path allowlisting/sanitization in Wardnet was rejected because effective filesystem authority belongs to quarantine and platform path semantics would create a second runtime policy surface. Matching only the complete `--cache-dir` spelling was rejected because the pinned parser accepts unique long-option abbreviations.

## Verification contract

Exact approved direct `pip` and `pip3` install controls with reviewed artifact coordinates, `--require-hashes`, and `--no-deps` remain `Allow`. Complete and accepted abbreviated cache-directory options, in both attached and separated forms, must return `Block` with `alternate_install_root`. Tests do not execute pip or touch the filesystem.

Every production or doctoring change invalidates predecessor workflow evidence. Integration requires exact-current CI/Fuzz success, fresh clean review/thread inventory, and ordinary expected-head merge into canonical Agent Artifact Admission before protected-main consideration. Issue #272 remains open until the effective delta reaches protected `main`.

## Traceability

- MITRE. (2025). *CWE-73: External control of file name or path* (CWE 4.20). https://cwe.mitre.org/data/definitions/73.html
- Python Software Foundation. (2026). *optparse — Parser for command line options*. Python 3.14 documentation. https://docs.python.org/3/library/optparse.html
- Python Packaging Authority. (2026). *pip command options* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/cmdoptions.py
- Python Packaging Authority. (2026). *pip index/session command implementation* (same commit). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/index_command.py
- Wardnet issue #272 and Draft PR #273 retain the hostile RED, repair, exact-current verification, and protected-main adoption criteria.
