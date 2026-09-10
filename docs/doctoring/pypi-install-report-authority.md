# PyPI installation-report write authority

## Decision

Wardnet Agent Artifact Admission rejects caller-selected `pip`/`pip3 install --report` arguments before execution. The admission receipt authorizes only the reviewed artifact mutation represented by the structured install intent; it does not authorize an additional caller-chosen filesystem write destination.

Both `--report=<file>` and `--report <file>` fail closed with Wardnet's existing `alternate_install_root` reason. Wardnet does not resolve, canonicalize, open, create, or otherwise authorize the requested path.

## Problem and threat

An exact approved PyPI artifact can otherwise retain the same package name, version, registry, publisher, digest, manifest digest, `--require-hashes`, and `--no-deps` while adding `--report=/attacker/selected/path.json`. The option token begins with `-`, so it is not an undeclared positional artifact operand. Without an explicit admission rule, the extra write capability can inherit artifact approval even though it is outside the reviewed mutation contract.

This maps to CWE-73, External Control of File Name or Path: externally influenced pathnames can grant file access or modification capability that the caller would not otherwise possess. Wardnet therefore denies the additional argv authority rather than attempting path sanitization.

## Primary-source evidence

At `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/commands/install.py` defines `--report` with a caller-provided `file` destination. During `InstallCommand.run`, when that destination is not `-`, pip opens the supplied filename for UTF-8 JSON output before proceeding with installation preparation. This is an observable filesystem-write side effect controlled by installer argv, not part of the approved artifact identity.

The test-first Wardnet specimen at `e15594f3b1c46f751fbce3f18ffb4b548ae97278` kept production code byte-identical and added `--report=/tmp/wardnet-install-report.json` to an otherwise-approved direct pip install. Hosted CI `34508270927`, rust job `102975711419`, reached the semantic assertion on Ubuntu 24.04 and returned `Allow` where the contract required `Block`. Formatting and all preceding workspace tests were successful, isolating the missing admission classifier as the causal defect.

## Ownership boundary

Wardnet owns the pre-execution decision that an unreviewed installer argument must not inherit Agent Artifact Admission authority. This rule is intentionally syntactic and fail-closed.

`quarantine-sandbox-runtime` remains canonical owner of the effective runtime filesystem, mount, workspace, privilege, cleanup, and isolation boundary. Wardnet does not duplicate sandbox path enforcement. EgressWeave remains canonical owner of outbound transport authorization. AppGuardrail remains canonical owner of static package/security analysis. No foreign source or mutable sibling dependency is copied into this bounded context.

## Alternatives considered

Allowing `--report=-` while rejecting file paths would preserve a stdout-only mode, but it would require Wardnet to parse option/value semantics that are unnecessary for the current product contract. The safer and smaller authority model is to reject the entire optional reporting capability until a reviewed use case explicitly requires it.

Sanitizing or constraining the caller-selected path was rejected because it would move runtime filesystem policy into Wardnet and duplicate quarantine ownership. Relying only on sandbox containment was also rejected: admission should not grant a side effect merely because another boundary may later constrain its impact.

## Verification contract

The exact approved direct `pip` and `pip3` install controls must remain admissible. Attached and separate `--report` spellings must return `Block` and include `alternate_install_root`. Tests must not execute pip or perform filesystem writes. Every production change invalidates predecessor workflow evidence and requires exact-head CI/security review before integration.

## Traceability

- CWE-73: External Control of File Name or Path, CWE 4.20. https://cwe.mitre.org/data/definitions/73.html
- Python Packaging Authority. (2026). *pip installation command implementation* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/commands/install.py
- Wardnet issue #268 and Draft PR #269 retain the hostile RED, causal repair, exact-head checks, and protected-main adoption criteria.
