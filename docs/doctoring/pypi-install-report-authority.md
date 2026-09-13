# PyPI installation-report write authority

## Decision

Wardnet Agent Artifact Admission rejects caller-selected `pip`/`pip3 install --report` authority before execution. Pip's command parser is built on Python `optparse`, so the security contract also rejects the currently unambiguous long-option prefixes from `--rep` through `--report`. The admission receipt authorizes only the reviewed artifact mutation represented by the structured install intent; it does not authorize an additional caller-chosen filesystem write destination.

Attached and separated values fail closed with Wardnet's existing `alternate_install_root` reason. Wardnet does not resolve, canonicalize, open, create, or otherwise authorize the requested path.

## Problem and threat

An exact approved PyPI artifact can otherwise retain the same package name, version, registry, publisher, digest, manifest digest, `--require-hashes`, and `--no-deps` while adding report-output authority. The option token begins with `-`, so Wardnet's positional artifact scan does not classify the output path as an undeclared artifact operand. Matching only the literal `--report` spelling is also insufficient because pip's `ConfigOptionParser` inherits Python `optparse.OptionParser` long-option matching and therefore accepts an unambiguous prefix such as `--rep` for `--report` in the current install option set.

This maps to CWE-73, External Control of File Name or Path: externally influenced pathnames can grant file access or modification capability that the caller would not otherwise possess. Wardnet therefore denies the additional argv authority rather than attempting path sanitization.

## Primary-source evidence

At `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/commands/install.py` defines `--report` with a caller-provided `file` destination. During `InstallCommand.run`, when that destination is not `-`, pip opens the supplied filename for UTF-8 JSON output before proceeding with installation preparation. Pip's `src/pip/_internal/cli/parser.py` imports `optparse`, defines `CustomOptionParser(optparse.OptionParser)`, and derives `ConfigOptionParser` from it. Python's `optparse` long-option matcher accepts a unique prefix of a configured long option; Wardnet must therefore reason about the parser's accepted language rather than only the help-text spelling.

The first Wardnet specimen at `e15594f3b1c46f751fbce3f18ffb4b548ae97278` kept production code byte-identical and added `--report=/tmp/wardnet-install-report.json` to an otherwise-approved direct pip install. Hosted CI `34508270927`, rust job `102975711419`, reached the semantic assertion on Ubuntu 24.04 and returned `Allow` where the contract required `Block`. Formatting and all preceding workspace tests were successful, isolating the missing admission classifier as the causal defect.

After the literal `--report` repair, fresh source review exposed the parser-abbreviation bypass. Test-only exact `93e6d8ea21a2c369efcb16e0d630c49c937f0f88` added attached and separated `--rep` cases while leaving production code unchanged from its predecessor. Hosted CI `34509524218`, rust job `102979904158`, acquired Ubuntu 24.04, passed checkout, toolchain setup and formatting, then failed in the workspace test step; Fuzz `34509524209` was terminal success. The minimum causal successor `d2c4e104b1827637c1f532884e26cf3018890a07` classifies `--rep`, `--repo`, `--repor`, and `--report`, with or without an attached `=value`, as the same unreviewed report-write authority. It does not broaden Wardnet into path evaluation or runtime filesystem enforcement.

## Ownership boundary

Wardnet owns the pre-execution decision that an unreviewed installer argument must not inherit Agent Artifact Admission authority. This rule is intentionally syntactic and fail-closed.

`quarantine-sandbox-runtime` remains canonical owner of the effective runtime filesystem, mount, workspace, privilege, cleanup, and isolation boundary. Wardnet does not duplicate sandbox path enforcement. EgressWeave remains canonical owner of outbound transport authorization. AppGuardrail remains canonical owner of static package/security analysis. No foreign source or mutable sibling dependency is copied into this bounded context.

## Alternatives considered

Allowing `--report=-` while rejecting file paths would preserve a stdout-only mode, but it would require Wardnet to parse option/value semantics that are unnecessary for the current product contract. The safer and smaller authority model is to reject the entire optional reporting capability until a reviewed use case explicitly requires it.

Sanitizing or constraining the caller-selected path was rejected because it would move runtime filesystem policy into Wardnet and duplicate quarantine ownership. Relying only on sandbox containment was also rejected: admission should not grant a side effect merely because another boundary may later constrain its impact.

Matching only the literal `--report` spelling was rejected after the executed abbreviation RED. Denying every token beginning with `--rep` was also rejected as unnecessarily broad: the bounded classifier names the currently accepted prefix family through the complete option spelling, keeping the policy explicit and reviewable.

## Verification contract

The exact approved direct `pip` and `pip3` install controls must remain admissible. Attached and separate forms of `--rep`, `--repo`, `--repor`, and `--report` must return `Block` and include `alternate_install_root`. Tests must not execute pip or perform filesystem writes. If upstream pip changes its option grammar such that another abbreviation becomes valid or one of these prefixes becomes ambiguous, the adapter contract must be re-reviewed against that released parser rather than silently weakening admission. Every production or documentation change invalidates predecessor workflow evidence and requires current-head verification before integration.

## Traceability

- MITRE. (2025). *CWE-73: External control of file name or path* (CWE 4.20). https://cwe.mitre.org/data/definitions/73.html
- Python Software Foundation. (2026). *optparse — Parser for command line options*. Python 3.14 documentation. https://docs.python.org/3/library/optparse.html
- Python Packaging Authority. (2026). *pip installation command implementation* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/commands/install.py
- Python Packaging Authority. (2026). *pip CLI parser implementation* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/parser.py
- Wardnet issue #268 and Draft PR #269 retain the hostile REDs, causal repairs, current-head checks, and protected-main adoption criteria.
