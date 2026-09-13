# PyPI verbose-log write authority

## Decision

Wardnet Agent Artifact Admission rejects caller-selected `pip`/`pip3 install` verbose-log output authority before execution. Pip exposes one general logging option through the aliases `--log`, `--log-file`, and `--local-log`. Because pip's parser is built on Python `optparse`, the admission boundary also rejects the currently accepted unambiguous long-option prefixes that resolve to this option. The admission receipt authorizes only the reviewed package installation represented by the structured intent; it does not authorize an additional caller-selected filesystem append destination.

The classifier is intentionally syntactic. Attached and separated forms fail closed with Wardnet's existing `alternate_install_root` reason. Wardnet does not resolve, canonicalize, create, open, append to, or otherwise authorize the requested path.

## Problem and threat

An otherwise exact approved PyPI install can retain the same package ecosystem, name, version, registry, publisher, digest, reviewed manifest digest, `--require-hashes`, and `--no-deps` while adding a verbose-log destination such as `--log=/tmp/wardnet-pip.log`. The option token begins with `-`, so the positional artifact-operand guard does not classify the pathname as another package operand. Without a dedicated authority check, the caller can therefore add a filesystem side effect that is absent from the reviewed install intent.

This maps to CWE-73, External Control of File Name or Path. Wardnet denies the additional argv capability instead of attempting pathname sanitization or runtime containment.

## Primary-source evidence

At `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/cli/cmdoptions.py` defines the general `log` option as a `PipOption` with aliases `--log`, `--log-file`, and `--local-log`, type `path`, and the help contract `Path to a verbose appending log.` The same module derives its option machinery from Python `optparse`.

At the same pip commit, `src/pip/_internal/cli/base_command.py` constructs every command with a `ConfigOptionParser`, adds `cmdoptions.general_group`, parses the command line, and then passes `options.log` to `setup_logging(..., user_log_file=options.log)` before the command-specific `run` method executes. The caller-selected destination is therefore live logging configuration for an otherwise approved install rather than inert metadata.

Python `optparse` accepts a unique long-option prefix. For the current pip option set, Wardnet's bounded classifier therefore recognizes the complete aliases and the presently unambiguous prefixes `--log-`, `--log-f`, `--log-fi`, `--log-fil`, `--loc`, `--loca`, `--local`, `--local-`, `--local-l`, and `--local-lo`. It deliberately does not treat ambiguous `--lo` as accepted caller authority. If upstream pip changes the option set or parser grammar, this accepted-language set must be re-reviewed against the released parser.

## Executed RED → minimum causal repair

Test-only exact `a9b8c5f5d9f70e17168d8fa5af3b331d6b498815` was one commit above canonical Agent Artifact Admission parent `f73c964714692eccf4f3a73a38b9c6165c8cb0c6` and changed only `crates/agent-artifact-admission/tests/pypi_log_output_authority_contract.rs`. Hosted CI `34513210814`, rust job `102992168251`, acquired GitHub-hosted Ubuntu 24.04, passed checkout, pinned toolchain, and formatting, then failed in the workspace test step while production remained byte-identical to the parent. That is the causal semantic RED for the missing verbose-log authority boundary.

The first production repair classified the three complete aliases. Fresh parser review then found the long-option-prefix bypass. Test-only `de879a19876a6421f2210603531aa2d4c73f8f6d` added abbreviated hostile cases but its first CI `34513728313` stopped at formatting and is not semantic evidence. Formatter-only `d6efe20260415a702556ecfc28590901227465a2` preserved production behavior; hosted CI `34513970080`, rust job `102994701557`, then passed checkout/toolchain/formatting and failed in the workspace test step, establishing the abbreviation RED. The minimum causal successor `a7c778872f825f7e2c3a4a366d385580b0ecf4a2` replaces broad/literal matching with the explicit currently accepted prefix family while leaving ambiguous `--lo` outside Wardnet's interpretation.

## Ownership boundary

Wardnet owns the pre-execution decision that an unreviewed installer argument cannot inherit Agent Artifact Admission authority. This rule neither executes pip nor grants runtime filesystem policy.

`quarantine-sandbox-runtime` remains canonical owner of effective filesystem, mount, workspace, privilege, cleanup, and hostile-execution isolation. EgressWeave remains canonical owner of executable outbound destination/DNS/peer/redirect/proxy/TLS/resource authorization. AppGuardrail remains canonical owner of static package/security analysis. No foreign source, runtime sandbox policy, transport implementation, or mutable sibling dependency is copied into this bounded context.

## Alternatives considered

Path sanitization or an allowed-directory grammar was rejected because it would duplicate quarantine's effective runtime filesystem authority and still leave Wardnet responsible for OS-level path semantics. Relying only on sandbox containment was also rejected: admission should not grant an unreviewed side effect merely because a later boundary may constrain its impact.

Matching only the three documented aliases was rejected after the executed abbreviation RED. Denying every token beginning with `--lo` was also rejected because that would reinterpret an ambiguous parser prefix as valid pip syntax. The chosen classifier enumerates only the spellings that currently resolve unambiguously to the logging option.

## Verification contract

Exact approved direct `pip` and `pip3` install controls with reviewed artifact coordinates, `--require-hashes`, and `--no-deps` must remain `Allow`. Attached and separated forms of each complete alias and representative accepted prefixes must return `Block` with `alternate_install_root`. Tests must not execute pip or touch the filesystem. A parser/version change invalidates the accepted-prefix assumption and requires primary-source re-verification rather than a broad prefix heuristic.

Every production or doctoring change invalidates predecessor workflow evidence. Integration requires exact-current CI/Fuzz success, clean current review/thread inventory, and ordinary expected-head merge into canonical Agent Artifact Admission before protected-main consideration.

## Traceability

- MITRE. (2025). *CWE-73: External control of file name or path* (CWE 4.20). https://cwe.mitre.org/data/definitions/73.html
- Python Software Foundation. (2026). *optparse — Parser for command line options*. Python 3.14 documentation. https://docs.python.org/3/library/optparse.html
- Python Packaging Authority. (2026). *pip shared command options* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/cmdoptions.py
- Python Packaging Authority. (2026). *pip base command implementation* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). GitHub. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/base_command.py
- Wardnet issue #270 and Draft PR #271 retain the hostile REDs, causal repairs, exact-current verification, and protected-main adoption criteria.
