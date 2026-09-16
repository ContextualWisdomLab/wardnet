# PyPI Requires-Python compatibility authority

## Decision

Wardnet Agent Artifact Admission rejects a direct `pip` or `pip3 install` intent that adds canonical `--ignore-requires-python`. The reviewed artifact receipt authorizes the exact package coordinate and installer intent; it does not authorize the caller to disable publisher-declared Python compatibility enforcement while retaining the same admission identity.

The classifier is deliberately syntactic and bounded to supported direct pip installs. Wardnet does not inspect the effective interpreter, resolve package metadata, execute pip, select another Python runtime, or decide whether the package would actually run in the target environment.

## Problem and threat

At exact upstream `pypa/pip@2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`, `src/pip/_internal/cli/cmdoptions.py` defines canonical `--ignore-requires-python` as a Boolean install option whose documented behavior is `Ignore the Requires-Python information`. `InstallCommand.run` forwards `options.ignore_requires_python` to resolver construction, so the option changes how pip treats the distribution metadata compatibility requirement.

Python Core Metadata defines `Requires-Python` as the distribution field that declares the Python version requirement. An otherwise reviewed request can therefore preserve the approved ecosystem, name, version, registry, owner, hash, manifest and hash/dependency safety flags while explicitly asking the installer to disregard a publisher compatibility constraint.

Before this repair, Wardnet had no dedicated classifier for that selector. Because the option starts with `-`, the existing positional artifact checks did not make the explicit compatibility override causal to a denial.

## Executed RED

Test-only exact `3ae6fcddc633053729673713853835e9f64c1a1b` is based on canonical Agent Artifact Admission parent `#129@22c50d886d9e2ed8f5c376bacff8ec1f8a0d5b6c`; production source is byte-identical to the parent.

Hosted CI run `34636878079`, rust job `103386810988`, acquired a GitHub-hosted Ubuntu 24.04 runner and completed checkout, pinned Rust toolchain and `cargo fmt --check`. The workspace test step then reached the new hostile contract and failed because the direct-pip request containing `--ignore-requires-python` returned `Allow` where the contract requires `Block`. The exact approved control remains required to return `Allow`, making the failure causal to the added compatibility override rather than bootstrap, formatting, artifact-cardinality or command-path noise.

## Minimum causal repair

The repair adds one crate-private direct-pip classifier and maps the canonical selector to the existing stable `missing_safety_flag` reason. It preserves the other package-manager grammars independently and introduces no interpreter discovery, package resolution or runtime mutation.

This slice recognizes only the canonical exact spelling. Pip long-option abbreviation behavior is not inferred here: expanding the accepted spelling family requires separate verification against the pinned parser and complete contemporaneous option set rather than broad prefix matching.

## Ownership boundary

Wardnet owns the pre-execution policy decision that a reviewed install intent cannot silently expand into a request to disable package-manager compatibility protection. `quarantine-sandbox-runtime` remains canonical owner of effective runtime filesystem, mount, privilege, resource, interpreter and hostile-execution isolation. EgressWeave remains canonical owner of executable outbound network authorization. AppGuardrail remains canonical owner of static package/security analysis.

Accordingly, Wardnet rejects the explicit selector but does not assert that a particular package is compatible or incompatible, does not select or install an interpreter, and does not turn package metadata into runtime authority.

## Alternatives considered

Allowing the override and relying only on runtime isolation was rejected because the admission receipt would still authorize installer semantics absent from the reviewed intent. Inferring compatibility by inspecting the local interpreter or downloaded distribution was rejected because it would duplicate executor/package-analysis authority and make an ambient runtime state part of a deterministic admission decision. Broad matching of abbreviated long options was rejected in this slice because the accepted abbreviation language depends on pip's complete parser option set and therefore requires its own pinned-parser proof.

## Verification contract

Exact approved direct `pip` and `pip3` installs with the reviewed artifact, `--require-hashes`, `--no-deps` and `--no-input` remain `Allow`. Adding canonical `--ignore-requires-python` must return `Block` with exactly `missing_safety_flag`. A suffix such as `--ignore-requires-python-extra`, the same token under `uv pip install`, and non-install direct pip commands do not match this classifier.

Every source or doctoring change invalidates predecessor workflow evidence. Integration requires exact-current formatting, locked workspace tests, strict Clippy, Fuzz, fresh review/thread inventory and ordinary expected-head merge into canonical Agent Artifact Admission before protected-main consideration. Issue #331 remains open until the effective delta reaches protected `main` or a verified complete successor.

## Traceability

- Python Packaging Authority. (2026). *pip command options* (commit `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`). `src/pip/_internal/cli/cmdoptions.py` defines `--ignore-requires-python`; `src/pip/_internal/commands/install.py` forwards the option to resolver construction. GitHub.
- Python Packaging Authority. (2026). *Core Metadata Specifications: Requires-Python*. Python Packaging User Guide. The field declares the Python version requirement for a distribution.
- National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (NIST SP 800-218). https://doi.org/10.6028/NIST.SP.800-218
- MITRE. (2025). *CWE-693: Protection Mechanism Failure*. Common Weakness Enumeration.
- Wardnet issue #331 and Draft PR #332 retain the hostile RED, causal repair, exact-current verification and protected-main adoption criteria.
