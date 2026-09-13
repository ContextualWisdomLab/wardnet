# PyPI registry authority traceability

Verified 2026-09-11. This note narrows one Agent Artifact Admission invariant: a reviewed Python artifact coordinate includes its HTTPS registry, so submitted installer arguments may not disable, replace, or add package-source authority outside that reviewed coordinate. It does not extend Wardnet into runtime environment inspection, network transport authorization, package retrieval, installation, or sandbox execution.

## Decision trace

The admission model rejects caller-selected `--index-url`, `--extra-index-url`, `--index`, `--default-index`, `--find-links`, and `--no-index` controls. pip documents that `--index-url` selects the base package index, `--extra-index-url` adds package indexes, `--find-links` adds candidate locations, and `--no-index` disables index lookup. Its current documentation also warns that `--extra-index-url` can create dependency-confusion exposure because candidate selection spans multiple locations.

The remaining gap was pip's parser grammar rather than a missing option name. pip's current CLI architecture uses `ConfigOptionParser`, whose parent is Python `optparse.OptionParser`. The live pip CLI accepts unambiguous long-option prefixes such as `--index-u=...`, `--extra-index-u=...`, and `--find-l=...`. Wardnet's generic option matcher deliberately recognizes exact long names because npm-family, uv, Cargo, and OCI clients do not share pip's parser grammar. Consequently, a caller could pair an otherwise approved `name==version` coordinate with an abbreviated pip source selector and bypass the submitted-intent source-authority check.

Wardnet now handles that grammar only inside the PyPI registry-authority policy. For direct `pip install` and `pip3 install`, the policy classifies accepted prefixes of `--index-url`, `--extra-index-url`, `--find-links`, and `--no-index` as the same `alternate_trust_root` authority as their full spellings. uv retains its exact-option path. This keeps the repair causal and avoids broadening generic argv semantics for unrelated installers.

The execution boundary remains unchanged. `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, `PIP_NO_INDEX`, project/user configuration files, cache contents, filesystem state, and other effective runtime environment/configuration are not inspected by Wardnet. `quarantine-sandbox-runtime` remains the canonical owner of hostile execution/isolation and effective runtime environment/config authority; EgressWeave remains the canonical executable outbound-transport authority. Wardnet evaluates only the structured submitted intent and emits admission policy/evidence.

## Evidence

- Earlier hosted hostile RED `205567a0eb18069c7c72c6b2387107aab96db948`: `pypi_install_cannot_disable_reviewed_registry_index` observed `Allow` for a reviewed exact PyPI coordinate whose argv added full `--no-index`; the original minimum repair classified explicit `--no-index` as `alternate_trust_root`.
- Current hostile RED `e6c46585d04f7fdf595fcf438b793d1de06abc59`, CI run `34602358631`, job `103272504094`: checkout and formatting succeeded, then the exact admission contract failed because abbreviated pip source selectors were still admitted.
- Minimum causal repair `edefb8eff1473223cf1ec56f16da84bbb2881012`: `pypi_registry_authority` adds pip/pip3-only accepted-prefix classification while leaving uv and all other executable grammars on their existing exact-option paths.
- Exact repair GREEN: CI run `34602771562`, job `103273850396` completed SUCCESS on `edefb8eff1473223cf1ec56f16da84bbb2881012`; formatting, locked workspace tests, and Clippy all passed.
- The contract covers full and abbreviated source selectors without reading environment variables, executing a package manager, fetching artifacts, authorizing egress, or duplicating quarantine/EgressWeave responsibilities.

## Primary-source basis

pip's current install documentation states that candidate discovery can use the configured base index, extra indexes, local filesystem, and `--find-links`, and warns that `--extra-index-url` is unsafe for private-package discovery because of dependency confusion. pip's current source tree defines these index/find-links options in `cmdoptions.py`. Its CLI architecture documents `ConfigOptionParser` as an `optparse.OptionParser` descendant, which is the parser behavior reproduced by the hostile contract.

The security implication is bounded: the defect concerns submitted command authority, not whether a remote source is trustworthy after transport or whether retrieved bytes match the reviewed digest. Those latter controls remain with their canonical execution/transport/artifact-verification owners.

## APA 7 references

Python Packaging Authority. (2026). *pip install: pip documentation v26.3.dev0*. Retrieved September 11, 2026, from https://pip.pypa.io/en/latest/cli/pip_install/

Python Packaging Authority. (2026). *Command line interface architecture* [Source documentation, revision `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`]. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/docs/html/development/architecture/command-line-interface.rst

Python Packaging Authority. (2026). *pip CLI option definitions* [Source code, revision `2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5`]. https://github.com/pypa/pip/blob/2b28a816d043826f2ba10ff1d22ec3d94d2ed7c5/src/pip/_internal/cli/cmdoptions.py

Python Software Foundation. (2026). *optparse — Parser for command line options* (Python 3.14.6 documentation). https://docs.python.org/3.14/library/optparse.html
