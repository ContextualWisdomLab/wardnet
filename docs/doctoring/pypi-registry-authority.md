# PyPI registry authority traceability

Verified 2026-09-11. This note narrows one Agent Artifact Admission invariant: a reviewed Python artifact coordinate includes its HTTPS registry, so submitted installer arguments may not disable that reviewed registry and inherit a different package-source authority. It does not extend Wardnet into runtime environment inspection or package retrieval.

## Decision trace

The protected admission model already rejects caller-selected `--index-url`, `--extra-index-url`, `--index`, `--default-index`, and `--find-links` controls. The remaining gap was the inverse selector: both pip and uv expose `--no-index`, which disables registry-index lookup. pip documents that `--no-index` ignores the package index and looks only at `--find-links` locations. uv documents `no-index` as ignoring all registry indexes and relying on direct URL dependencies or `--find-links`.

A submitted `pip install` or `uv pip install` carrying `--no-index` therefore contradicts an approval whose artifact identity includes a reviewed registry URL. Wardnet now classifies that submitted command as `alternate_trust_root` and blocks it before execution. This is intentionally narrower than reproducing pip or uv configuration precedence.

The execution boundary remains unchanged. `PIP_NO_INDEX`, `UV_NO_INDEX`, project/user configuration files, cache contents, filesystem state, and other effective runtime environment/configuration are not inspected by Wardnet. `quarantine-sandbox-runtime` remains the canonical owner of hostile execution/isolation and effective runtime environment/config authority. Wardnet evaluates only the structured submitted intent and emits admission policy/evidence.

## Evidence

- Hosted hostile RED `205567a0eb18069c7c72c6b2387107aab96db948`: `pypi_install_cannot_disable_reviewed_registry_index` observed `Allow` for a reviewed exact PyPI coordinate whose argv added `--no-index`.
- Minimum causal repair: `pypi_registry_authority::disables_reviewed_registry` recognizes only direct `pip`/`pip3 install` and `uv pip install` invocations carrying explicit `--no-index` authority, and the admission decision reuses stable `alternate_trust_root` evidence.
- The focused contract covers both pip and uv without reading environment variables, executing either package manager, fetching artifacts, or duplicating quarantine/EgressWeave responsibilities.

## Primary-source basis

pip 26.2.1 states that `--no-index` ignores the package index and that candidate discovery can otherwise include local filesystem and `--find-links` locations. uv's current settings reference states that `no-index` ignores all registry indexes and instead relies on direct URL dependencies and `--find-links`. These are package-source selection semantics, not installation-isolation semantics.

## APA 7 references

Astral Software, Inc. (2026). *Settings: uv documentation*. Retrieved September 11, 2026, from https://docs.astral.sh/uv/reference/settings/

pip developers. (2026). *pip install: pip documentation v26.2.1*. Retrieved September 11, 2026, from https://pip.pypa.io/en/stable/cli/pip_install/
