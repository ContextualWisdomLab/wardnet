# uv index-strategy authority

Wardnet treats caller-selected uv index search strategy as Agent Artifact Admission evidence, not as network execution policy. The reviewed `uv pip install` boundary permits uv's default `first-index` strategy, including its explicit attached and separate-value forms. It rejects `unsafe-first-match` and `unsafe-best-match` with `AlternateTrustRoot` because both relax the first-index trust boundary across package indexes.

Astral documents `first-index` as the default strategy and states that stopping at the first index containing a package name is intended to prevent dependency-confusion attacks. Astral describes `unsafe-first-match` as searching for compatible versions across all indexes and `unsafe-best-match` as searching all indexes for the best version; the compatibility guide explicitly warns that `unsafe-best-match` exposes users to dependency-confusion risk.

Astral's CLI grammar also permits top-level uv options before the active command. Wardnet therefore reuses the shared top-level uv command parser when attributing unsafe index-strategy evidence, so a submitted command such as `uv --color never pip install ... --index-strategy=unsafe-best-match` cannot lose its causal `AlternateTrustRoot` reason. This evidence-only parsing does not make that argv admissible: Wardnet's supported install grammar remains the narrower direct `uv pip install`, so the same global-option form remains `ForbiddenCommand` as well.

Wardnet only evaluates structured argv submitted in the install intent. It does not read `uv.toml`, `pyproject.toml`, environment variables, certificate stores, DNS, TLS state, registry contents, or package indexes. Effective runtime configuration and isolation remain owned by `quarantine-sandbox-runtime`; executable egress authorization remains owned by EgressWeave; package/static analysis remains owned by AppGuardrail.

## Acceptance boundary

- `uv pip install ...` with no explicit index strategy remains admissible when every other admission requirement is satisfied.
- `--index-strategy=first-index` and `--index-strategy first-index` remain admissible.
- `--index-strategy=unsafe-first-match`, `--index-strategy unsafe-first-match`, `--index-strategy=unsafe-best-match`, and `--index-strategy unsafe-best-match` are blocked with explicit `AlternateTrustRoot` evidence.
- Reviewed top-level uv options before `pip install` cannot hide unsafe index-strategy evidence; those argv remain generically forbidden rather than widening the install grammar.
- Near-spellings do not acquire uv semantics.
- Delegated child argv under unsupported `uv run` flows is not reinterpreted as `uv pip install` authority.
- The repair does not widen Wardnet's supported install grammar beyond direct `uv pip install`.

## References

Astral Software. (n.d.). *Package indexes*. uv documentation. Retrieved September 13, 2026, from https://docs.astral.sh/uv/concepts/indexes/

Astral Software. (n.d.). *Compatibility with pip: Package priority*. uv documentation. Retrieved September 13, 2026, from https://docs.astral.sh/uv/pip/compatibility/#package-priority

Astral Software. (n.d.). *Settings: index-strategy*. uv documentation. Retrieved September 13, 2026, from https://docs.astral.sh/uv/reference/settings/#index-strategy

Astral Software. (n.d.). *CLI reference: uv pip install*. uv documentation. Retrieved September 13, 2026, from https://docs.astral.sh/uv/reference/cli/#uv-pip-install
