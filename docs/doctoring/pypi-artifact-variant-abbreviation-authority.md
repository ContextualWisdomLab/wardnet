# Direct pip artifact-variant abbreviation authority

## Problem and ownership boundary

Wardnet Agent Artifact Admission authorizes reviewed installer intent and emits pre-execution security evidence. It does not resolve or fetch packages, perform TLS/network I/O, install or execute artifacts, isolate hostile workloads, or choose provider/runtime credentials. Those execution, transport, analysis, isolation, orchestration, and identity responsibilities remain with their canonical CWL owners.

The direct `pip`/`pip3` grammar is nevertheless part of Wardnet's admission surface. pip exposes selectors such as `--platform`, `--python-version`, `--implementation`, `--abi`, `--no-binary`, `--only-binary`, `--prefer-binary`, `--no-build-isolation`, and `--config-settings`. These options can change wheel compatibility, binary-versus-source selection, build isolation, or backend build configuration without changing the explicit package name/version operand that Wardnet already approved.

Python's `optparse`-compatible long-option parser accepts unambiguous prefixes. Executable parser verification against pip 25.1.1 established the direct-pip spellings `--pl`, `--python-`, `--im`, `--a`, `--no-bi`, `--o`, `--prefe`, `--no-bu`, and `--conf` as accepted, while shorter forms such as `--p`, `--py`, `--i`, `--no-b`, `--pref`, and `--con` remain ambiguous and must not be invented as aliases by Wardnet.

## Exact RED evidence

Test-only head `30623bf4d244daa97f928a29408bfe8c3b74d0af` added only `crates/agent-artifact-admission/tests/pypi_artifact_variant_abbreviation_contract.rs`. Hosted CI `34632315148`, Rust job `103371851676`, acquired GitHub-hosted `ubuntu-24.04`, checked out that exact head, installed the pinned Rust toolchain, and passed `cargo fmt --check`. `cargo test --locked --workspace` then failed while Fuzz `34632315062` succeeded. The failure is therefore a semantic admission RED rather than runner, checkout, or formatting noise.

After #326 integrated normally, restack PR #328 adopted exact parent `feat/agent-artifact-admission@8003b9a211208a66c87b198b678528382fd07f3e` into this child without changing the tree, force-updating history, or transferring predecessor GREEN as current evidence.

## Decision

Extend only the existing direct-pip artifact/build-variant classifier.

For value-taking selectors, classify prefixes from the shortest verified unambiguous spelling through the character before the canonical spelling, preserving both separate-value and `--option=value` forms:

- `--platform` from `--pl`;
- `--python-version` from `--python-`;
- `--implementation` from `--im`;
- `--abi` from `--a`;
- `--no-binary` from `--no-bi`;
- `--only-binary` from `--o`;
- `--config-settings` from `--conf`.

For Boolean selectors, classify only argument-free accepted prefixes:

- `--prefer-binary` from `--prefe`;
- `--no-build-isolation` from `--no-bu`.

Canonical spellings remain under the pre-existing classifier. Ambiguous shorter prefixes remain unclassified because pip rejects them. Boolean abbreviations with an invented `=value` form are not treated as accepted pip grammar. `uv` retains its independent option language and receives no pip-prefix behavior.

This is a Wardnet admission/policy repair. It does not duplicate EgressWeave transport authorization, quarantine execution/isolation, AppGuardrail package analysis, contextual-orchestrator agent/LLM orchestration, or Keyverse identity/secret authority.

## Alternatives rejected

Blocking every textual prefix beginning with a few matching characters was rejected because it would invent parser semantics and create false positives. Treating an exact approved package operand as sufficient despite caller-selected compatibility/build selectors was rejected because the resulting artifact/build path can differ materially from the reviewed intent. Reimplementing pip resolution or build behavior inside Wardnet was rejected because Wardnet owns admission evidence, not package-manager execution.

## Security effect and residual risk

The repair closes an admission bypass where a caller could keep the approved package coordinate while selecting a different compatibility target, binary/source policy, build-isolation mode, or backend build configuration through a pip-accepted abbreviated option. The bounded helper records both positive and negative grammar controls so future widening requires an explicit hostile RED rather than prefix guessing.

Residual risk remains when pip changes parser behavior or adds security-significant selectors. Such changes require parser verification and a new bounded admission contract. Wardnet must not infer aliases from spelling similarity alone.

## Traceability

- NIST SP 800-218 SSDF v1.1 is the final normative SSDF publication used by this decision. SP 800-218 Rev. 1 / SSDF v1.2 remains an Initial Public Draft published December 17, 2025 and is informative only.
- Current PyPA pip documentation identifies the compatibility, binary/source, build-isolation, and backend configuration selectors whose authority this repair bounds.
- Python `optparse` documentation is the primary parser reference for accepted abbreviated long options.
- CWE-20 supports strict validation of untrusted structured input; CWE-829 is relevant where caller-controlled build/source selection can include functionality outside the intended reviewed control sphere.

## References (APA 7th)

MITRE. (2026). *CWE-20: Improper input validation* (Version 4.20). Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/20.html

MITRE. (2026). *CWE-829: Inclusion of functionality from untrusted control sphere* (Version 4.20). Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/829.html

National Institute of Standards and Technology. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2025). *Secure software development framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218 Rev. 1, Initial Public Draft). https://doi.org/10.6028/NIST.SP.800-218r1.ipd

Python Packaging Authority. (n.d.). *pip install — pip documentation*. Retrieved September 12, 2026, from https://pip.pypa.io/en/latest/cli/pip_install/

Python Software Foundation. (n.d.). *optparse — Parser for command line options*. Retrieved September 12, 2026, from https://docs.python.org/3/library/optparse.html
