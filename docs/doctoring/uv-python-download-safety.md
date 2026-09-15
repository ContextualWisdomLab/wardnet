# uv Python download safety at Agent Artifact Admission

## Problem

Wardnet treats an admitted package-install intent as authority for the artifacts explicitly bound by the policy and request. That cardinality guarantee is incomplete for `uv pip install` unless automatic Python acquisition is disabled.

The current uv CLI reference documents that `uv pip install` searches for a Python interpreter for package resolution and, when no suitable interpreter is found, can install one automatically. uv exposes `--no-python-downloads` to disable automatic Python downloads. A reviewed PyPI artifact therefore must not inherit implicit authority to acquire a Python distribution that is absent from `InstallIntent.artifacts`.

## Wardnet control

For a request that otherwise satisfies Wardnet's supported `uv pip install` admission grammar, the submitted argv must contain the exact Boolean flag `--no-python-downloads` before an explicit `--` option terminator. Missing, near-spelled, or assigned forms such as `--no-python-download`, `--no-python-downloads=false`, or a token after `--` do not satisfy the control.

The guard is applied only to an intent that the existing admission pipeline would otherwise allow. This preserves the primary causal reason for requests already denied by registry, trust-root, install-root, configuration, mutation, build-variant, dependency-cardinality, interpreter-authority, or other controls. The audit `command_sha256` remains bound to the exact submitted argv.

A representative admissible command shape is:

```text
uv pip install cwl-example==1.2.3 --require-hashes --no-deps --no-python-downloads
```

The flag closes only implicit Python-distribution acquisition. It does not approve a caller-selected interpreter, alternate installation root, mutable dependency set, alternate registry or trust root, package-manager configuration override, or any other authority that Wardnet already evaluates separately.

## Ownership boundary

Wardnet owns the pre-execution admission decision, causal reason codes, and security evidence. It does not discover or install Python, inspect ambient interpreter state, fetch package bytes, execute package managers, authorize network destinations, or isolate the eventual process.

- `quarantine-sandbox-runtime` owns effective interpreter, filesystem, process/session isolation, cleanup, and hostile execution controls.
- EgressWeave owns executable outbound transport authorization.
- AppGuardrail owns static package and code-security analysis.
- `contextual-orchestrator` owns Agent and LLM orchestration.

This control does not copy or reimplement those owners' runtime behavior. It prevents Wardnet from issuing an admission receipt whose explicit artifact set is narrower than the package manager's permitted acquisition behavior.

## Verification contract

The hostile contract starts from an otherwise approved single-artifact uv install and proves that the no-guard, near-spelling, and assigned-false forms fail closed with `MissingSafetyFlag`, while exact `--no-python-downloads` preserves the approved path. Exact submitted argv remains independently verifiable through `command_sha256`.

Production acceptance requires the same exact head to pass the locked Rust workspace tests, strict Clippy, and the repository's applicable security and fuzz gates. Predecessor or test-only results are not promoted to the repaired head.

## References

Astral Software, Inc. (n.d.). *uv CLI reference*. Retrieved September 13, 2026, from https://docs.astral.sh/uv/reference/cli/

Astral Software, Inc. (n.d.). *Python versions*. Retrieved September 13, 2026, from https://docs.astral.sh/uv/concepts/python-versions/
