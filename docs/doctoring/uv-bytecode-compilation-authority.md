# uv bytecode-compilation authority trace

Verified 2026-09-13. This note extends the Agent Artifact Admission research trace for one bounded policy decision. It does not grant `uv run` execution authority and does not transfer runtime ownership into Wardnet.

## Decision

Astral documents top-level uv usage as `uv [OPTIONS] <COMMAND>` and documents `--color` as a top-level output option. Astral also documents `--compile-bytecode` (alias `--compile`) as caller-selected bytecode materialization. For install operations such as `uv pip install`, uv compiles installed or reinstalled Python files. For sync operations such as `uv sync` and `uv run`, uv states that the option processes the entire `site-packages` directory, including packages that are not otherwise being modified by the operation. The resulting `.pyc` state therefore is not represented by the reviewed package artifact coordinate alone.

Wardnet records that authority as `ReasonCode::ArtifactNotApproved`. Existing supported `uv pip install` command eligibility is unchanged. A reviewed uv global option may precede the active `pip install` command without erasing the separate bytecode-materialization reason, even though that globally prefixed argv can remain outside Wardnet's supported install grammar and therefore also retain `ReasonCode::ForbiddenCommand`. Unsupported `uv run` remains blocked by `ForbiddenCommand`; when the exact compile selector is owned by uv before the delegated child-command boundary, the decision additionally records `ArtifactNotApproved`. A compile-looking token after the delegated child begins, after the `uv run --` boundary, on a non-install `uv pip` command, or with a nearby spelling such as `--compile-bytecodex` does not inherit uv bytecode semantics.

The parser reuses the shared `uv_active_command_index` command-phase helper to identify the active top-level command after reviewed global options. Exact active `pip install` is inspected only from its install argument slice. `uv_run_owned_argument_end` remains the delegation boundary for `uv run`. This keeps one command-phase model instead of introducing a second interpretation of uv argv. `supported_install_command` is deliberately unchanged, and exact submitted argv remains the audit identity through `command_sha256`.

## Ownership boundary

Wardnet owns pre-execution admission policy and causal security evidence only. It does not execute uv, compile Python bytecode, enumerate or mutate `site-packages`, select an interpreter, or provide filesystem/session isolation. Those effective-execution controls remain with the canonical runtime and transport owners (`quarantine-sandbox-runtime`, EgressWeave, and their released contracts). AppGuardrail remains the static package/security-analysis owner; contextual-orchestrator remains the Agent/LLM orchestration owner.

## RED/GREEN evidence contract

Issue #393 and Draft PR #394 established the first executable regression for uv-owned `uv run` compile selectors and their delegated-child boundary. Their accepted RED deliberately retained the exact approved artifact argument in argv so baseline artifact mismatch could not manufacture `ArtifactNotApproved`; the repair preserved existing `uv pip install` behavior and reused the shared uv parser helpers.

Issue #395 and serialized Draft PR #396 extend that contract to reviewed global options before active `uv pip install`. The test-only exact head `6c24a3d9d4e2f554649346fcb06222e01ff380e9` kept production source byte-identical to its parent. Hosted CI `34734372758`, rust job `103662996596`, passed checkout, toolchain, and formatting, then failed in `cargo test --locked --workspace` specifically at `uv_global_options_preserve_pip_install_bytecode_authority_evidence`: the decision contained `[ForbiddenCommand]` but omitted `ArtifactNotApproved`. Nearby-spelling and non-install controls passed. That is the semantic RED for the current repair.

GREEN requires the same hostile and negative-control contract on one unchanged exact head, plus formatting, locked workspace tests, strict Clippy, applicable fuzz/security gates, current review/thread clearance, and ordinary expected-head integration. No queued, skipped, predecessor, synthetic, or unrelated runner result is promoted as passing evidence.

This testing pattern follows NIST SSDF's emphasis on verifying software against security requirements and retaining evidence that supports secure-development decisions. Wardnet does not claim NIST certification or conformance from this individual control.

## APA 7 references

Astral Software, Inc. (2026). *Commands: uv CLI reference.* https://docs.astral.sh/uv/reference/cli/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST Special Publication 800-218).* https://doi.org/10.6028/NIST.SP.800-218
