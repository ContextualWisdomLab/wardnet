# uv bytecode-compilation authority trace

Verified 2026-09-13. This note extends the Agent Artifact Admission research trace for one bounded policy decision. It does not grant `uv run` execution authority and does not transfer runtime ownership into Wardnet.

## Decision

Astral documents `--compile-bytecode` (alias `--compile`) as caller-selected bytecode materialization. For install operations, uv compiles installed or reinstalled Python files. For sync operations such as `uv sync` and `uv run`, uv states that the option processes the entire `site-packages` directory, including packages that are not otherwise being modified by the operation. The resulting `.pyc` state therefore is not represented by the reviewed package artifact coordinate alone.

Wardnet records that authority as `ReasonCode::ArtifactNotApproved`. Existing supported `uv pip install` semantics are unchanged. Unsupported `uv run` remains blocked by `ReasonCode::ForbiddenCommand`; when the exact compile selector is owned by uv before the delegated child-command boundary, the decision additionally records `ArtifactNotApproved`. A compile-looking token after the delegated child begins, after the `uv run --` boundary, or with a nearby spelling such as `--compile-bytecodex` does not inherit uv bytecode semantics.

The parser reuses the shared uv command/delegation helpers already used by admission trust classification. This keeps one command-phase model instead of introducing a second interpretation of `uv run` argv. Exact submitted argv remains the audit identity through `command_sha256`.

## Ownership boundary

Wardnet owns pre-execution admission policy and causal security evidence only. It does not execute uv, compile Python bytecode, enumerate or mutate `site-packages`, select an interpreter, or provide filesystem/session isolation. Those effective-execution controls remain with the canonical runtime and transport owners (`quarantine-sandbox-runtime`, EgressWeave, and their released contracts). AppGuardrail remains the static package/security-analysis owner; contextual-orchestrator remains the Agent/LLM orchestration owner.

## RED/GREEN evidence contract

Issue #393 and Draft PR #394 carry the executable regression. The RED fixture deliberately retains the exact approved artifact argument in argv so baseline artifact mismatch cannot manufacture `ArtifactNotApproved`. The accepted RED requires the uv-owned compile selector to be the only missing causal classifier while delegated-child and nearby-spelling controls remain negative. GREEN requires the same exact contract plus existing `uv pip install` behavior, formatting, locked workspace tests, strict Clippy, and applicable fuzz/security gates.

This testing pattern follows NIST SSDF's emphasis on verifying software against security requirements and retaining evidence that supports secure-development decisions. Wardnet does not claim NIST certification or conformance from this individual control.

## APA 7 references

Astral Software, Inc. (2026). *Commands: uv CLI reference.* https://docs.astral.sh/uv/reference/cli/

National Institute of Standards and Technology. (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for mitigating the risk of software vulnerabilities (NIST Special Publication 800-218).* https://doi.org/10.6028/NIST.SP.800-218
