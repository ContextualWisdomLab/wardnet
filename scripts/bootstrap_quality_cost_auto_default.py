#!/usr/bin/env python3
"""Create the test-first adaptive contextual-orchestrator SOC patch."""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_PATH = Path("src/lib.rs")
ADR_PATH = Path("docs/adr/0001-adaptive-contextual-orchestrator-default.md")
CHANGELOG_PATH = Path("CHANGELOG.md")


def replace_once(path: Path, old: str, new: str) -> None:
    """Replace exactly one source fragment or fail closed."""
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def write_test() -> None:
    """Add only the adaptive request assertion for the RED commit."""
    replace_once(
        SOURCE_PATH,
        '        assert_eq!(body["model"], "m1");\n        assert_eq!(body["messages"][0]["role"], "system");',
        '        assert_eq!(body["model"], "m1");\n        assert_eq!(body["orchestration_mode"], "auto");\n        assert_eq!(body["messages"][0]["role"], "system");',
    )


def implement() -> None:
    """Delegate the ordinary SOC analysis topology to adaptive orchestration."""
    replace_once(
        SOURCE_PATH,
        '        "model": model,\n        "messages": [',
        '        "model": model,\n        "orchestration_mode": "auto",\n        "messages": [',
    )

    if CHANGELOG_PATH.exists():
        raise SystemExit(f"refusing to overwrite existing {CHANGELOG_PATH}")
    CHANGELOG_PATH.write_text(
        """# Changelog

## Unreleased

### Changed

- LLM-backed SOC analysis now explicitly requests contextual-orchestrator `auto` mode, allowing the orchestration plane to choose the quality-sufficient model/workflow and then minimize known execution cost instead of fixing the consumer to one model call.
""",
        encoding="utf-8",
    )

    ADR_PATH.parent.mkdir(parents=True, exist_ok=True)
    if ADR_PATH.exists():
        raise SystemExit(f"refusing to overwrite existing {ADR_PATH}")
    ADR_PATH.write_text(
        """# ADR-0001: Adaptive contextual-orchestrator mode is the SOC-analysis default

- Status: Accepted
- Date: 2026-08-16

## Context

Wardnet's optional SOC-analysis adapter sent an OpenAI-compatible chat request without an explicit orchestration mode. The gateway currently interprets omission as adaptive behavior, but the consumer contract did not make that requirement reviewable or prevent future drift to a fixed single-worker route.

## Decision

Every ordinary SOC-analysis request includes `orchestration_mode: "auto"`.

Contextual-orchestrator owns provider/model selection, test-time compute, workflow depth, verification, fallback, and known-price optimization. Quality sufficiency is the first constraint; cost is minimized among paths that satisfy it. Missing or untrusted price metadata is classified as unpriced rather than free.

Wardnet continues to own event lookup, admin authorization, the bounded SOC prompt, response-shape validation, and operator-visible failure handling. Explicit fixed modes may be used only in controlled ablation or a documented incident override and are not product defaults.

## Consequences

A routine event may still use one worker when adaptive policy finds that sufficient. Ambiguous or high-risk triage may use deeper orchestration without changing the Wardnet API.

## References

Omidvar, H., & Akhlaghi, V. (2026). *A communication-theoretic framework for LLM agents: Cost-aware adaptive reliability* [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2605.09121

Tang, Y., Cetin, E., Xu, J., Sun, Q., Nielsen, S., Richard, V., Goda, H., Tymchenko, I., Nguyen, N., Lee, H., Ashiga, M., Kotyan, S., Kuroki, S., & Clanuwat, T. (2026). *Sakana Fugu technical report* [Technical report]. arXiv. https://doi.org/10.48550/arXiv.2606.21228
""",
        encoding="utf-8",
    )


def main() -> None:
    """Run one bounded bootstrap phase."""
    if len(sys.argv) != 2 or sys.argv[1] not in {"test", "implement"}:
        raise SystemExit("usage: bootstrap_quality_cost_auto_default.py test|implement")
    if sys.argv[1] == "test":
        write_test()
    else:
        implement()


if __name__ == "__main__":
    main()
