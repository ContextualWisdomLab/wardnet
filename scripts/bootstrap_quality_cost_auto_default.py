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
    """Add the adaptive gateway and generic-provider compatibility assertions."""
    replace_once(
        SOURCE_PATH,
        '        let body = soc_llm_chat_body("m1", &soc_test_event());\n        assert_eq!(body["model"], "m1");',
        '        let body = soc_llm_chat_body("contextual-orchestrator", &soc_test_event());\n        assert_eq!(body["model"], "contextual-orchestrator");\n        assert_eq!(body["orchestration_mode"], "auto");',
    )
    replace_once(
        SOURCE_PATH,
        '        assert_eq!(extract_soc_llm_content(&payload).as_deref(), Some("analysis"));\n    }',
        '        assert_eq!(extract_soc_llm_content(&payload).as_deref(), Some("analysis"));\n\n        let generic_body = soc_llm_chat_body("generic-model", &soc_test_event());\n        assert!(generic_body.get("orchestration_mode").is_none());\n    }',
    )


def implement() -> None:
    """Delegate contextual-orchestrator topology without breaking generic providers."""
    text = SOURCE_PATH.read_text(encoding="utf-8")
    start = text.find("fn soc_llm_chat_body(")
    end = text.find("\n}\n\nfn extract_soc_llm_content", start)
    if start < 0 or end < 0:
        raise SystemExit("soc_llm_chat_body function boundary was not found")
    block = text[start : end + 2]
    if block.count("serde_json::json!({") != 1:
        raise SystemExit("soc_llm_chat_body must contain exactly one JSON body")
    block = block.replace("    serde_json::json!({", "    let mut body = serde_json::json!({", 1)
    closing = "        ]\n    })\n}"
    replacement = (
        "        ]\n"
        "    });\n"
        "    if model == \"contextual-orchestrator\" {\n"
        "        body[\"orchestration_mode\"] = serde_json::Value::String(\"auto\".to_string());\n"
        "    }\n"
        "    body\n"
        "}"
    )
    if block.count(closing) != 1:
        raise SystemExit("soc_llm_chat_body closing shape was not found")
    block = block.replace(closing, replacement, 1)
    SOURCE_PATH.write_text(text[:start] + block + text[end + 2 :], encoding="utf-8")

    if CHANGELOG_PATH.exists():
        raise SystemExit(f"refusing to overwrite existing {CHANGELOG_PATH}")
    CHANGELOG_PATH.write_text(
        """# Changelog

## Unreleased

### Changed

- SOC analysis configured with model `contextual-orchestrator` now explicitly requests adaptive `auto` mode, while other OpenAI-compatible model identifiers retain their original generic payload.
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

Wardnet's optional SOC-analysis adapter accepts an OpenAI-compatible model identifier. It omitted an explicit orchestration mode, so contextual-orchestrator's adaptive requirement was not reviewable. Sending an orchestration-only field to every provider would break generic providers that reject unknown parameters.

## Decision

When and only when the configured model is exactly `contextual-orchestrator`, the SOC-analysis request includes `orchestration_mode: "auto"`.

Contextual-orchestrator owns provider/model selection, test-time compute, workflow depth, verification, fallback, and known-price optimization. Quality sufficiency is the first constraint; cost is minimized among paths that satisfy it. Missing or untrusted price metadata is classified as unpriced rather than free.

Other model identifiers receive the unchanged generic OpenAI-compatible payload. Wardnet continues to own event lookup, admin authorization, the bounded SOC prompt, response-shape validation, and operator-visible failure handling. Explicit fixed modes may be used only in controlled ablation or a documented incident override and are not product defaults.

## Consequences

Contextual-orchestrator deployments obtain an explicit adaptive policy without breaking direct providers. A routine event may still use one worker when adaptive policy finds that sufficient; ambiguous or high-risk triage may use deeper orchestration without changing the Wardnet API.

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
