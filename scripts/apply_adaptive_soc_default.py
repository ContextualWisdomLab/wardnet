#!/usr/bin/env python3
"""Add explicit auto orchestration to the optional SOC LLM request."""

from __future__ import annotations

import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source_path = root / "src" / "lib.rs"
adr_path = root / "docs" / "adr" / "0010-adaptive-contextual-orchestrator-default.md"
changelog_path = root / "CHANGELOG.md"

source = source_path.read_text(encoding="utf-8")
if "orchestration_mode" not in source:
    patterns = [
        r'(?P<indent>[ \t]*)"model"\s*:\s*(?P<value>[^,\n}]+),\s*\n(?P=indent)"messages"\s*:',
        r'(?P<indent>[ \t]*)"model"\s*=>\s*(?P<value>[^,\n}]+),\s*\n(?P=indent)"messages"\s*=>',
    ]
    changed = False
    for pattern in patterns:
        match = re.search(pattern, source)
        if match is None:
            continue
        original = match.group(0)
        separator = ":" if '"model"' in original and ":" in original.splitlines()[0] else "=>"
        message_separator = ":" if separator == ":" else "=>"
        replacement = (
            f'{match.group("indent")}"model"{separator}{match.group("value")},\n'
            f'{match.group("indent")}"orchestration_mode"{separator} "auto",\n'
            f'{match.group("indent")}"messages"{message_separator}'
        )
        source = source[: match.start()] + replacement + source[match.end() :]
        changed = True
        break
    if not changed:
        # Flexible fallback for serde_json::json! blocks where formatting places
        # model and messages on one line.
        source, count = re.subn(
            r'("model"\s*:\s*[^,}]+,\s*)("messages"\s*:)',
            r'\1"orchestration_mode": "auto", \2',
            source,
            count=1,
        )
        if count != 1:
            raise RuntimeError("could not locate the SOC model/messages JSON payload")
source_path.write_text(source, encoding="utf-8")

adr_path.parent.mkdir(parents=True, exist_ok=True)
if not adr_path.exists():
    adr_path.write_text(
        '''# ADR-0010: SOC analysis delegates default execution to contextual-orchestrator auto

- Status: Accepted
- Date: 2026-08-16

## Context

Wardnet's optional SOC analysis endpoint calls the organization LLM gateway, but a
model/messages-only request leaves policy implicit and can collapse into a fixed
single-worker path. Security analysis ranges from short enrichment to high-risk,
multi-step investigation; the application should not hard-code one model or one
workflow for all cases.

## Decision

The SOC request explicitly includes `orchestration_mode: "auto"`. The central
orchestrator selects the quality-sufficient route, worker-plus-verifier path, or
conducted workflow; known lower cost is used only after capability and safety
requirements. Unpriced providers are not treated as free.

Wardnet retains WAF/IDS evidence collection, authorization, bounded request handling,
audit records, security-domain validation, and operator presentation. Explicit fixed
modes remain controlled orchestration experiments and rollback controls, not the
product default.

## References

Omidvar, H., & Akhlaghi, V. (2026). *A communication-theoretic framework for LLM agents: Cost-aware adaptive reliability* [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2605.09121

Tang, Y., Cetin, E., Xu, J., Sun, Q., Nielsen, S., Richard, V., Goda, H., Tymchenko, I., Nguyen, N., Lee, H., Ashiga, M., Kotyan, S., Kuroki, S., & Clanuwat, T. (2026). *Sakana Fugu technical report* [Technical report]. arXiv. https://doi.org/10.48550/arXiv.2606.21228
''',
        encoding="utf-8",
    )

if changelog_path.exists():
    changelog = changelog_path.read_text(encoding="utf-8")
    entry = (
        "- Optional SOC LLM analysis now explicitly selects contextual-orchestrator "
        "`auto` instead of relying on a single-model default.\n"
    )
    if entry not in changelog:
        marker = "## Unreleased\n"
        if marker in changelog:
            changelog = changelog.replace(marker, marker + "\n### Changed\n\n" + entry, 1)
        else:
            changelog = "## Unreleased\n\n### Changed\n\n" + entry + "\n" + changelog
        changelog_path.write_text(changelog, encoding="utf-8")
