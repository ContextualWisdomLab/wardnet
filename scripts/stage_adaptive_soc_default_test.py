#!/usr/bin/env python3
"""Stage a Rust contract test for the SOC LLM adaptive request default."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
test_path = root / "tests" / "adaptive_orchestrator_default.rs"
content = '''//! Contract test for the contextual-orchestrator SOC request policy.

#[test]
fn soc_llm_request_explicitly_delegates_to_auto_policy() {
    let source = include_str!("../src/lib.rs");
    assert!(source.contains("orchestration_mode"));
    assert!(source.contains("auto"));
}
'''

if test_path.exists():
    if test_path.read_text(encoding="utf-8") != content:
        raise SystemExit(f"refusing to replace a different test: {test_path}")
else:
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(content, encoding="utf-8")
