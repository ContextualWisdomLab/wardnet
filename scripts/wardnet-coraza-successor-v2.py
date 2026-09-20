#!/usr/bin/env python3
"""Finish PR #435 after the first successor exposed workspace regressions.

The predecessor harness already re-proves the three hostile Coraza REDs and
materializes the reviewed security fix. Its exact hosted run then found two
candidate defects: live WAF evaluation happened before independent Wardnet
local-deny scoring, and bracketed IPv6 loopback was rejected. This successor
repairs only those causal defects, keeps unconfigured block-mode forwarding
fail-closed, and re-runs the complete repository gate before promotion.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=ROOT, check=check, text=True)


def replace_once(text: str, old: str, new: str, seam: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected exactly one {seam} seam, found {count}")
    return text.replace(old, new, 1)


def materialize_predecessor_candidate() -> None:
    result = run(["python", "scripts/wardnet-coraza-successor-repair.py"], check=False)
    if result.returncode == 0:
        fail("predecessor unexpectedly reached GREEN; refuse to rewrite a different candidate")
    for path in (
        "src/proven_engine.rs",
        "tests/coraza_proven_engine_adapter.rs",
        "tests/coraza_non_disruptive_detection.rs",
        "docs/doctoring/in-path-coraza-adapter.md",
    ):
        if not (ROOT / path).is_file():
            fail(f"predecessor did not materialize expected candidate file: {path}")


def fix_bracketed_ipv6_loopback() -> None:
    path = ROOT / "src/proven_engine.rs"
    text = path.read_text()
    old = '''    if host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    {'''
    new = '''    let numeric_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost")
        || numeric_host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    {'''
    path.write_text(replace_once(text, old, new, "bracketed IPv6 loopback validation"))


def move_coraza_gate_after_independent_local_deny() -> None:
    path = ROOT / "src/lib.rs"
    text = path.read_text()
    engine_marker = '''    let engine_uri = match uri.query() {'''
    score_marker = '''    let scored = score_request('''
    monitor_marker = '''    if !proven_engine_recorded {'''
    if text.count(engine_marker) != 1 or text.count(monitor_marker) != 1:
        fail("live Coraza gateway seams are not unique")

    engine_start = text.index(engine_marker)
    score_start = text.index(score_marker, engine_start)
    engine_block = text[engine_start:score_start]
    for required in (
        "proven_engine::evaluate_sidecar",
        "ProvenEngineOutcome::Unavailable",
        "StatusCode::SERVICE_UNAVAILABLE",
    ):
        if required not in engine_block:
            fail(f"live Coraza block lost expected candidate evidence: {required}")

    without_early_engine = text[:engine_start] + text[score_start:]
    monitor_at = without_early_engine.index(monitor_marker, engine_start)
    between = without_early_engine[engine_start:monitor_at]
    if "scored.score >= route.block_threshold.unwrap_or(BLOCK_SCORE)" not in between:
        fail("local-deny gate is not between score and monitored-event seams")
    if "StatusCode::FORBIDDEN" not in between:
        fail("local-deny gate no longer returns the expected forbidden decision")

    text = without_early_engine[:monitor_at] + engine_block + without_early_engine[monitor_at:]
    path.write_text(text)


def reconcile_existing_no_engine_contract() -> None:
    path = ROOT / "src/lib.rs"
    text = path.read_text()
    old = '''        let allowed = app_request(
            &app,
            empty_request(Method::GET, "/gateway/cve-lookup?id=CVE-2021-44228"),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);'''
    new = '''        let undecidable = app_request(
            &app,
            empty_request(Method::GET, "/gateway/cve-lookup?id=CVE-2021-44228"),
        )
        .await;
        assert_eq!(
            undecidable.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "KEV metadata must not become a request signature; without a proven WAF, an otherwise-allowed block-mode request is unavailable rather than falsely blocked"
        );'''
    path.write_text(replace_once(text, old, new, "KEV legitimate-request no-engine contract"))


def reconcile_monitor_degraded_event_contract() -> None:
    path = ROOT / "src/lib.rs"
    text = path.read_text()
    old_request = '''        app_request(
            &app,
            gateway_get_from_ip("/gateway/demo?q=hi", "203.0.113.9"),
        )
        .await;'''
    new_request = '''        let monitor = app_request(
            &app,
            gateway_get_from_ip("/gateway/demo?q=hi", "203.0.113.9"),
        )
        .await;
        assert_eq!(
            monitor.status(),
            StatusCode::OK,
            "monitor mode must continue traffic when Coraza is unavailable while retaining degraded evidence"
        );'''
    text = replace_once(
        text,
        old_request,
        new_request,
        "monitor-mode degraded-evidence response contract",
    )
    old_event = '''        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0]["action"], "monitored");'''
    new_event = '''        assert_eq!(recent.len(), 1);
        assert_eq!(
            recent[0]["action"],
            "engine_unavailable",
            "an unconfigured proven WAF is degraded security evidence even when monitor mode continues the request"
        );'''
    path.write_text(
        replace_once(
            text,
            old_event,
            new_event,
            "monitor-mode degraded-evidence event contract",
        )
    )


def add_local_deny_ordering_regression() -> None:
    path = ROOT / "tests/coraza_live_enforcement.rs"
    text = path.read_text()
    marker = "block_route_preserves_local_deny_before_unconfigured_proven_waf"
    if marker in text:
        fail("local-deny ordering regression unexpectedly already exists")
    text += r'''

#[tokio::test]
async fn block_route_preserves_local_deny_before_unconfigured_proven_waf() {
    let app = app_with_block_route("coraza-local-deny", "/local-deny").await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/local-deny?q=1%20UNION%20SELECT%201")
                .body(Body::empty())
                .expect("valid hostile request"),
        )
        .await
        .expect("gateway must answer locally denied request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "independent Wardnet threat scoring may deny before Coraza; the missing proven engine gates only traffic that would otherwise proceed upstream"
    );
}
'''
    path.write_text(text)


def update_boundary_docs() -> None:
    path = ROOT / "docs/doctoring/in-path-coraza-adapter.md"
    text = path.read_text()
    needle = "An unconfigured engine and malformed, oversized, uncorrelated, timed-out, or unreachable evidence are `engine_unavailable`; a block-mode route fails closed with HTTP 503."
    replacement = needle + " Independent Wardnet threat/DNSBL evidence may deny a request first; Coraza is the required authorization boundary only for block-mode traffic that has not already been denied and would otherwise proceed upstream."
    path.write_text(replace_once(text, needle, replacement, "local-deny/Coraza ordering documentation"))


def verify_candidate() -> None:
    commands = (
        ["cargo", "fmt", "--check"],
        ["git", "diff", "--check"],
        [
            "cargo",
            "test",
            "--locked",
            "--lib",
            "proven_engine::tests::sidecar_is_loopback_only",
            "--",
            "--exact",
        ],
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_live_enforcement",
        ],
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_proven_engine_adapter",
        ],
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_non_disruptive_detection",
        ],
        ["cargo", "test", "--locked", "--workspace"],
        [
            "cargo",
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
    run(["cargo", "fmt"])
    for command in commands:
        run(command)


def main() -> None:
    materialize_predecessor_candidate()
    fix_bracketed_ipv6_loopback()
    move_coraza_gate_after_independent_local_deny()
    reconcile_existing_no_engine_contract()
    reconcile_monitor_degraded_event_contract()
    add_local_deny_ordering_regression()
    update_boundary_docs()
    verify_candidate()


if __name__ == "__main__":
    main()
