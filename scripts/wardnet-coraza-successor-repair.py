#!/usr/bin/env python3
"""Re-prove and repair the bounded live Coraza authority boundary for PR #435.

This is a one-shot repair harness. It intentionally re-establishes the three
hostile semantic REDs before materializing the minimum Wardnet-owned fixes, then
runs exact repository verification. The companion workflow removes this helper
from the verified production candidate before pushing it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TMP_AUTHORITY = Path("/tmp/wardnet-coraza-authority-repair.py")
TMP_GENERATOR = Path("/tmp/wardnet-coraza-bounded-repair.sh")


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def replace_once(text: str, old: str, new: str, seam: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected exactly one {seam} seam, found {count}")
    return text.replace(old, new, 1)


def run(argv: list[str]) -> None:
    subprocess.run(argv, cwd=ROOT, check=True)


def expect_semantic_red(argv: list[str], required: tuple[str, ...]) -> None:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(result.stdout, end="")
    if result.returncode == 0:
        fail(f"expected hostile semantic RED but command succeeded: {' '.join(argv)}")
    for needle in required:
        if needle not in result.stdout:
            fail(f"hostile RED did not contain required evidence: {needle}")


def prepare_stage_helper() -> None:
    shutil.copy2(ROOT / "scripts/wardnet-coraza-authority-repair.py", TMP_AUTHORITY)
    shutil.copy2(ROOT / "scripts/wardnet-coraza-bounded-repair.sh", TMP_GENERATOR)

    text = TMP_AUTHORITY.read_text()
    text = replace_once(
        text,
        'if text.count("tests/coraza_live_enforcement.rs") != 2:',
        'if text.count("tests/coraza_live_enforcement.rs") != 3:',
        "generated-test seam-count guard",
    )
    text = replace_once(
        text,
        'path = Path("scripts/wardnet-coraza-bounded-repair.sh")',
        'path = Path("/tmp/wardnet-coraza-bounded-repair.sh")',
        "temporary generator path",
    )
    text = replace_once(
        text,
        '''def stage() -> None:
    harden_generator()
    subprocess.run(["bash", "scripts/wardnet-coraza-bounded-repair.sh"], check=True)''',
        '''def stage() -> None:
    harden_generator()
    subprocess.run(["bash", "/tmp/wardnet-coraza-bounded-repair.sh"], check=True)''',
        "temporary stage orchestration",
    )
    TMP_AUTHORITY.write_text(text)


def stage_candidate() -> None:
    run(["python", str(TMP_AUTHORITY), "stage"])

    path = ROOT / "tests/coraza_live_enforcement.rs"
    text = path.read_text()
    text = replace_once(
        text,
        '''//! The paired benign-header test is intentionally part of the same contract:
//! the repair must not turn every block-mode request into a blanket 503. A real
//! Coraza/CRS adapter must distinguish an attack from ordinary header traffic.''',
        '''//! With no proven engine configured, block mode must fail closed even for benign
//! headers because Wardnet has no authority to infer a clean verdict. The separate
//! configured-adapter test proves ordinary traffic passes after explicit clean evidence.''',
        "stale no-authority module comment",
    )
    path.write_text(text)
    run(["cargo", "fmt"])
    run(["git", "diff", "--check"])


def prove_and_fix_disruption_authority() -> None:
    run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_non_disruptive_detection",
            "--no-run",
        ]
    )
    expect_semantic_red(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_non_disruptive_detection",
            "block_route_does_not_escalate_non_disruptive_coraza_detection_to_block",
            "--",
            "--exact",
            "--nocapture",
        ],
        (
            "block_route_does_not_escalate_non_disruptive_coraza_detection_to_block ... FAILED",
            "non-interrupted HTTP 200 Coraza evidence with a CRS message",
        ),
    )
    run(["python", str(TMP_AUTHORITY), "fix"])
    run(["cargo", "fmt"])
    run(["git", "diff", "--check"])


def prove_and_fix_raw_client_attribution() -> None:
    source = ROOT / "src/proven_engine.rs"
    text = source.read_text()
    text = replace_once(
        text,
        '''        "origin",
        "x-requested-with",
    ];''',
        '''        "origin",
        "x-requested-with",
        "x-forwarded-for",
        "x-real-ip",
    ];''',
        "hardened raw client-attribution allowlist",
    )
    source.write_text(text)

    path = ROOT / "tests/coraza_proven_engine_adapter.rs"
    text = path.read_text()
    text = replace_once(
        text,
        '''                .header("authorization", "Bearer must-not-forward")
                .header("cookie", "session=must-not-forward")
                .header("x-admin-token", "must-not-forward")''',
        '''                .header("authorization", "Bearer must-not-forward")
                .header("cookie", "session=must-not-forward")
                .header("x-admin-token", "must-not-forward")
                .header("x-forwarded-for", "198.51.100.66")
                .header("x-real-ip", "198.51.100.77")''',
        "hostile Coraza request-header fixture",
    )
    text = replace_once(
        text,
        '''    for forbidden in [
        "authorization",
        "cookie",
        "x-admin-token",
        "proxy-authorization",
        "x-forwarded-for",
        "x-real-ip",
    ] {
        assert!(headers.iter().all(|header| header["name"] != forbidden));
    }''',
        '''    for forbidden in [
        "authorization",
        "cookie",
        "x-admin-token",
        "proxy-authorization",
        "x-forwarded-for",
        "x-real-ip",
    ] {
        assert!(
            headers.iter().all(|header| header["name"] != forbidden),
            "raw client-attribution header {forbidden} must not cross the Coraza sidecar boundary"
        );
    }''',
        "forwarded-header denial assertion",
    )
    path.write_text(text)

    run(["cargo", "fmt"])
    run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_proven_engine_adapter",
            "--no-run",
        ]
    )
    expect_semantic_red(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_proven_engine_adapter",
            "block_route_uses_coraza_for_header_only_attack_and_minimizes_credentials",
            "--",
            "--exact",
            "--nocapture",
        ],
        (
            "block_route_uses_coraza_for_header_only_attack_and_minimizes_credentials ... FAILED",
            "raw client-attribution header x-forwarded-for must not cross the Coraza sidecar boundary",
        ),
    )

    text = source.read_text()
    text = replace_once(
        text,
        '''        "origin",
        "x-requested-with",
        "x-forwarded-for",
        "x-real-ip",
    ];''',
        '''        "origin",
        "x-requested-with",
    ];''',
        "raw client-attribution header allowlist",
    )
    source.write_text(text)
    run(["cargo", "fmt"])
    run(["git", "diff", "--check"])


def prove_incomplete_header_envelope_red() -> None:
    path = ROOT / "tests/coraza_proven_engine_adapter.rs"
    text = path.read_text()
    test_name = "block_route_fails_closed_before_sidecar_on_incomplete_header_envelope"
    if test_name in text:
        fail("incomplete-header hostile test unexpectedly exists before successor staging")
    path.write_text(
        text
        + r'''

#[tokio::test]
async fn block_route_fails_closed_before_sidecar_on_incomplete_header_envelope() {
    let (url, calls, task) = spawn_coraza_sidecar().await;
    let app = app_with_route(
        "coraza-header-envelope",
        "/header-envelope",
        "block",
        &url,
    )
    .await;
    let oversized = "x".repeat(9_000);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-envelope")
                .header("user-agent", oversized.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an incomplete allowlisted-header projection must fail closed instead of accepting a clean Coraza verdict for a request the sidecar did not inspect in full"
    );
    assert_eq!(
        calls.lock().await.len(),
        0,
        "Wardnet must not ask Coraza to authorize a partial allowlisted-header envelope"
    );
    task.abort();
}
'''
    )
    run(["cargo", "fmt"])
    run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_proven_engine_adapter",
            "--no-run",
        ]
    )
    expect_semantic_red(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "coraza_proven_engine_adapter",
            test_name,
            "--",
            "--exact",
            "--nocapture",
        ],
        (
            f"{test_name} ... FAILED",
            "an incomplete allowlisted-header projection must fail closed",
        ),
    )


def replace_function(text: str, start_marker: str, end_marker: str, new: str, seam: str) -> str:
    try:
        start = text.index(start_marker)
        end = text.index(end_marker, start)
    except ValueError as error:
        fail(f"could not locate {seam} boundary: {error}")
    if text.find(start_marker, start + 1) != -1:
        fail(f"expected exactly one {seam} start marker")
    return text[:start] + new + text[end:]


def apply_complete_header_envelope_fix() -> None:
    source = ROOT / "src/proven_engine.rs"
    text = source.read_text()
    start_marker = "pub(crate) fn engine_forwarded_headers("
    end_marker = "\n\nfn sidecar_request_body("
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    old_block = text[start:end]
    for required in (
        "-> Vec<(String, String)>",
        "return forwarded;",
        "let Ok(value) = value.to_str() else",
        "FORWARDED_HEADERS_MAX_BYTES",
    ):
        if required not in old_block:
            fail(f"partial Coraza header-envelope seam lost expected pre-fix evidence: {required}")
    if old_block.count("return forwarded;") != 2:
        fail("partial Coraza header-envelope seam must have exactly two truncating returns")

    new_block = '''pub(crate) fn engine_forwarded_headers(
    headers: &axum::http::HeaderMap,
) -> Result<Vec<(String, String)>, String> {
    let allowlist = [
        "host",
        "user-agent",
        "accept",
        "content-type",
        "referer",
        "origin",
        "x-requested-with",
    ];
    let mut forwarded = Vec::new();
    let mut total = 0usize;
    for name in allowlist {
        for value in headers.get_all(name) {
            if forwarded.len() >= FORWARDED_HEADER_LIMIT {
                return Err(format!(
                    "Coraza request header envelope exceeds {FORWARDED_HEADER_LIMIT} fields"
                ));
            }
            let value = value.to_str().map_err(|_| {
                format!("Coraza allowlisted request header {name} is not UTF-8")
            })?;
            let next = total.saturating_add(name.len()).saturating_add(value.len());
            if next > FORWARDED_HEADERS_MAX_BYTES {
                return Err(format!(
                    "Coraza request header envelope exceeds {FORWARDED_HEADERS_MAX_BYTES} bytes"
                ));
            }
            total = next;
            forwarded.push((name.to_string(), value.to_string()));
        }
    }
    Ok(forwarded)
}'''
    text = text[:start] + new_block + text[end:]

    eval_start = text.index("pub(crate) async fn evaluate_sidecar(")
    response_marker = "    let response = match client"
    eval_end = text.index(response_marker, eval_start)
    old_prefix = text[eval_start:eval_end]
    for required in (
        "headers: &[(String, String)]",
        "ProvenEngineOutcome::Unavailable",
        "let payload = sidecar_request_body",
    ):
        if required not in old_prefix:
            fail(f"Coraza sidecar argument seam lost expected pre-fix evidence: {required}")
    new_prefix = '''pub(crate) async fn evaluate_sidecar(
    client: &reqwest::Client,
    config: &ProvenEngineConfig,
    method: &str,
    uri: &str,
    body: &str,
    client_ip: Option<IpAddr>,
    headers: &axum::http::HeaderMap,
    policy_id: &str,
) -> ProvenEngineOutcome {
    let Some(url) = config.sidecar_url() else {
        return ProvenEngineOutcome::Unavailable {
            reason: "Coraza proven engine is not configured".to_string(),
        };
    };
    let forwarded_headers = match engine_forwarded_headers(headers) {
        Ok(headers) => headers,
        Err(reason) => return ProvenEngineOutcome::Unavailable { reason },
    };
    let payload = sidecar_request_body(
        method,
        uri,
        body,
        client_ip,
        &forwarded_headers,
        policy_id,
    );
'''
    text = text[:eval_start] + new_prefix + text[eval_end:]

    unit_start_marker = "    #[test]\n    fn header_forwarding_is_bounded_and_excludes_credentials()"
    unit_end_marker = "\n\n    #[test]\n    fn clean_evidence_requires_exact_request_correlation()"
    unit_start = text.index(unit_start_marker)
    unit_end = text.index(unit_end_marker, unit_start)
    unit_block = text[unit_start:unit_end]
    if "engine_forwarded_headers(&oversized).is_empty()" not in unit_block:
        fail("Coraza header unit-contract seam lost pre-fix truncation assertion")
    new_unit = '''    #[test]
    fn header_forwarding_is_bounded_and_excludes_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("wardnet.example"));
        headers.insert("user-agent", HeaderValue::from_static("buyer-probe/1"));
        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        headers.insert("cookie", HeaderValue::from_static("sid=secret"));
        headers.insert("x-admin-token", HeaderValue::from_static("admin-secret"));
        let forwarded = engine_forwarded_headers(&headers).expect("complete bounded headers");
        let names: Vec<&str> = forwarded.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["host", "user-agent"]);

        let mut oversized = HeaderMap::new();
        oversized.insert(
            "user-agent",
            HeaderValue::from_str(&"x".repeat(FORWARDED_HEADERS_MAX_BYTES + 1)).unwrap(),
        );
        assert!(engine_forwarded_headers(&oversized).is_err());

        let mut opaque = HeaderMap::new();
        opaque.insert("user-agent", HeaderValue::from_bytes(&[0x80]).unwrap());
        assert!(engine_forwarded_headers(&opaque).is_err());
    }'''
    text = text[:unit_start] + new_unit + text[unit_end:]
    source.write_text(text)

    caller = ROOT / "src/lib.rs"
    text = caller.read_text()
    text = replace_once(
        text,
        '''    let forwarded_headers = proven_engine::engine_forwarded_headers(&headers);
    let mut proven_engine_recorded = false;''',
        '''    let mut proven_engine_recorded = false;''',
        "prebuilt Coraza header-envelope caller",
    )
    text = replace_once(
        text,
        '''        &forwarded_headers,
        &route.id,''',
        '''        &headers,
        &route.id,''',
        "Coraza header-envelope call",
    )
    caller.write_text(text)

    doc = ROOT / "docs/doctoring/in-path-coraza-adapter.md"
    text = doc.read_text()
    text = replace_once(
        text,
        "Header forwarding is capped at 32 fields / 8 KiB. Sidecar evaluation has a 1.5 s timeout and a 1 MiB response cap.",
        "Header forwarding is capped at 32 fields / 8 KiB. If any allowlisted value cannot be represented as UTF-8 or the complete allowlisted envelope would exceed either cap, Wardnet records `engine_unavailable` and does not call the sidecar; a partial request projection is never eligible for a clean verdict. Sidecar evaluation has a 1.5 s timeout and a 1 MiB response cap.",
        "Coraza header-envelope doctoring documentation",
    )
    doc.write_text(text)

    threat = ROOT / "docs/security/threat-model.md"
    text = threat.read_text()
    text = replace_once(
        text,
        "forwards a bounded credential-minimized request envelope, and treats an unconfigured engine",
        "forwards a complete bounded credential-minimized request envelope, rejects unrepresentable or truncated allowlisted headers before sidecar authorization, and treats an unconfigured engine",
        "Coraza complete-envelope threat-model documentation",
    )
    threat.write_text(text)

    run(["cargo", "fmt"])
    run(["git", "diff", "--check"])


def verify_candidate() -> None:
    commands = (
        ["cargo", "fmt", "--check"],
        ["git", "diff", "--check"],
        ["cargo", "test", "--locked", "--test", "coraza_live_enforcement"],
        ["cargo", "test", "--locked", "--test", "coraza_proven_engine_adapter"],
        ["cargo", "test", "--locked", "--test", "coraza_non_disruptive_detection"],
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
    for command in commands:
        run(command)


def main() -> None:
    prepare_stage_helper()
    stage_candidate()
    prove_and_fix_disruption_authority()
    prove_and_fix_raw_client_attribution()
    prove_incomplete_header_envelope_red()
    apply_complete_header_envelope_fix()
    verify_candidate()


if __name__ == "__main__":
    main()
