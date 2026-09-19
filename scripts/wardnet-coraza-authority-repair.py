#!/usr/bin/env python3
"""Stage and repair the bounded live Coraza authority contract for PR #435.

This temporary helper exists only to make the hostile RED and causal fix
reproducible on a hosted runner. It is removed by the one-shot workflow after
the exact candidate is GREEN.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def replace_once(text: str, old: str, new: str, seam: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one {seam} seam, found {count}")
    return text.replace(old, new, 1)


def harden_generator() -> None:
    path = Path("scripts/wardnet-coraza-bounded-repair.sh")
    text = path.read_text()

    text = replace_once(
        text,
        '        "x-requested-with",\n        "x-forwarded-for",\n        "x-real-ip",\n',
        '        "x-requested-with",\n',
        "staged forwarding-header allowlist",
    )
    text = replace_once(
        text,
        'for forbidden in ["authorization", "cookie", "x-admin-token", "proxy-authorization"] {',
        'for forbidden in ["authorization", "cookie", "x-admin-token", "proxy-authorization", "x-forwarded-for", "x-real-ip"] {',
        "staged forbidden-header assertion",
    )
    text = replace_once(
        text,
        '''    let interrupted = tx
        .get("is_interrupted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);''',
        '''    let explicitly_not_interrupted = tx
        .get("is_interrupted")
        .and_then(|value| value.as_bool())
        == Some(false);''',
        "staged implicit clean evidence",
    )
    text = replace_once(
        text,
        '''    !interrupted
        && status.is_some_and(|code| code < 400)''',
        '''    explicitly_not_interrupted
        && status.is_some_and(|code| code < 400)''',
        "staged clean predicate",
    )
    text = replace_once(
        text,
        '''          "transaction": {
            "request": {"method":"GET","uri":"/ok"},''',
        '''          "transaction": {
            "is_interrupted": false,
            "request": {"method":"GET","uri":"/ok"},''',
        "staged unit clean-evidence fixture",
    )
    text = replace_once(
        text,
        '''        "transaction": {
            "request": {"method": method, "uri": uri},
            "response": {"http_code": 200}''',
        '''        "transaction": {
            "is_interrupted": false,
            "request": {"method": method, "uri": uri},
            "response": {"http_code": 200}''',
        "staged integration clean-evidence fixture",
    )
    docs = "`Authorization`, `Cookie`, `Proxy-Authorization`, and `X-Admin-Token` are never forwarded."
    text = replace_once(
        text,
        docs,
        docs
        + " Raw `X-Forwarded-For` and `X-Real-IP` are also withheld until Wardnet's trusted-proxy attribution owner reaches protected truth; the sidecar receives the transport-derived `client_ip` separately.",
        "staged header-minimization documentation",
    )
    if text.count("tests/coraza_live_enforcement.rs") != 2:
        raise SystemExit("expected exactly two staged generated-test path seams")
    text = text.replace(
        "tests/coraza_live_enforcement.rs", "tests/coraza_proven_engine_adapter.rs"
    )
    text = replace_once(text, "    NotConfigured,\n", "", "NotConfigured enum")
    text = replace_once(
        text,
        '''    let Some(url) = config.sidecar_url() else {
        return ProvenEngineOutcome::NotConfigured;
    };''',
        '''    let Some(url) = config.sidecar_url() else {
        return ProvenEngineOutcome::Unavailable {
            reason: "Coraza proven engine is not configured".to_string(),
        };
    };''',
        "no-engine outcome",
    )
    text = replace_once(
        text,
        '''        proven_engine::ProvenEngineOutcome::NotConfigured
        | proven_engine::ProvenEngineOutcome::Clean => {}''',
        "        proven_engine::ProvenEngineOutcome::Clean => {}",
        "caller NotConfigured",
    )
    path.write_text(text)


def write_detection_red() -> None:
    Path("tests/coraza_non_disruptive_detection.rs").write_text(
        r'''use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    routing::post,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, ProvenEngineConfig, build_app};

async fn detection_only() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "transaction": {
            "client_ip": "203.0.113.44",
            "is_interrupted": false,
            "request": {"method": "GET", "uri": "/detect-only"},
            "response": {"http_code": 200}
        },
        "messages": [{
            "message": "Protocol Attack Detected",
            "data": {"id": 921110, "severity": 2}
        }],
        "engine": {"name": "coraza", "ruleset": "owasp-crs-test-fixture"}
    }))
}

async fn spawn_coraza_sidecar() -> (String, JoinHandle<()>) {
    let app = Router::new().route("/evaluate", post(detection_only));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/evaluate"), task)
}

async fn app_with_block_route(sidecar_url: &str) -> axum::Router {
    let state = AppState::seeded(Some("secret".to_string())).with_proven_engine(
        ProvenEngineConfig::sidecar(sidecar_url).expect("loopback sidecar"),
    );
    let app = build_app(state);
    let route = serde_json::json!({
        "id": "coraza-detect-only",
        "path_prefix": "/detect-only",
        "upstream": "mock://coraza-detect-only",
        "mode": "block",
        "enabled": true,
        "block_threshold": null
    })
    .to_string();

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/routes")
                .header(CONTENT_TYPE, "application/json")
                .header("x-admin-token", "secret")
                .body(Body::from(route))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    app
}

#[tokio::test]
async fn block_route_does_not_escalate_non_disruptive_coraza_detection_to_block() {
    let (url, task) = spawn_coraza_sidecar().await;
    let app = app_with_block_route(&url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/detect-only")
                .header("user-agent", "wardnet-detection-probe/1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "non-interrupted HTTP 200 Coraza evidence with a CRS message must remain SOC detection evidence rather than implicit engine block authority"
    );
    task.abort();
}
'''
    )


def reconcile_unconfigured_contract() -> None:
    test = Path("tests/coraza_live_enforcement.rs")
    text = test.read_text()
    old = '''#[tokio::test]
async fn block_route_does_not_blanket_fail_closed_for_benign_headers() {
    let app = app_with_block_route("coraza-header-benign", "/header-benign").await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-benign")
                .header("user-agent", "wardnet-buyer-probe/1.0")
                .header("accept", "application/json")
                .body(Body::empty())
                .expect("valid benign request"),
        )
        .await
        .expect("gateway must answer benign request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a repair may not make every block-mode request unavailable; benign headers must pass once evaluated by the live WAF path"
    );
}'''
    new = '''#[tokio::test]
async fn block_route_fails_closed_for_benign_headers_when_proven_waf_is_unconfigured() {
    let app = app_with_block_route("coraza-header-benign", "/header-benign").await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-benign")
                .header("user-agent", "wardnet-buyer-probe/1.0")
                .header("accept", "application/json")
                .body(Body::empty())
                .expect("valid benign request"),
        )
        .await
        .expect("gateway must answer benign request");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "block mode must not infer a clean WAF verdict when no proven engine is configured; the adapter contract separately proves benign traffic passes after explicit clean evidence"
    );
}'''
    test.write_text(replace_once(text, old, new, "stale benign no-authority contract"))

    replacements = {
        Path("docs/architecture.md"): (
            "fails block-mode traffic closed on unusable configured-engine evidence",
            "fails block-mode traffic closed when the proven engine is unconfigured or its evidence is unusable",
        ),
        Path("docs/doctoring/in-path-coraza-adapter.md"): (
            "Malformed, oversized, uncorrelated, timed-out, or unreachable evidence is `engine_unavailable`; a block-mode route fails closed with HTTP 503.",
            "An unconfigured engine and malformed, oversized, uncorrelated, timed-out, or unreachable evidence are `engine_unavailable`; a block-mode route fails closed with HTTP 503.",
        ),
        Path("docs/runbooks/operations.md"): (
            "fails block mode closed on unusable configured-engine evidence",
            "fails block mode closed when the proven engine is unconfigured or its evidence is unusable",
        ),
        Path("docs/security/threat-model.md"): (
            "treats malformed, oversized, uncorrelated, timed-out, or unreachable evidence as `engine_unavailable`; block-mode routes fail closed.",
            "treats an unconfigured engine and malformed, oversized, uncorrelated, timed-out, or unreachable evidence as `engine_unavailable`; block-mode routes fail closed.",
        ),
    }
    for path, (old, new) in replacements.items():
        text = path.read_text()
        path.write_text(replace_once(text, old, new, f"documentation in {path}"))


def stage() -> None:
    harden_generator()
    subprocess.run(["bash", "scripts/wardnet-coraza-bounded-repair.sh"], check=True)
    write_detection_red()
    reconcile_unconfigured_contract()


def fix() -> None:
    path = Path("src/proven_engine.rs")
    text = path.read_text()

    marker = '''fn evidence_suffix(value: &serde_json::Value, policy_id: &str) -> String {'''
    helper = '''fn response_proves_disruption(
    value: &serde_json::Value,
    sidecar_status: reqwest::StatusCode,
) -> bool {
    if matches!(sidecar_status.as_u16(), 403 | 406) {
        return true;
    }
    let tx = value.get("transaction").unwrap_or(value);
    tx.get("is_interrupted")
        .and_then(|value| value.as_bool())
        == Some(true)
        || tx
            .pointer("/response/http_code")
            .or_else(|| tx.pointer("/response/status"))
            .and_then(|value| value.as_u64())
            .is_some_and(|code| matches!(code, 403 | 406))
}

fn evidence_suffix(value: &serde_json::Value, policy_id: &str) -> String {'''
    text = replace_once(text, marker, helper, "live disruption predicate insertion")

    old = '''        Ok(mut parsed) if !parsed.hits.is_empty() => {
            let idx = parsed
                .hits
                .iter()
                .position(|hit| hit.action == "block")
                .unwrap_or(0);
            let mut hit = parsed.hits.swap_remove(idx);
            hit.reason = format!("{}; {suffix}", hit.reason);
            if matches!(status.as_u16(), 403 | 406) {
                hit.action = "block".to_string();
            }
            ProvenEngineOutcome::Hit(hit)
        }'''
    new = '''        Ok(mut parsed) if !parsed.hits.is_empty() => {
            let disruptive = response_proves_disruption(&value, status);
            let idx = parsed
                .hits
                .iter()
                .position(|hit| hit.action == "block")
                .unwrap_or(0);
            let mut hit = parsed.hits.swap_remove(idx);
            hit.reason = format!("{}; {suffix}", hit.reason);
            hit.action = if disruptive { "block" } else { "monitor" }.to_string();
            ProvenEngineOutcome::Hit(hit)
        }'''
    text = replace_once(text, old, new, "live detection/disruption authority projection")
    path.write_text(text)

    docs_path = Path("docs/doctoring/in-path-coraza-adapter.md")
    docs = docs_path.read_text()
    old_docs = "Block evidence retains Coraza/CRS rule text/ID from the audit adapter and adds Wardnet policy identity plus sidecar ruleset identity when supplied."
    new_docs = (
        "Coraza/CRS rule messages retain their rule text/ID as SOC evidence, but the live adapter projects enforcement authority separately: only explicit `is_interrupted=true`, HTTP 403/406 from the sidecar, or transaction response 403/406 is disruptive. A non-interrupted successful transaction with rule messages remains monitor evidence and is never promoted to a block merely because audit severity maps to a high score. Wardnet adds policy identity plus sidecar ruleset identity when supplied."
    )
    docs_path.write_text(replace_once(docs, old_docs, new_docs, "detection/disruption documentation"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("stage", "fix"))
    args = parser.parse_args()
    if args.mode == "stage":
        stage()
    else:
        fix()


if __name__ == "__main__":
    main()
