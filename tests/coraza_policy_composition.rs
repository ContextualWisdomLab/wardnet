//! Coraza audit policy composition through authenticated management routes.
//! Synthetic audit records exercise the adapter, not a running Coraza engine.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

async fn read(app: &axum::Router, path: &str, token: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("x-admin-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}

async fn import(app: &axum::Router, token: &str, record: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/waf/coraza/audit")
                .header("content-type", "application/json")
                .header("x-admin-token", token)
                .body(Body::from(record.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    (status, value)
}

async fn indicators(app: &axum::Router, token: &str) -> Value {
    json!({
        "dnsbl": read(app, "/api/dnsbl", token).await,
        "threats": read(app, "/api/threats", token).await,
    })
}

async fn block_app(token: &str) -> axum::Router {
    let app = build_app(AppState::seeded(Some(token.to_string())));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/routes")
                .header("content-type", "application/json")
                .header("x-admin-token", token)
                .body(Body::from(
                    json!({
                        "id": "demo", "path_prefix": "/demo", "upstream": "mock://demo-upstream",
                        "mode": "block", "enabled": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let routes = read(&app, "/api/routes", token).await;
    assert_eq!(routes[0]["mode"], "block");
    app
}

async fn gateway(app: &axum::Router, ip: &str, path: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/gateway/demo{path}"))
                .header("x-real-ip", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    (status, value)
}

fn low_severity_record(ip: &str, path: &str, interrupted: bool) -> Value {
    json!({
        "transaction": {
            "client_ip": ip,
            "is_interrupted": interrupted,
            "request": {"uri": path},
        },
        "messages": [{"message": "synthetic policy observation", "data": {"severity": 3}}],
    })
}

#[tokio::test]
async fn mixed_array_publishes_only_block_grade_rows() {
    let token = format!("coraza-array-fixture-{}", std::process::id());
    let app = block_app(&token).await;
    let (status, result) = import(
        &app,
        &token,
        json!([
            low_severity_record("192.0.2.224", "/coraza-monitor?fixture=1", false),
            low_severity_record("192.0.2.225", "/coraza-array?fixture=1", true),
            {"transaction": {"response": {"http_code": 200}}}
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["accepted_hits"], 2);
    assert_eq!(result["skipped"], 1);
    assert_eq!(result["enforcement_hints"], 3);
    let events = read(&app, "/api/events", &token).await;
    let rows = events.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["action"], "monitor");
    assert_eq!(rows[1]["action"], "block");
    assert!(rows[0]["id"].as_u64().unwrap() < rows[1]["id"].as_u64().unwrap());
    assert_eq!(result["event_ids"], json!([rows[0]["id"], rows[1]["id"]]));
    let hints = indicators(&app, &token).await;
    let dnsbl: Vec<_> = hints["dnsbl"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["source"] == "engine:coraza")
        .collect();
    assert_eq!(dnsbl.len(), 1);
    assert_eq!(dnsbl[0]["address"], "192.0.2.225");
    let threats: Vec<_> = hints["threats"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["source"] == "engine:coraza")
        .collect();
    assert_eq!(threats.len(), 2);
    assert!(
        threats
            .iter()
            .all(|row| row["value"] == "192.0.2.225" || row["value"] == "/coraza-array")
    );
    let before = json!({"events": events, "indicators": hints,
        "audit": read(&app, "/api/audit-logs", &token).await});
    let (status, _) = import(&app, &token, json!([])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        before,
        json!({
            "events": read(&app, "/api/events", &token).await,
            "indicators": indicators(&app, &token).await,
            "audit": read(&app, "/api/audit-logs", &token).await
        })
    );
    let (status, response) = gateway(&app, "192.0.2.224", "/coraza-monitor").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["score"], 0);
    let (status, response) = gateway(&app, "192.0.2.225", "/coraza-array").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response["score"], 150);
}

#[tokio::test]
async fn message_free_interruptions_without_targets_do_not_publish_hints() {
    for record in [
        json!({"action": "BLOCK"}),
        json!({"action": "DeNy"}),
        json!({"action": "DrOp"}),
        json!({"transaction": {"response": {"http_code": 406}, "request": {"uri": "/"}}}),
    ] {
        let token = format!("coraza-action-fixture-{}", std::process::id());
        let app = block_app(&token).await;
        let before = indicators(&app, &token).await;
        let (status, result) = import(&app, &token, record.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(result["accepted_hits"], 1);
        assert_eq!(result["enforcement_hints"], 0);
        let events = read(&app, "/api/events", &token).await;
        assert_eq!(events.as_array().unwrap().len(), 1);
        assert_eq!(events[0]["score"], 50);
        assert_eq!(events[0]["action"], "block");
        assert_eq!(events[0]["reason"], "coraza/crs: transaction interrupted");
        assert_eq!(events[0]["client_ip"], Value::Null);
        assert_eq!(
            events[0]["path"],
            if record.get("transaction").is_some() {
                "/"
            } else {
                "coraza://transaction"
            }
        );
        assert_eq!(indicators(&app, &token).await, before);
    }
}

#[tokio::test]
async fn interrupted_low_severity_audit_publishes_medium_hints() {
    let token = format!("coraza-interruption-fixture-{}", std::process::id());
    let app = block_app(&token).await;
    let (status, result) = import(
        &app,
        &token,
        low_severity_record("192.0.2.222", "/coraza-low?fixture=1", true),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["enforcement_hints"], 3);
    let events = read(&app, "/api/events", &token).await;
    assert_eq!(events[0]["score"], 25);
    assert_eq!(events[0]["action"], "block");
    assert_eq!(events[0]["path"], "/coraza-low?fixture=1");
    let threats = read(&app, "/api/threats", &token).await;
    let hints: Vec<_> = threats
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["source"] == "engine:coraza")
        .collect();
    assert_eq!(hints.len(), 2);
    for row in &hints {
        assert_eq!(row["severity"], "medium");
        assert_eq!(row["ttl_seconds"], 3600);
    }
    assert!(
        hints
            .iter()
            .any(|row| row["indicator_type"] == "path" && row["value"] == "/coraza-low")
    );
    assert!(
        hints
            .iter()
            .any(|row| row["indicator_type"] == "client_ip" && row["value"] == "192.0.2.222")
    );
    let dnsbl = read(&app, "/api/dnsbl", &token).await;
    let row = dnsbl
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["source"] == "engine:coraza")
        .unwrap();
    assert_eq!(row["address"], "192.0.2.222");
    assert_eq!(row["code"], "127.0.0.2");
    assert_eq!(row["ttl_seconds"], 3600);
    let (status, response) = gateway(&app, "192.0.2.222", "/coraza-low").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response["score"], 150);
    // A medium path hint alone is below the seeded route's block threshold.
    let (status, response) = gateway(&app, "192.0.2.223", "/coraza-low").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["score"], 25);
}

#[tokio::test]
async fn monitor_audit_does_not_publish_enforcement_indicators() {
    let token = format!("coraza-policy-fixture-{}", std::process::id());
    let app = block_app(&token).await;
    let before = indicators(&app, &token).await;
    let (status, result) = import(
        &app,
        &token,
        low_severity_record("192.0.2.221", "/coraza-monitor?fixture=1", false),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["accepted_hits"], 1);
    assert_eq!(result["skipped"], 0);
    assert_eq!(result["enforcement_hints"], 0);
    let events = read(&app, "/api/events", &token).await;
    let rows = events.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(result["event_ids"], json!([rows[0]["id"]]));
    assert_eq!(rows[0]["action"], "monitor");
    assert_eq!(rows[0]["score"], 25);
    assert_eq!(rows[0]["client_ip"], "192.0.2.221");
    assert_eq!(rows[0]["path"], "/coraza-monitor?fixture=1");
    assert_eq!(indicators(&app, &token).await, before);
    let (status, response) = gateway(&app, "192.0.2.221", "/coraza-monitor").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["score"], 0);
}
