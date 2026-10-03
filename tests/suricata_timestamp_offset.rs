//! Suricata numeric offsets must retain the same UTC event occurrence time.
//! Offline synthetic records exercise the public parser and authenticated router.

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

#[tokio::test]
async fn authenticated_eve_import_retains_offset_occurrence_time() {
    let token = format!("time-offset-fixture-{}", std::process::id());
    let app = build_app(AppState::seeded(Some(token.clone())));
    let records = json!([
        {"event_type":"alert", "timestamp":"2024-06-15T13:34:56.123456+0100", "src_ip":"192.0.2.211", "http":{"url":"/offset"}, "alert":{"signature":"positive offset", "severity":1}},
        {"event_type":"alert", "timestamp":"2024-06-15T07:04:56-0530", "src_ip":"192.0.2.212", "http":{"url":"/offset"}, "alert":{"signature":"negative offset", "severity":1}}
    ]);
    let before = json!({
        "events":read(&app,"/api/events", &token).await,
        "dnsbl":read(&app,"/api/dnsbl", &token).await,
        "threats":read(&app,"/api/threats", &token).await,
        "audit":read(&app,"/api/audit-logs", &token).await
    });
    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/ids/suricata/eve")
                .header("content-type", "application/json")
                .body(Body::from(records.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        before,
        json!({
            "events":read(&app,"/api/events", &token).await,
            "dnsbl":read(&app,"/api/dnsbl", &token).await,
            "threats":read(&app,"/api/threats", &token).await,
            "audit":read(&app,"/api/audit-logs", &token).await
        })
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/ids/suricata/eve")
                .header("content-type", "application/json")
                .header("x-admin-token", &token)
                .body(Body::from(records.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let result: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(result["accepted_alerts"], 2);
    assert_eq!(result["enforcement_hints"], 6);
    let events = read(&app, "/api/events", &token).await;
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 2);
    for event in events {
        assert_eq!(event["timestamp_unix"], 1_718_454_896_u64);
        assert_eq!(event["score"], 80);
        assert_eq!(event["action"], "block");
        assert_eq!(event["path"], "/offset");
    }
    let dnsbl = read(&app, "/api/dnsbl", &token).await;
    let rows: Vec<_> = dnsbl
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["source"] == "engine:suricata")
        .collect();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["ttl_seconds"], 3600);
        assert_eq!(row["code"], "127.0.0.2");
    }
}
