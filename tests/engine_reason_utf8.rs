//! Real management routes must not panic while deriving bounded engine hints.
//! Documents and credentials are synthetic; no live engine/service is used.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

async fn read(app: &axum::Router, path: &str) -> Value {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}

async fn check_engine(coraza: bool) {
    let token = format!("engine-utf8-fixture-{}", std::process::id());
    let (endpoint, source, prefix) = if coraza {
        ("/api/waf/coraza/audit", "engine:coraza", "coraza/crs: ")
    } else {
        ("/api/ids/suricata/eve", "engine:suricata", "suricata: ")
    };
    for message in [
        format!("{}{}", if coraza { "" } else { "x" }, "한".repeat(90)),
        "🛡".repeat(70),
    ] {
        let app = build_app(AppState::seeded(Some(token.clone())));
        let expected_full = format!("{prefix}{message}");
        assert!(expected_full.len() > 200);
        assert!(
            !expected_full.is_char_boundary(199),
            "fixture must bisect UTF-8"
        );
        let document = if coraza {
            json!({"transaction": {
                "client_ip": "192.0.2.201", "is_interrupted": true,
                "request": {"uri": "/utf8?fixture=1"}
            }, "messages": [{"message": message, "data": {"severity": 1}}]})
        } else {
            json!({"event_type": "alert", "src_ip": "192.0.2.201",
                "http": {"url": "/utf8?fixture=1"},
                "alert": {"signature": message, "severity": 1}})
        };
        let before = read(&app, "/api/dnsbl").await;
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("content-type", "application/json")
                    .body(Body::from(document.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(read(&app, "/api/dnsbl").await, before);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("content-type", "application/json")
                    .header("x-admin-token", &token)
                    .body(Body::from(document.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let result: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(result["enforcement_hints"], 3);
        let events = read(&app, "/api/events").await;
        assert!(
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"] == expected_full
                    && row["action"] == "block"
                    && row["score"] == 80)
        );
        // Independent expected prefix: whole scalar values whose cumulative
        // UTF-8 length fits the existing 199-byte payload allowance.
        let mut expected = String::new();
        for ch in expected_full.chars() {
            if expected.len() + ch.len_utf8() > 199 {
                break;
            }
            expected.push(ch);
        }
        expected.push('…');
        let rows = read(&app, "/api/dnsbl").await;
        let row = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["source"] == source)
            .unwrap();
        assert_eq!(row["reason"], expected);
        assert_eq!(row["ttl_seconds"], 3600);
        assert_eq!(row["code"], "127.0.0.2");
        let threats = read(&app, "/api/threats").await;
        assert_eq!(
            threats
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["source"] == source)
                .count(),
            2
        );
    }
}

#[tokio::test]
async fn coraza_long_unicode_reason_preserves_events_and_bounded_hints() {
    check_engine(true).await;
}

#[tokio::test]
async fn suricata_long_unicode_reason_preserves_events_and_bounded_hints() {
    check_engine(false).await;
}
