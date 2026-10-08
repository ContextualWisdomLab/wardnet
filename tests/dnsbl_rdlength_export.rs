//! Authenticated admission rejects oversized metadata without replacing evidence.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

#[tokio::test]
async fn rejected_txt_rdata_overflow_preserves_saved_entry_and_zone() {
    let app = build_app(AppState::seeded(Some("rdlength-fixture-token".into())));
    let mut baseline_zone = None;
    for (payload, status) in [
        (65_279, StatusCode::CREATED),
        (65_280, StatusCode::BAD_REQUEST),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dnsbl")
                    .header("content-type", "application/json")
                    .header("x-admin-token", "rdlength-fixture-token")
                    .body(Body::from(
                        serde_json::json!({
                            "address": "192.0.2.10", "code": "127.0.0.2",
                            "reason": "x".repeat(payload - 12), "source": "unit", "ttl_seconds": 600
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::BAD_REQUEST {
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            assert!(
                String::from_utf8(body.to_vec())
                    .unwrap()
                    .contains("DNSBL TXT metadata exceeds 65535 wire bytes")
            );
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/dnsbl")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let entries: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let entry = entries
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["address"] == "192.0.2.10")
            .unwrap();
        assert_eq!(entry["reason"].as_str().unwrap().len(), 65_267);
        assert_eq!(entry["source"], "unit");
        assert_eq!(entry["ttl_seconds"], 600);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/dnsbl/zone")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let zone = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        if let Some(baseline) = &baseline_zone {
            assert_eq!(&zone, baseline, "rejected write changed published bytes");
        } else {
            baseline_zone = Some(zone);
        }
    }
}
