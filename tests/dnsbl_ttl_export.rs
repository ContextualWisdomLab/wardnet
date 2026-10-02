//! DNSBL API admission, readback and exported cache-lifetime contract.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

/// Exercise real authenticated routes with a disposable in-memory aggregate.
#[tokio::test]
async fn dnsbl_ttl_is_preserved_from_admission_to_zone_export() {
    let app = build_app(AppState::seeded(Some("ttl-fixture-token".to_string())));
    for (ttl, expected_status) in [
        (60u64, StatusCode::CREATED),
        (2_147_483_647, StatusCode::CREATED),
        (2_147_483_648, StatusCode::BAD_REQUEST),
        (u64::MAX, StatusCode::BAD_REQUEST),
        (0, StatusCode::BAD_REQUEST),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/dnsbl")
                    .header("content-type", "application/json")
                    .header("x-admin-token", "ttl-fixture-token")
                    .body(Body::from(
                        serde_json::json!({
                            "address": "192.0.2.10", "code": "127.0.0.2",
                            "reason": "scanner", "source": "unit", "ttl_seconds": ttl
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let entries: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let saved = entries
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["address"] == "192.0.2.10")
            .unwrap();
        let expected_ttl = if expected_status == StatusCode::CREATED {
            ttl
        } else {
            2_147_483_647
        };
        assert_eq!(saved["ttl_seconds"], expected_ttl);
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
        let zone = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            zone.contains(&format!("10.2.0.192 {expected_ttl} IN A 127.0.0.2\n")),
            "{zone}"
        );
        assert!(
            zone.contains(&format!(
                "10.2.0.192 {expected_ttl} IN TXT \"scanner source=unit\"\n"
            )),
            "{zone}"
        );
        assert_eq!(
            zone.lines().count(),
            6,
            "rejected writes must not add records"
        );
    }
}
