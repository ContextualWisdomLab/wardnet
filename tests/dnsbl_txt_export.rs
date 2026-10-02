//! HTTP admission-to-DNSBL-publishing regression without a live server.

#[path = "support/dnsbl_txt.rs"]
mod dnsbl_txt;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

#[tokio::test]
async fn admitted_long_dnsbl_metadata_exports_as_lossless_valid_txt() {
    let app = build_app(AppState::seeded(Some("dnsbl-fixture-token".to_string())));
    let reason = format!("{}한🛡\\\"\n", "x".repeat(254));
    let source = "test:source\\\"\n".repeat(50);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/dnsbl")
                .header("content-type", "application/json")
                .header("x-admin-token", "dnsbl-fixture-token")
                .body(Body::from(
                    serde_json::json!({
                        "address": "192.0.2.10", "code": "127.0.0.2",
                        "reason": reason, "source": source, "ttl_seconds": 300
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/dnsbl/zone")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    let zone = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    dnsbl_txt::assert_zone_txt_valid(&zone);
    assert_eq!(zone.lines().count(), 6, "seed plus admitted entry only");
    let text = zone
        .lines()
        .find_map(|line| line.strip_prefix("10.2.0.192 IN TXT "))
        .unwrap();
    let strings = dnsbl_txt::decode_txt_rdata(text);
    assert!(strings.len() > 1);
    assert_eq!(
        strings.concat(),
        format!("{reason} source={source}").as_bytes()
    );
}
