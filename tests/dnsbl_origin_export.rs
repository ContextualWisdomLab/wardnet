//! Config-to-HTTP DNSBL publication boundary without an operational server.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppConfig, AppState, build_app};

/// Invalid operator origins must not produce an unloadable publication response.
#[tokio::test]
async fn configured_dnsbl_origin_is_checked_at_the_http_publication_boundary() {
    let cases = [
        ("dnsbl.example.".to_string(), "dnsbl.example".to_string()),
        ("dnsbl..example".to_string(), "dnsbl.invalid".to_string()),
        (
            format!("{}.example", "a".repeat(64)),
            "dnsbl.invalid".to_string(),
        ),
        (
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(46),
            ]
            .join("."),
            "dnsbl.invalid".to_string(),
        ),
    ];
    for (origin, expected) in cases {
        let mut config = AppConfig::memory(None);
        config.dnsbl_origin = origin;
        let state = AppState::load(config).await.unwrap();
        let app = build_app(state);
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let zone = std::str::from_utf8(&body).unwrap();
        assert!(
            zone.starts_with(&format!("$ORIGIN {expected}.\n")),
            "{zone}"
        );
        assert!(zone.contains("IN A 127.0.0.2"));
        assert!(zone.contains("IN TXT "));
    }
}
