//! Hostile acceptance for issue #434 / parent #86.
//!
//! Protected main scores gateway path/query/body/IP but has no live proven-WAF
//! authority on the request path. A header-only exploit therefore must not be
//! silently forwarded by a block-mode route when Coraza/OWASP CRS is absent.
//! The minimum acceptable behavior before a proven engine evaluates the request
//! is fail-closed; the successor implementation will add the real engine port.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

#[tokio::test]
async fn block_route_fails_closed_for_header_only_attack_without_proven_waf() {
    let app = build_app(AppState::seeded(Some("secret".to_string())));

    let route = serde_json::json!({
        "id": "coraza-header-red",
        "path_prefix": "/header-red",
        "upstream": "mock://header-red",
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
                .expect("valid route request"),
        )
        .await
        .expect("router must answer route write");
    assert_eq!(created.status(), StatusCode::CREATED);

    // CRS detects Shellshock-style command injection in request headers. The
    // path/query/body are intentionally benign so Wardnet's local scorer cannot
    // accidentally satisfy this contract with an in-house signature.
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-red")
                .header("user-agent", "() { :;}; /bin/bash -c 'cat /etc/passwd'")
                .body(Body::empty())
                .expect("valid hostile request"),
        )
        .await
        .expect("gateway must answer hostile request");

    assert!(
        matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::SERVICE_UNAVAILABLE
        ),
        "block-mode traffic must fail closed until a proven Coraza/CRS authority evaluates header-borne attacks; got {}",
        response.status()
    );
}
