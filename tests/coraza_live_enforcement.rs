//! Hostile acceptance for issue #434 / parent #86.
//!
//! Protected main scores gateway path/query/body/IP but has no live proven-WAF
//! authority on the request path. A header-only exploit therefore must not be
//! silently forwarded by a block-mode route when Coraza/OWASP CRS is absent.
//! The minimum acceptable behavior before a proven engine evaluates the request
//! is fail-closed; the successor implementation will add the real engine port.
//!
//! The paired benign-header test is intentionally part of the same contract:
//! the repair must not turn every block-mode request into a blanket 503. A real
//! Coraza/CRS adapter must distinguish an attack from ordinary header traffic.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

async fn app_with_block_route(route_id: &str, path_prefix: &str) -> axum::Router {
    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let route = serde_json::json!({
        "id": route_id,
        "path_prefix": path_prefix,
        "upstream": format!("mock://{route_id}"),
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
    app
}

#[tokio::test]
async fn block_route_fails_closed_for_header_only_attack_without_proven_waf() {
    let app = app_with_block_route("coraza-header-red", "/header-red").await;

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

#[tokio::test]
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
}
