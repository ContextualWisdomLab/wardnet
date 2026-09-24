//! Hostile acceptance for issue #434 / parent #86.
//!
//! Protected main scores gateway path/query/body/IP but has no live proven-WAF
//! authority on the request path. A header-only exploit therefore must not be
//! silently forwarded by a block-mode route when Coraza/OWASP CRS is absent.
//! The minimum acceptable behavior before a proven engine evaluates the request
//! is fail-closed; the successor implementation will add the real engine port.
//!
//! With no proven engine configured, block mode must fail closed even for benign
//! headers because Wardnet has no authority to infer a clean verdict. The separate
//! configured-adapter test proves ordinary traffic passes after explicit clean evidence.

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
}

#[tokio::test]
async fn block_route_preserves_local_deny_before_unconfigured_proven_waf() {
    let app = app_with_block_route("coraza-local-deny", "/local-deny").await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/local-deny?q=1%20UNION%20SELECT%201")
                .body(Body::empty())
                .expect("valid hostile request"),
        )
        .await
        .expect("gateway must answer locally denied request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "independent Wardnet threat scoring may deny before Coraza; the missing proven engine gates only traffic that would otherwise proceed upstream"
    );
}
