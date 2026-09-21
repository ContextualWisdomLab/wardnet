//! Hostile buyer acceptance for #440: Wardnet must preserve only explicitly
//! admitted end-to-end HTTP metadata across the generic gateway boundary.
//!
//! The benign preservation assertions are intentionally RED against the current
//! protected behavior. Security assertions pin the least-authority boundary at
//! the same time so the eventual GREEN cannot become a transparent header tunnel.
//! Production source stays byte-identical in this test-only phase.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode,
        header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST},
    },
    response::{IntoResponse, Response},
    routing::any,
};
use tokio::sync::Mutex;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

#[derive(Clone, Default)]
struct Capture {
    request_headers: Arc<Mutex<Option<HeaderMap>>>,
}

async fn capture_upstream(State(capture): State<Capture>, headers: HeaderMap) -> Response {
    *capture.request_headers.lock().await = Some(headers);

    let mut response = (StatusCode::ACCEPTED, r#"{"ok":true}"#).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response.headers_mut().append(
        "x-wardnet-app-meta",
        HeaderValue::from_static("buyer-contract-v1"),
    );
    response.headers_mut().append(
        "x-wardnet-app-meta",
        HeaderValue::from_static("buyer-contract-v2"),
    );
    response
        .headers_mut()
        .insert("location", HeaderValue::from_static("/v1/items/42"));
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("5"));
    response.headers_mut().insert(
        "www-authenticate",
        HeaderValue::from_static("Bearer realm=\"buyer\""),
    );

    // These are never application metadata. The gateway must remove them even
    // when benign response fields are admitted by the mediation policy.
    response.headers_mut().insert(
        "connection",
        HeaderValue::from_static("x-wardnet-connection-secret, keep-alive"),
    );
    response.headers_mut().insert(
        "x-wardnet-connection-secret",
        HeaderValue::from_static("must-not-reflect"),
    );
    response.headers_mut().insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"proxy\""),
    );
    response
        .headers_mut()
        .insert("upgrade", HeaderValue::from_static("websocket"));
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_static("upstream-secret=1; HttpOnly"),
    );
    response
}

async fn gateway_with_loopback_upstream() -> (Router, Capture, tokio::task::JoinHandle<()>) {
    let capture = Capture::default();
    let upstream_app = Router::new()
        .route("/v1/items", any(capture_upstream))
        .with_state(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback upstream listener");
    let upstream_addr = listener.local_addr().expect("loopback upstream address");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream_app)
            .await
            .expect("loopback upstream must serve until test cleanup");
    });

    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let route = serde_json::json!({
        "id": "header-mediation-red",
        "path_prefix": "/headers",
        "upstream": format!("http://{upstream_addr}"),
        "mode": "monitor",
        "enabled": true,
        "block_threshold": null
    });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/routes")
                .header(CONTENT_TYPE, "application/json")
                .header("x-admin-token", "secret")
                .body(Body::from(route.to_string()))
                .expect("valid route registration request"),
        )
        .await
        .expect("Wardnet must answer route registration");
    assert_eq!(created.status(), StatusCode::CREATED);

    (app, capture, upstream_task)
}

fn header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().expect("test header is ASCII").to_string())
        .collect()
}

#[tokio::test]
async fn gateway_preserves_admitted_request_content_negotiation_metadata() {
    let (app, capture, upstream_task) = gateway_with_loopback_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/gateway/headers/v1/items")
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json")
                .header("x-wardnet-app-meta", "request-contract-v1")
                .header("x-wardnet-app-meta", "request-contract-v2")
                .body(Body::from(r#"{"probe":true}"#))
                .expect("valid buyer request"),
        )
        .await
        .expect("gateway must answer buyer request");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let captured = capture
        .request_headers
        .lock()
        .await
        .clone()
        .expect("loopback upstream must receive the request");
    assert_eq!(
        captured
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "Wardnet must preserve an explicitly admitted request media type"
    );
    assert_eq!(
        captured.get(ACCEPT).and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "Wardnet must preserve explicitly admitted response content negotiation"
    );
    assert_eq!(
        header_values(&captured, "x-wardnet-app-meta"),
        ["request-contract-v1", "request-contract-v2"],
        "application metadata multiplicity must remain intact"
    );

    upstream_task.abort();
}

#[tokio::test]
async fn gateway_strips_request_authority_credentials_and_hop_by_hop_fields() {
    let (app, capture, upstream_task) = gateway_with_loopback_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/gateway/headers/v1/items")
                .header(CONTENT_TYPE, "application/json")
                .header(HOST, "attacker.example")
                .header(CONTENT_LENGTH, "999")
                .header("x-admin-token", "management-secret")
                .header("authorization", "Bearer buyer-secret")
                .header("cookie", "session=buyer-secret")
                .header("x-forwarded-for", "203.0.113.77")
                .header("x-real-ip", "203.0.113.77")
                .header("proxy-authorization", "Basic cHJveHk6c2VjcmV0")
                .header("connection", "x-wardnet-connection-secret, keep-alive")
                .header("x-wardnet-connection-secret", "must-not-forward")
                .header("te", "trailers")
                .header("trailer", "x-proof")
                .header("upgrade", "websocket")
                .body(Body::from(r#"{"probe":true}"#))
                .expect("hostile buyer request fixture"),
        )
        .await
        .expect("gateway must answer hostile buyer request");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let captured = capture
        .request_headers
        .lock()
        .await
        .clone()
        .expect("loopback upstream must receive the sanitized request");
    for name in [
        "x-admin-token",
        "authorization",
        "cookie",
        "x-forwarded-for",
        "x-real-ip",
        "proxy-authorization",
        "connection",
        "x-wardnet-connection-secret",
        "te",
        "trailer",
        "upgrade",
    ] {
        assert!(
            captured.get(name).is_none(),
            "security-sensitive request field {name} crossed the gateway boundary"
        );
    }
    assert_ne!(
        captured.get(HOST).and_then(|value| value.to_str().ok()),
        Some("attacker.example"),
        "attacker-controlled Host authority must not be forwarded"
    );
    assert_ne!(
        captured
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("999"),
        "attacker-controlled framing authority must not be forwarded"
    );

    upstream_task.abort();
}

#[tokio::test]
async fn duplicate_management_credentials_fail_closed_before_proxying() {
    let (app, capture, upstream_task) = gateway_with_loopback_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/headers/v1/items")
                .header("x-admin-token", "first")
                .header("x-admin-token", "second")
                .body(Body::empty())
                .expect("duplicate sensitive header fixture"),
        )
        .await
        .expect("gateway must answer duplicate-sensitive-header request");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "ambiguous duplicated management credentials must fail closed"
    );
    assert!(
        capture.request_headers.lock().await.is_none(),
        "a fail-closed request must not reach the upstream"
    );

    upstream_task.abort();
}

#[tokio::test]
async fn gateway_preserves_admitted_upstream_representation_metadata() {
    let (app, _capture, upstream_task) = gateway_with_loopback_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/headers/v1/items")
                .body(Body::empty())
                .expect("valid buyer request"),
        )
        .await
        .expect("gateway must answer buyer request");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "Wardnet must preserve an explicitly admitted upstream representation media type"
    );
    assert_eq!(
        header_values(response.headers(), "x-wardnet-app-meta"),
        ["buyer-contract-v1", "buyer-contract-v2"],
        "bounded application metadata multiplicity must remain intact"
    );
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok()),
        Some("/v1/items/42")
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"buyer\"")
    );

    for name in [
        "connection",
        "x-wardnet-connection-secret",
        "proxy-authenticate",
        "upgrade",
        "set-cookie",
    ] {
        assert!(
            response.headers().get(name).is_none(),
            "security-sensitive upstream field {name} must not be reflected"
        );
    }

    upstream_task.abort();
}
