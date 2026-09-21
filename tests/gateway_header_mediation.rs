//! Hostile buyer acceptance for #440: Wardnet must preserve only explicitly
//! admitted end-to-end HTTP metadata across the generic gateway boundary.
//!
//! These tests are intentionally RED against protected `main`: the current
//! proxy drops all request headers before `reqwest` and all response headers
//! before returning the upstream body. The production repair must make these
//! buyer semantics pass without turning the gateway into a transparent header
//! tunnel; security-sensitive and hop-by-hop stripping is covered by the
//! follow-on GREEN contract in #440.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode,
        header::{ACCEPT, CONTENT_TYPE},
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
    response.headers_mut().insert(
        "x-wardnet-app-meta",
        HeaderValue::from_static("buyer-contract-v1"),
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
        response
            .headers()
            .get("x-wardnet-app-meta")
            .and_then(|value| value.to_str().ok()),
        Some("buyer-contract-v1"),
        "Wardnet must preserve bounded application metadata admitted by policy"
    );

    upstream_task.abort();
}
