//! Hostile buyer acceptance for #447: end-to-end representation codings must
//! remain coupled to the byte-identical representation crossing Wardnet's
//! generic gateway boundary.
//!
//! This lane is intentionally test-only. Production mediation remains owned by
//! #441; once that parent settles, this child must adopt the complete parent
//! non-force before any production repair is authorized.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::any,
};
use tokio::sync::Mutex;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

const REQUEST_GZIP_JSON: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xab, 0x56, 0x2a, 0x28, 0xca, 0x4f,
    0x4a, 0x55, 0xb2, 0x2a, 0x29, 0x2a, 0x4d, 0xad, 0x05, 0x00, 0xa9, 0x27, 0x1b, 0xbb, 0x0e, 0x00,
    0x00, 0x00,
];
const RESPONSE_GZIP_JSON: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xab, 0x56, 0xca, 0xcf, 0x56, 0xb2,
    0x2a, 0x29, 0x2a, 0x4d, 0xad, 0x05, 0x00, 0x90, 0x5f, 0xd4, 0xa7, 0x0b, 0x00, 0x00, 0x00,
];

#[derive(Clone, Default)]
struct Capture {
    request_headers: Arc<Mutex<Option<HeaderMap>>>,
    request_body: Arc<Mutex<Option<Bytes>>>,
}

async fn coded_upstream(
    State(capture): State<Capture>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    *capture.request_headers.lock().await = Some(headers);
    *capture.request_body.lock().await = Some(body);

    let mut response = (StatusCode::OK, Body::from(RESPONSE_GZIP_JSON)).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert("content-encoding", HeaderValue::from_static("gzip"));
    response
        .headers_mut()
        .insert("connection", HeaderValue::from_static("x-hop-secret"));
    response
        .headers_mut()
        .insert("x-hop-secret", HeaderValue::from_static("must-not-reflect"));
    response
}

async fn gateway_with_coded_upstream() -> (Router, Capture, tokio::task::JoinHandle<()>) {
    let capture = Capture::default();
    let upstream = Router::new()
        .route("/v1/coded", any(coded_upstream))
        .with_state(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback upstream listener");
    let upstream_addr = listener.local_addr().expect("loopback upstream address");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("loopback upstream must serve until test cleanup");
    });

    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let route = serde_json::json!({
        "id": "content-encoding-red",
        "path_prefix": "/coded",
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
async fn request_preserves_content_encoding_with_byte_identical_representation() {
    let (app, capture, upstream_task) = gateway_with_coded_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/gateway/coded/v1/coded")
                .header(CONTENT_TYPE, "application/json")
                .header("content-encoding", "gzip")
                .header("connection", "x-hop-secret")
                .header("x-hop-secret", "must-not-forward")
                .body(Body::from(REQUEST_GZIP_JSON))
                .expect("coded buyer request"),
        )
        .await
        .expect("gateway must answer coded buyer request");
    assert_eq!(response.status(), StatusCode::OK);

    let headers = capture
        .request_headers
        .lock()
        .await
        .clone()
        .expect("loopback upstream must receive request");
    assert_eq!(
        headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip"),
        "coded representation bytes must not cross without their Content-Encoding metadata"
    );
    assert!(headers.get("connection").is_none());
    assert!(headers.get("x-hop-secret").is_none());

    let body = capture
        .request_body
        .lock()
        .await
        .clone()
        .expect("loopback upstream must receive request body");
    assert_eq!(body.as_ref(), REQUEST_GZIP_JSON);

    upstream_task.abort();
}

#[tokio::test]
async fn response_preserves_content_encoding_with_byte_identical_representation() {
    let (app, _capture, upstream_task) = gateway_with_coded_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/coded/v1/coded")
                .body(Body::empty())
                .expect("coded response buyer request"),
        )
        .await
        .expect("gateway must answer coded response buyer request");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip"),
        "coded response bytes must not cross without their Content-Encoding metadata"
    );
    assert!(response.headers().get("connection").is_none());
    assert!(response.headers().get("x-hop-secret").is_none());

    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("coded response body must remain readable");
    assert_eq!(body.as_ref(), RESPONSE_GZIP_JSON);

    upstream_task.abort();
}
