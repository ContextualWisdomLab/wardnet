//! Hostile response-singleton acceptance for #440.
//!
//! `Location` and `Retry-After` are single-valued response fields under RFC 9110.
//! A gateway must not relay ambiguous duplicate values as an otherwise successful
//! upstream response. This child remains test-only; #441 owns the production
//! mediation repair.

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::any,
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

async fn duplicate_location_response() -> Response {
    let mut response = (StatusCode::FOUND, "ambiguous location").into_response();
    response
        .headers_mut()
        .append("location", HeaderValue::from_static("/v1/items/first"));
    response
        .headers_mut()
        .append("location", HeaderValue::from_static("/v1/items/second"));
    response
}

async fn duplicate_retry_after_response() -> Response {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "ambiguous retry").into_response();
    response
        .headers_mut()
        .append("retry-after", HeaderValue::from_static("5"));
    response
        .headers_mut()
        .append("retry-after", HeaderValue::from_static("120"));
    response
}

async fn gateway_with_hostile_upstream() -> (Router, tokio::task::JoinHandle<()>) {
    let upstream_app = Router::new()
        .route("/v1/duplicate-location", any(duplicate_location_response))
        .route(
            "/v1/duplicate-retry-after",
            any(duplicate_retry_after_response),
        );
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
        "id": "response-singleton-red",
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

    (app, upstream_task)
}

#[tokio::test]
async fn duplicate_upstream_location_fails_closed() {
    let (app, upstream_task) = gateway_with_hostile_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/headers/v1/duplicate-location")
                .body(Body::empty())
                .expect("duplicate Location fixture"),
        )
        .await
        .expect("gateway must answer hostile upstream response");

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "multiple Location values are an ambiguous upstream response and must fail closed"
    );
    assert!(
        response.headers().get("location").is_none(),
        "ambiguous Location authority must not be relayed"
    );

    upstream_task.abort();
}

#[tokio::test]
async fn duplicate_upstream_retry_after_fails_closed() {
    let (app, upstream_task) = gateway_with_hostile_upstream().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/headers/v1/duplicate-retry-after")
                .body(Body::empty())
                .expect("duplicate Retry-After fixture"),
        )
        .await
        .expect("gateway must answer hostile upstream response");

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "multiple Retry-After values are ambiguous and must fail closed"
    );
    assert!(
        response.headers().get("retry-after").is_none(),
        "ambiguous Retry-After metadata must not be relayed"
    );

    upstream_task.abort();
}
