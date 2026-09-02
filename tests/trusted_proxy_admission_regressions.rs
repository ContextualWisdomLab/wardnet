use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, IpNet, build_app, effective_client_ip};

#[tokio::test]
async fn direct_build_app_serving_preserves_gateway_compatibility_without_trusting_headers() {
    let app = build_app(AppState::seeded(None).with_rate_limit(1, 60));

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/demo")
                .header("x-forwarded-for", "203.0.113.9")
                .header("x-real-ip", "203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/demo")
                .header("x-forwarded-for", "198.51.100.7")
                .header("x-real-ip", "198.51.100.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "without peer metadata, forwarded headers must stay untrusted and share the unknown-peer limiter bucket",
    );
}

#[test]
fn malformed_forwarded_chain_falls_back_to_direct_peer_without_x_real_ip() {
    let peer = "192.0.2.44".parse().unwrap();
    let trusted = [IpNet::parse("192.0.2.0/24").unwrap()];

    assert_eq!(
        effective_client_ip(
            Some(peer),
            Some("203.0.113.9, not-an-ip, 192.0.2.10"),
            Some("198.51.100.88"),
            &trusted,
        ),
        Some(peer),
        "one malformed X-Forwarded-For hop invalidates the chain; X-Real-IP must not become an attacker-controlled fallback",
    );
}
