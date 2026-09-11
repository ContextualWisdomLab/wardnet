use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    routing::get,
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

#[tokio::test]
async fn request_controlled_phishing_database_url_cannot_reach_loopback() {
    let fetch_count = Arc::new(AtomicUsize::new(0));
    let route_count = Arc::clone(&fetch_count);
    let feed_mock = Router::new().route(
        "/domains",
        get(move || {
            let route_count = Arc::clone(&route_count);
            async move {
                route_count.fetch_add(1, Ordering::SeqCst);
                (StatusCode::OK, "evil.example\n")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, feed_mock).into_future());

    let payload = serde_json::json!({
        "feed_id": "phishing-db-ssrf-red",
        "source": "https://github.com/Phishing-Database/Phishing.Database",
        "domain_url": format!("http://{addr}/domains"),
        "ip_url": format!("http://{addr}/unused"),
        "ttl_seconds": 900,
        "domain_limit": 10,
        "ip_limit": 10,
        "severity": "critical",
        "import_domains": true,
        "import_ips": false,
        "allow_non_default_hosts": true
    });

    let response = build_app(AppState::seeded(Some("secret".to_string())))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/threat-feeds/import/phishing-database")
                .header(CONTENT_TYPE, "application/json")
                .header("x-admin-token", "secret")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "operator input must not be able to authorize a request-selected phishing feed URL"
    );
    assert_eq!(
        fetch_count.load(Ordering::SeqCst),
        0,
        "the request-selected loopback URL must never be fetched"
    );
}
