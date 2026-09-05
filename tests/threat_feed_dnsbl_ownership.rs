use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, DnsblEntry, build_app};

fn json_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-admin-token", "secret")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn dnsbl(app: &axum::Router) -> Vec<DnsblEntry> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/dnsbl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn feed_payload(feed_id: &str, source: &str, addresses: &[&str]) -> serde_json::Value {
    json!({
        "feed_id": feed_id,
        "source": source,
        "ttl_seconds": 3600,
        "threats": [],
        "dnsbl": addresses.iter().map(|address| json!({
            "address": address,
            "code": "127.0.0.2",
            "reason": format!("{feed_id} verdict"),
            "source": source,
            "ttl_seconds": 3600,
            "prefix_len": null
        })).collect::<Vec<_>>()
    })
}

#[tokio::test]
async fn feed_refresh_reaps_dnsbl_entries_it_withdraws() {
    let app = build_app(AppState::seeded(Some("secret".to_string())));

    let first = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload("feed-a", "feed:a", &["203.0.113.210"]),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert!(dnsbl(&app).iter().any(|entry| entry.address.to_string() == "203.0.113.210"));

    let refresh = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload("feed-a", "feed:a", &["203.0.113.250"]),
        ))
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::CREATED);

    assert!(
        !dnsbl(&app)
            .iter()
            .any(|entry| entry.address.to_string() == "203.0.113.210"),
        "withdrawn feed DNSBL material must not keep blocking after refresh"
    );
}

#[tokio::test]
async fn feed_refresh_preserves_dnsbl_still_owned_by_another_feed() {
    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let address = "203.0.113.211";

    for (feed_id, source) in [("feed-a", "feed:a"), ("feed-b", "feed:b")] {
        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/api/threat-feeds/import",
                feed_payload(feed_id, source, &[address]),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let refresh = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload("feed-a", "feed:a", &["203.0.113.250"]),
        ))
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::CREATED);

    assert!(
        dnsbl(&app)
            .iter()
            .any(|entry| entry.address.to_string() == address),
        "one feed cannot delete a DNSBL address still claimed by another feed"
    );
}

#[tokio::test]
async fn feed_refresh_preserves_operator_managed_dnsbl_payload() {
    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let address = "203.0.113.212";

    let feed = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload("feed-a", "feed:a", &[address]),
        ))
        .await
        .unwrap();
    assert_eq!(feed.status(), StatusCode::CREATED);

    let operator = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/dnsbl",
            json!({
                "address": address,
                "code": "127.0.0.77",
                "reason": "operator-reviewed exception payload",
                "source": "operator",
                "ttl_seconds": 86400,
                "prefix_len": null
            }),
        ))
        .await
        .unwrap();
    assert_eq!(operator.status(), StatusCode::CREATED);

    let refresh = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload("feed-a", "feed:a", &["203.0.113.250"]),
        ))
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::CREATED);

    let entries = dnsbl(&app);
    let entry = entries
        .iter()
        .find(|entry| entry.address.to_string() == address)
        .expect("operator-owned DNSBL entry must survive feed withdrawal");
    assert_eq!(entry.code, "127.0.0.77");
    assert_eq!(entry.reason, "operator-reviewed exception payload");
    assert_eq!(entry.source, "operator");
    assert_eq!(entry.ttl_seconds, 86400);
}

#[tokio::test]
async fn feed_import_does_not_overwrite_operator_dnsbl_or_count_a_skipped_write() {
    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let address = "203.0.113.213";

    let operator = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/dnsbl",
            json!({
                "address": address,
                "code": "127.0.0.88",
                "reason": "operator-owned payload",
                "source": "operator",
                "ttl_seconds": 86400,
                "prefix_len": null
            }),
        ))
        .await
        .unwrap();
    assert_eq!(operator.status(), StatusCode::CREATED);

    let imported = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload("feed-a", "feed:a", &[address]),
        ))
        .await
        .unwrap();
    assert_eq!(imported.status(), StatusCode::CREATED);
    let bytes = to_bytes(imported.into_body(), usize::MAX).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["upserted_dnsbl"], 0);

    let entries = dnsbl(&app);
    let entry = entries
        .iter()
        .find(|entry| entry.address.to_string() == address)
        .expect("operator-owned DNSBL entry must remain present");
    assert_eq!(entry.code, "127.0.0.88");
    assert_eq!(entry.reason, "operator-owned payload");
    assert_eq!(entry.source, "operator");
    assert_eq!(entry.ttl_seconds, 86400);
}
