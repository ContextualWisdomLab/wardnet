//! Actual Axum import/readback for OpenCTI GraphQL hash arrays.
//! Synthetic documents and credentials; no upstream service or live state.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

async fn read(app: &axum::Router, path: &str) -> Value {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}

async fn import(app: &axum::Router, document: &Value, token: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/threat-intel/opencti?feed_id=graphql-hashes&source=fixture&ttl_seconds=600")
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("x-admin-token", token);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(document.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn graphql_hash_array_import_preserves_all_hashes_and_authorization() {
    // Test-owned value, not an operator credential or environment read.
    let token = format!("opencti-test-{}", std::process::id());
    let app = build_app(AppState::seeded(Some(token.clone())));
    let md5 = "AB".repeat(16);
    let sha256 = "CD".repeat(32);
    let document = json!({"data": {"stixCyberObservables": {"edges": [{"node": {
        "entity_type": "StixFile", "observable_value": "sample.exe",
        "hashes": [{"algorithm": "MD5", "hash": md5},
                   {"algorithm": "SHA-256", "hash": sha256}],
        "x_opencti_score": 80
    }}]}}});
    let before = read(&app, "/api/threats").await;
    let before_dnsbl = read(&app, "/api/dnsbl").await;
    let before_feeds = read(&app, "/api/threat-feeds").await;
    let (status, _) = import(&app, &document, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(read(&app, "/api/threats").await, before);
    assert_eq!(read(&app, "/api/threat-feeds").await, before_feeds);

    let (status, result) = import(&app, &document, Some(&token)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["upserted_threats"], 2);
    assert_eq!(result["upserted_dnsbl"], 0);
    assert_eq!(result["skipped_objects"], 0);
    let rows = read(&app, "/api/threats").await;
    let imported: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["source"] == "fixture")
        .collect();
    assert_eq!(imported.len(), 2);
    for (kind, value) in [
        ("md5", md5.to_ascii_lowercase()),
        ("sha-256", sha256.to_ascii_lowercase()),
    ] {
        let row = imported
            .iter()
            .find(|row| row["indicator_type"] == kind)
            .unwrap();
        assert_eq!(row["value"], value);
        assert_eq!(row["ttl_seconds"], 600);
        assert_eq!(row["severity"], "critical");
    }
    assert_eq!(read(&app, "/api/dnsbl").await, before_dnsbl);
    let feeds = read(&app, "/api/threat-feeds").await;
    let feed = feeds
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["feed_id"] == "graphql-hashes")
        .unwrap();
    assert_eq!(feed["threat_count"], 2);
    assert_eq!(feed["dnsbl_count"], 0);

    let malformed = json!({"entities": [{
        "entity_type": "StixFile", "observable_value": "a".repeat(32),
        "hashes": [{"algorithm": "MD5", "hash": null}]
    }]});
    let (status, _) = import(&app, &malformed, Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(read(&app, "/api/threats").await, rows);
    assert_eq!(read(&app, "/api/threat-feeds").await, feeds);
    assert_eq!(read(&app, "/api/dnsbl").await, before_dnsbl);
}
