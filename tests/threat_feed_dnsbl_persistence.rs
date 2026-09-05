use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppConfig, AppState, DnsblEntry, build_app};

fn json_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-admin-token", "secret")
        .body(Body::from(body.to_string()))
        .unwrap()
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

fn unique_state_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-{test_name}-{}-{nonce}.json",
        std::process::id()
    ))
}

fn file_config(path: &Path) -> AppConfig {
    AppConfig {
        admin_token: Some("secret".to_string()),
        state_path: Some(path.to_path_buf()),
        dnsbl_origin: AppConfig::DEFAULT_DNSBL_ORIGIN.to_string(),
        event_limit: AppConfig::DEFAULT_EVENT_LIMIT,
    }
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

async fn import_feed(
    app: &axum::Router,
    feed_id: &str,
    source: &str,
    addresses: &[&str],
) -> StatusCode {
    app.clone()
        .oneshot(json_request(
            Method::POST,
            "/api/threat-feeds/import",
            feed_payload(feed_id, source, addresses),
        ))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn dnsbl_feed_ownership_survives_restart_before_withdrawal() {
    let path = unique_state_path("dnsbl-ownership-restart");
    let config = file_config(&path);
    let target = "203.0.113.220";

    let app = build_app(AppState::load(config.clone()).await.unwrap());
    assert_eq!(
        import_feed(&app, "feed-a", "feed:a", &[target]).await,
        StatusCode::CREATED
    );
    drop(app);

    let app = build_app(AppState::load(config).await.unwrap());
    assert_eq!(
        import_feed(&app, "feed-a", "feed:a", &["203.0.113.250"]).await,
        StatusCode::CREATED
    );
    assert!(
        !dnsbl(&app)
            .await
            .iter()
            .any(|entry| entry.address.to_string() == target),
        "persisted feed ownership must still reap a withdrawn DNSBL address after restart"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn predecessor_state_without_dnsbl_ownership_fields_remains_loadable() {
    let path = unique_state_path("dnsbl-ownership-legacy-state");
    let config = file_config(&path);

    let state = AppState::load(config.clone()).await.unwrap();
    drop(state);

    let mut legacy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = legacy.as_object_mut().expect("seeded state is an object");
    // These keys are intentionally absent in the predecessor schema. The GREEN
    // implementation must add them with serde defaults rather than requiring a
    // one-shot migration that makes an existing Wardnet state file unreadable.
    object.remove("operator_dnsbl_addresses");
    object.insert(
        "threat_feed_ownership".to_string(),
        json!([{"feed_id": "legacy-feed", "threat_keys": []}]),
    );
    std::fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

    AppState::load(config)
        .await
        .expect("pre-DNSBL-ownership state must deserialize with empty ownership defaults");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn failed_persistence_rolls_back_dnsbl_ownership_before_retry() {
    let path = unique_state_path("dnsbl-ownership-rollback");
    let backup = path.with_extension("backup.json");
    let config = file_config(&path);
    let target = "203.0.113.221";
    let app = build_app(AppState::load(config).await.unwrap());

    assert_eq!(
        import_feed(&app, "feed-a", "feed:a", &[target]).await,
        StatusCode::CREATED
    );

    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        import_feed(&app, "feed-a", "feed:a", &["203.0.113.250"]).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "replacing a state file with a directory must make persistence fail"
    );
    assert!(
        dnsbl(&app)
            .await
            .iter()
            .any(|entry| entry.address.to_string() == target),
        "failed persistence must restore the complete pre-mutation DNSBL snapshot"
    );

    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert_eq!(
        import_feed(&app, "feed-a", "feed:a", &["203.0.113.250"]).await,
        StatusCode::CREATED
    );
    assert!(
        !dnsbl(&app)
            .await
            .iter()
            .any(|entry| entry.address.to_string() == target),
        "retry after rollback must see the original ownership and reap the withdrawn address"
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(backup);
}
