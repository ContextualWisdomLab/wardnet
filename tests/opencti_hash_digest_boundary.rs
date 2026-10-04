//! Synthetic export documents exercise actual management, storage and gateway code.
//! No live OpenCTI service, operator credentials or file malware scanning.
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppConfig, AppState, build_app};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct StateFixture {
    root: PathBuf,
    path: PathBuf,
}
impl StateFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wardnet-opencti-digest-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("create exclusive owned fixture");
        Self {
            path: root.join("state.json"),
            root,
        }
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap()
    }
}
impl Drop for StateFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).expect("remove only owned fixture");
    }
}

async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    document: Option<&Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("x-admin-token", token);
    }
    let body = match document {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    (status, body)
}

async fn read(app: &axum::Router, path: &str, token: &str) -> Value {
    let (status, body) = request(app, "GET", path, Some(token), None).await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn app(fixture: &StateFixture, token: &str) -> axum::Router {
    build_app(
        AppState::load(AppConfig {
            admin_token: Some(token.to_string()),
            state_path: Some(fixture.path.clone()),
            dnsbl_origin: "dnsbl.fixture".to_string(),
            event_limit: 100,
        })
        .await
        .unwrap(),
    )
}

async fn block_app(fixture: &StateFixture, token: &str) -> axum::Router {
    let app = app(fixture, token).await;
    let route = json!({"id": "digest", "path_prefix": "/digest", "upstream": "mock://digest", "mode": "block", "enabled": true});
    let (status, _) = request(&app, "POST", "/api/routes", Some(token), Some(&route)).await;
    assert_eq!(status, StatusCode::CREATED);
    let routes = read(&app, "/api/routes", token).await;
    let route = routes
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "digest")
        .unwrap();
    assert_eq!(route["mode"], "block");
    app
}

async fn snapshot(app: &axum::Router, token: &str) -> Value {
    json!({"threats": read(app, "/api/threats", token).await,
        "dnsbl": read(app, "/api/dnsbl", token).await,
        "feeds": read(app, "/api/threat-feeds", token).await,
        "audit": read(app, "/api/audit-logs", token).await,
        "events": read(app, "/api/events", token).await})
}

async fn import(app: &axum::Router, document: &Value, token: Option<&str>) -> (StatusCode, Value) {
    request(
        app,
        "POST",
        "/api/threat-intel/opencti?feed_id=digest-boundary&source=fixture:digest&ttl_seconds=600",
        token,
        Some(document),
    )
    .await
}

async fn allowed_status(app: &axum::Router) {
    let (status, body) = request(app, "GET", "/gateway/digest/status", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["score"], 0);
}

#[tokio::test]
async fn invalid_direct_md5_is_rejected_without_mutating_persisted_enforcement() {
    let fixture = StateFixture::new();
    let token = format!("opencti-digest-fixture-{}", std::process::id());
    let app = block_app(&fixture, &token).await;
    allowed_status(&app).await;
    let before = snapshot(&app, &token).await;
    let bytes = fixture.bytes();
    let document = json!({"entities": [{"entity_type": "MD5", "observable_value": "status", "x_opencti_score": 80}]});
    let (status, _) = import(&app, &document, Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "known MD5 must reject an arbitrary keyword"
    );
    assert_eq!(snapshot(&app, &token).await, before);
    assert_eq!(fixture.bytes(), bytes);
    allowed_status(&app).await;
    let reloaded = app_after_reload(&fixture, &token).await;
    assert_eq!(
        read(&reloaded, "/api/threats", &token).await,
        before["threats"]
    );
    assert_eq!(
        read(&reloaded, "/api/threat-feeds", &token).await,
        before["feeds"]
    );
    allowed_status(&reloaded).await;
}

#[tokio::test]
async fn explicit_file_hashes_reject_invalid_known_digests_without_display_fallback() {
    for hashes in [
        json!([{"algorithm": "MD5", "hash": "status"}]),
        json!({"MD5": "status"}),
    ] {
        let fixture = StateFixture::new();
        let token = format!("opencti-digest-fixture-{}", std::process::id());
        let app = block_app(&fixture, &token).await;
        allowed_status(&app).await;
        let before = snapshot(&app, &token).await;
        let bytes = fixture.bytes();
        let document = json!({"data": {"stixCyberObservables": {"edges": [{"node": {
            "entity_type": "StixFile", "observable_value": "a".repeat(32),
            "hashes": hashes, "x_opencti_score": 80
        }}]}}});
        let (status, _) = import(&app, &document, Some(&token)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "explicit invalid digest must not use display hash"
        );
        assert_eq!(snapshot(&app, &token).await, before);
        assert_eq!(fixture.bytes(), bytes);
        allowed_status(&app).await;
    }
}

fn hash_document(kind: &str, algorithm: &str, value: &str) -> Value {
    match kind {
        "direct" => {
            json!({"entity_type": algorithm, "observable_value": value, "x_opencti_score": 80})
        }
        "array" => json!({"entity_type": "StixFile", "observable_value": "a".repeat(32),
            "hashes": [{"algorithm": algorithm, "hash": value}], "x_opencti_score": 80}),
        "map" => json!({"entity_type": "Artifact", "observable_value": "a".repeat(32),
            "hashes": {algorithm: value}, "x_opencti_score": 80}),
        _ => panic!("unsupported fixture shape"),
    }
}

#[tokio::test]
async fn known_digest_length_and_ascii_hex_boundaries_apply_to_every_mapping() {
    let fixture = StateFixture::new();
    let token = format!("opencti-digest-fixture-{}", std::process::id());
    let app = block_app(&fixture, &token).await;
    for kind in ["direct", "array", "map"] {
        for (algorithm, length) in [("MD5", 32), ("SHA1", 40), ("SHA256", 64), ("SHA512", 128)] {
            let valid = "AB".repeat(length / 2);
            let (status, result) = import(
                &app,
                &hash_document(kind, algorithm, &format!(" {valid} ")),
                Some(&token),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{kind}/{algorithm}");
            assert_eq!(result["upserted_threats"], 1);
            let threats = read(&app, "/api/threats", &token).await;
            let row = threats
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["source"] == "fixture:digest")
                .unwrap();
            assert_eq!(row["value"], valid.to_ascii_lowercase());
            assert_eq!(row["indicator_type"], algorithm.to_ascii_lowercase());
            let before = snapshot(&app, &token).await;
            let bytes = fixture.bytes();
            for invalid in [
                "a".repeat(length - 1),
                "a".repeat(length + 1),
                "g".repeat(length),
                "é".repeat(length / 2),
                format!("{} {}", "a".repeat(length / 2), "a".repeat(length / 2 - 1)),
            ] {
                let (status, _) = import(
                    &app,
                    &hash_document(kind, algorithm, &invalid),
                    Some(&token),
                )
                .await;
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "{kind}/{algorithm} invalid digest admitted"
                );
                assert_eq!(snapshot(&app, &token).await, before);
                assert_eq!(fixture.bytes(), bytes);
            }
        }
    }
}

#[tokio::test]
async fn hyphenated_algorithms_retain_spelling_and_unknown_algorithms_remain_compatible() {
    let fixture = StateFixture::new();
    let token = format!("opencti-digest-fixture-{}", std::process::id());
    let app = app(&fixture, &token).await;
    for kind in ["array", "map"] {
        for (algorithm, length) in [("SHA-1", 40), ("SHA-256", 64), ("SHA-512", 128)] {
            let valid = "CD".repeat(length / 2);
            let (status, _) =
                import(&app, &hash_document(kind, algorithm, &valid), Some(&token)).await;
            assert_eq!(status, StatusCode::CREATED);
            let before = snapshot(&app, &token).await;
            let bytes = fixture.bytes();
            let threats = before["threats"].as_array().unwrap();
            let row = threats
                .iter()
                .find(|r| r["source"] == "fixture:digest")
                .unwrap();
            assert_eq!(row["indicator_type"], algorithm.to_ascii_lowercase());
            assert_eq!(row["value"], valid.to_ascii_lowercase());
            let (status, _) = import(
                &app,
                &hash_document(kind, algorithm, "status"),
                Some(&token),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(snapshot(&app, &token).await, before);
            assert_eq!(fixture.bytes(), bytes);
        }
        let (status, _) = import(
            &app,
            &hash_document(kind, "SSDEEP", "3:AB:CD"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let threats = read(&app, "/api/threats", &token).await;
        let row = threats
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["source"] == "fixture:digest")
            .unwrap();
        assert_eq!(row["indicator_type"], "ssdeep");
        assert_eq!(row["value"], "3:ab:cd");
    }
}

#[tokio::test]
async fn mixed_hash_rows_keep_valid_evidence_and_authorization_precedes_validation() {
    let fixture = StateFixture::new();
    let token = format!("opencti-digest-fixture-{}", std::process::id());
    let app = app(&fixture, &token).await;
    let valid = "AB".repeat(32);
    for hashes in [
        json!([{"algorithm": "MD5", "hash": "status"}, {"algorithm": "SHA-256", "hash": valid}]),
        json!({"MD5": "status", "SHA-256": valid}),
    ] {
        let document = json!({"entities": [
            {"entity_type": "MD5", "observable_value": "status"},
            {"entity_type": "StixFile", "observable_value": "file.bin", "hashes": hashes, "x_opencti_score": 80}]});
        let before = snapshot(&app, &token).await;
        let bytes = fixture.bytes();
        let (status, _) = import(&app, &document, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(snapshot(&app, &token).await, before);
        assert_eq!(fixture.bytes(), bytes);
        let (status, result) = import(&app, &document, Some(&token)).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(result["upserted_threats"], 1);
        assert_eq!(result["upserted_dnsbl"], 0);
        assert_eq!(result["skipped_objects"], 1);
        let after = snapshot(&app, &token).await;
        assert_eq!(after["dnsbl"], before["dnsbl"]);
        let rows: Vec<_> = after["threats"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["source"] == "fixture:digest")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["indicator_type"], "sha-256");
        assert_eq!(rows[0]["value"], valid.to_ascii_lowercase());
        let reload = app_after_reload(&fixture, &token).await;
        assert_eq!(
            read(&reload, "/api/threats", &token).await,
            after["threats"]
        );
    }
}

async fn app_after_reload(fixture: &StateFixture, token: &str) -> axum::Router {
    app(fixture, token).await
}

#[tokio::test]
async fn valid_direct_md5_preserves_digest_metadata_and_reload() {
    let fixture = StateFixture::new();
    let token = format!("opencti-digest-fixture-{}", std::process::id());
    let app = block_app(&fixture, &token).await;
    let value = "AB".repeat(16);
    let document = json!({"entities": [{"entity_type": "MD5", "observable_value": value, "x_opencti_score": 80}]});
    let (status, result) = import(&app, &document, Some(&token)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["upserted_threats"], 1);
    assert_eq!(result["upserted_dnsbl"], 0);
    let threats = read(&app, "/api/threats", &token).await;
    let rows: Vec<_> = threats
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["source"] == "fixture:digest")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["value"], value.to_ascii_lowercase());
    assert_eq!(rows[0]["indicator_type"], "md5");
    assert_eq!(rows[0]["severity"], "critical");
    assert_eq!(rows[0]["ttl_seconds"], 600);
    let reloaded = app_after_reload(&fixture, &token).await;
    assert_eq!(read(&reloaded, "/api/threats", &token).await, threats);
    allowed_status(&reloaded).await;
}
