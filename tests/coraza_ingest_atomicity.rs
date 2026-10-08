//! Coraza management import must preserve state on rejected requests.
//! All documents, credentials and persisted files belong to this offline fixture.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use waf_ids_ai_soc::{AdminPrincipal, AppConfig, AppState, build_app};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct StateFixture {
    root: PathBuf,
    path: PathBuf,
}

impl StateFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wardnet-coraza-atomicity-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("create exclusive fixture root");
        Self {
            path: root.join("state.json"),
            root,
        }
    }

    fn stored(&self) -> Value {
        serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap()
    }

    fn children(&self) -> Vec<PathBuf> {
        let mut paths: Vec<_> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        paths
    }
}

impl Drop for StateFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).expect("remove only owned fixture root");
    }
}

async fn persisted_app(path: &Path, token: &str, event_limit: usize) -> axum::Router {
    let state = AppState::load(AppConfig {
        admin_token: Some(token.to_string()),
        state_path: Some(path.to_path_buf()),
        dnsbl_origin: "dnsbl.fixture".to_string(),
        event_limit,
    })
    .await
    .unwrap();
    build_app(state)
}

async fn read(app: &axum::Router, path: &str, token: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("x-admin-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}

async fn snapshot(app: &axum::Router, token: &str) -> Value {
    json!({
        "events": read(app, "/api/events", token).await,
        "threats": read(app, "/api/threats", token).await,
        "dnsbl": read(app, "/api/dnsbl", token).await,
        "audit": read(app, "/api/audit-logs", token).await,
    })
}

async fn import(app: &axum::Router, token: Option<&str>, body: Vec<u8>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/waf/coraza/audit")
        .header("content-type", "application/x-ndjson");
    if let Some(token) = token {
        request = request.header("x-admin-token", token);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    (status, value)
}

fn hit(path: &str, interrupted: bool) -> Value {
    json!({
        "transaction": {
            "client_ip": "192.0.2.231", "is_interrupted": interrupted,
            "request": {"uri": path}, "time_stamp": "2024-06-15T12:34:56Z"
        },
        "messages": [{"message": "synthetic atomicity record", "data": {"severity": 3}}]
    })
}

#[tokio::test]
async fn batch_result_reports_only_retained_event_ids_after_reload() {
    let fixture = StateFixture::new();
    let token = format!("coraza-retention-fixture-{}", std::process::id());
    let app = persisted_app(&fixture.path, &token, 2).await;
    let before = snapshot(&app, &token).await;
    let batch = json!([
        hit("/retention-one", false),
        hit("/retention-two", false),
        hit("/retention-three", false)
    ]);
    let (status, result) = import(&app, Some(&token), batch.to_string().into_bytes()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["accepted_hits"], 3);
    assert_eq!(result["skipped"], 0);
    assert_eq!(result["event_ids"], json!([2, 3]));
    assert_eq!(result["enforcement_hints"], 0);
    let committed = snapshot(&app, &token).await;
    assert_eq!(committed["dnsbl"], before["dnsbl"]);
    assert_eq!(committed["threats"], before["threats"]);
    let events = committed["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["id"], 2);
    assert_eq!(events[0]["path"], "/retention-two");
    assert_eq!(events[1]["id"], 3);
    assert_eq!(events[1]["path"], "/retention-three");
    for event in events {
        assert_eq!(event["action"], "monitor");
        assert_eq!(event["score"], 25);
        assert_eq!(event["timestamp_unix"], 1_718_454_896_u64);
    }
    let audit = committed["audit"].as_array().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["id"], 1);
    assert_eq!(audit[0]["action"], "import_coraza_audit");
    assert_eq!(audit[0]["resource"], "waf_coraza");
    assert_eq!(audit[0]["resource_id"], "3_hits");
    assert_eq!(audit[0]["outcome"], "success");
    let persisted = fixture.stored();
    assert_eq!(persisted["events"], committed["events"]);
    assert_eq!(persisted["audit_logs"], committed["audit"]);
    assert_eq!(persisted["next_event_id"], 4);
    assert_eq!(persisted["next_audit_log_id"], 2);
    assert_eq!(fixture.children(), vec![fixture.path.clone()]);
    drop(app);
    let reloaded = persisted_app(&fixture.path, &token, 2).await;
    assert_eq!(snapshot(&reloaded, &token).await, committed);
    assert_eq!(fixture.stored(), persisted);
    let (status, next) = import(
        &reloaded,
        Some(&token),
        hit("/retention-four", false).to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(next["event_ids"], json!([4]));
    assert_eq!(fixture.stored()["next_event_id"], 5);
    assert_eq!(fixture.stored()["next_audit_log_id"], 3);
}

#[tokio::test]
async fn persistence_failure_rolls_back_coraza_batch_before_retry() {
    let fixture = StateFixture::new();
    let token = format!("coraza-rollback-fixture-{}", std::process::id());
    let app = persisted_app(&fixture.path, &token, 10).await;
    let before = snapshot(&app, &token).await;
    let baseline = std::fs::read(&fixture.path).unwrap();
    // Replace only the owned destination after startup so atomic rename fails.
    std::fs::remove_file(&fixture.path).unwrap();
    std::fs::create_dir(&fixture.path).unwrap();
    let batch = json!([hit("/rollback-one", true), hit("/rollback-two", true)]);
    let (status, response) = import(&app, Some(&token), batch.to_string().into_bytes()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("failed to replace state file")
    );
    assert_eq!(snapshot(&app, &token).await, before);
    assert!(fixture.path.is_dir());
    assert_eq!(fixture.children(), vec![fixture.path.clone()]);
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 0);

    // Recovery is fixture-only: restore its baseline file, then use the same app.
    // The subsequent IDs verify in-memory counters, not just unchanged disk.
    std::fs::remove_dir(&fixture.path).unwrap();
    std::fs::write(&fixture.path, baseline).unwrap();
    let (status, result) = import(&app, Some(&token), batch.to_string().into_bytes()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(result["accepted_hits"], 2);
    assert_eq!(result["event_ids"], json!([1, 2]));
    assert_eq!(result["enforcement_hints"], 6);
    let committed = snapshot(&app, &token).await;
    let persisted = fixture.stored();
    assert_eq!(persisted["events"], committed["events"]);
    assert_eq!(persisted["threats"], committed["threats"]);
    assert_eq!(persisted["dnsbl"], committed["dnsbl"]);
    assert_eq!(persisted["audit_logs"], committed["audit"]);
    assert_eq!(persisted["next_event_id"], 3);
    assert_eq!(persisted["next_audit_log_id"], 2);
    assert_eq!(persisted["audit_logs"].as_array().unwrap().len(), 1);
    assert_eq!(persisted["audit_logs"][0]["id"], 1);
    assert_eq!(persisted["audit_logs"][0]["action"], "import_coraza_audit");
    assert_eq!(persisted["audit_logs"][0]["outcome"], "success");
    assert_eq!(fixture.children(), vec![fixture.path.clone()]);
    drop(app);
    let reloaded = persisted_app(&fixture.path, &token, 10).await;
    assert_eq!(snapshot(&reloaded, &token).await, committed);
    assert_eq!(fixture.stored(), persisted);
}

#[tokio::test]
async fn invalid_coraza_bodies_do_not_commit_a_partial_batch() {
    let malformed_batch = format!("{}\n{{", hit("/partial-batch", true));
    for (body, diagnostic) in [
        (vec![0xff], "Coraza audit body must be UTF-8 text"),
        (b"  \n".to_vec(), "empty Coraza audit body"),
        (b"{}".to_vec(), "no Coraza WAF hits found"),
        (b"[]".to_vec(), "no Coraza WAF hits found"),
        (
            malformed_batch.into_bytes(),
            "invalid Coraza audit JSON on line 2",
        ),
    ] {
        let fixture = StateFixture::new();
        let token = format!("coraza-invalid-fixture-{}", std::process::id());
        let app = persisted_app(&fixture.path, &token, 10).await;
        let before = snapshot(&app, &token).await;
        let stored = std::fs::read(&fixture.path).unwrap();
        let (status, response) = import(&app, Some(&token), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(response["error"].as_str().unwrap().contains(diagnostic));
        assert_eq!(snapshot(&app, &token).await, before);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), stored);
        assert_eq!(fixture.children(), vec![fixture.path.clone()]);
        // A successful import after rejection proves neither ID counter advanced.
        let (status, result) = import(
            &app,
            Some(&token),
            hit("/after-rejection", true).to_string().into_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(result["event_ids"], json!([1]));
        assert_eq!(result["enforcement_hints"], 3);
        let persisted = fixture.stored();
        assert_eq!(persisted["next_event_id"], 2);
        assert_eq!(persisted["next_audit_log_id"], 2);
        assert_eq!(persisted["audit_logs"][0]["id"], 1);
    }
}

#[tokio::test]
async fn write_authorization_precedes_coraza_body_validation() {
    let fixture = StateFixture::new();
    let writer = format!("coraza-write-fixture-{}", std::process::id());
    let reader = format!("coraza-read-fixture-{}", std::process::id());
    let state = AppState::load(AppConfig {
        admin_token: None,
        state_path: Some(fixture.path.clone()),
        dnsbl_origin: "dnsbl.fixture".to_string(),
        event_limit: 10,
    })
    .await
    .unwrap()
    .with_admin_tokens(HashMap::from([
        (
            writer.clone(),
            AdminPrincipal {
                actor: "fixture-writer".into(),
                can_write: true,
            },
        ),
        (
            reader.clone(),
            AdminPrincipal {
                actor: "fixture-reader".into(),
                can_write: false,
            },
        ),
    ]));
    let app = build_app(state);
    let before = snapshot(&app, &writer).await;
    let stored = std::fs::read(&fixture.path).unwrap();
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("unknown-fixture-principal"), StatusCode::UNAUTHORIZED),
        (Some(reader.as_str()), StatusCode::FORBIDDEN),
    ] {
        let (status, response) = import(&app, token, vec![0xff]).await;
        assert_eq!(status, expected);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("X-Admin-Token")
        );
        let text = response.to_string();
        assert!(!text.contains(&writer) && !text.contains(&reader));
        assert_eq!(snapshot(&app, &writer).await, before);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), stored);
    }
    let (status, response) = import(
        &app,
        Some(&writer),
        hit("/auth-positive", false).to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(response["event_ids"], json!([1]));
    let persisted = fixture.stored();
    assert_eq!(persisted["next_event_id"], 2);
    assert_eq!(persisted["next_audit_log_id"], 2);
    assert_eq!(persisted["audit_logs"][0]["actor"], "fixture-writer");
}
