//! STIX `revoked` lifecycle boundary through actual management, persistence and gateway.
//! OASIS STIX 2.1 (10 June 2021) section 3.2 common property `revoked`: "Revoked objects are
//! no longer considered valid by the object creator." The specification leaves handling to
//! implementations; Wardnet does not admit revoked indicators as enforcement evidence.
//! Synthetic documents/credentials only; no TAXII server or deployed incident.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppConfig, AppState, build_app};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wardnet-stix-revoked-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state.json")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
async fn app(fixture: &Fixture) -> axum::Router {
    build_app(
        AppState::load(AppConfig {
            admin_token: Some("synthetic-revoked-token".into()),
            state_path: Some(fixture.state()),
            dnsbl_origin: "dnsbl.fixture".into(),
            event_limit: 100,
        })
        .await
        .unwrap(),
    )
}
async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: bool,
    client: Option<&str>,
    value: Option<&Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if token {
        builder = builder.header("x-admin-token", "synthetic-revoked-token");
    }
    if let Some(ip) = client {
        builder = builder.header("x-forwarded-for", ip);
    }
    let body = match value {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap(),
    )
}
async fn snapshot(app: &axum::Router) -> Value {
    let mut out = serde_json::Map::new();
    for path in [
        "/api/threats",
        "/api/dnsbl",
        "/api/threat-feeds",
        "/api/audit-logs",
        "/api/events",
    ] {
        let (status, body) = request(app, "GET", path, true, None, None).await;
        assert_eq!(status, StatusCode::OK);
        out.insert(path.into(), body);
    }
    Value::Object(out)
}
fn indicator(shape: &str, ip: &str, revoked: Option<Value>) -> Value {
    let pattern = format!("[ipv4-addr:value = '{ip}']");
    let mut object = if shape == "entities" {
        json!({"entity_type": "Indicator", "standard_id": format!("indicator--{ip}"), "pattern_type": "stix", "pattern": pattern, "confidence": 80})
    } else {
        json!({"type": "indicator", "id": format!("indicator--{ip}"), "pattern_type": "stix", "pattern": pattern, "confidence": 80})
    };
    if let Some(flag) = revoked {
        object["revoked"] = flag;
    }
    object
}
fn document(shape: &str, objects: Vec<Value>) -> Value {
    match shape {
        "stix" => json!({"type": "bundle", "id": "bundle--revoked-fixture", "objects": objects}),
        "opencti" => Value::Array(objects),
        "entities" => json!({"entities": objects}),
        _ => panic!("unknown fixture shape"),
    }
}
fn path(shape: &str) -> String {
    let endpoint = if shape == "stix" { "stix" } else { "opencti" };
    format!("/api/threat-intel/{endpoint}?feed_id=revoked&source=fixture:revoked&ttl_seconds=600")
}
fn values(body: &Value, field: &str) -> Vec<String> {
    body.as_array()
        .unwrap()
        .iter()
        .filter(|row| row["source"] == "fixture:revoked")
        .map(|row| row[field].as_str().unwrap().to_string())
        .collect()
}
async fn block_route(app: &axum::Router) {
    let route = json!({"id":"revoked", "path_prefix":"/revoked", "upstream":"mock://fixture", "mode":"block", "enabled":true});
    let (status, _) = request(app, "POST", "/api/routes", true, None, Some(&route)).await;
    assert_eq!(status, StatusCode::CREATED);
}
async fn gateway_score(app: &axum::Router, ip: &str) -> (StatusCode, Value) {
    request(app, "GET", "/gateway/revoked/x", false, Some(ip), None).await
}

#[tokio::test]
async fn revoked_indicator_is_not_admitted_while_live_siblings_are_enforced() {
    for shape in ["stix", "opencti", "entities"] {
        let fixture = Fixture::new();
        let app = app(&fixture).await;
        block_route(&app).await;
        let doc = document(
            shape,
            vec![
                indicator(shape, "203.0.113.66", Some(json!(true))),
                indicator(shape, "203.0.113.10", Some(json!(false))),
                indicator(shape, "203.0.113.11", None),
            ],
        );
        let (status, result) = request(&app, "POST", &path(shape), true, None, Some(&doc)).await;
        assert_eq!(status, StatusCode::CREATED, "{shape}: {result}");
        assert_eq!(result["upserted_threats"], 2, "{shape}: {result}");
        assert_eq!(result["upserted_dnsbl"], 2, "{shape}: {result}");
        let state = snapshot(&app).await;
        let mut threats = values(&state["/api/threats"], "value");
        threats.sort();
        assert_eq!(threats, ["203.0.113.10", "203.0.113.11"], "{shape}");
        let mut dnsbl = values(&state["/api/dnsbl"], "address");
        dnsbl.sort();
        assert_eq!(dnsbl, ["203.0.113.10", "203.0.113.11"], "{shape}");

        let reloaded = self::app(&fixture).await;
        assert_eq!(snapshot(&reloaded).await, state, "{shape}: reload");
        let (status, body) = gateway_score(&reloaded, "203.0.113.66").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{shape}: revoked evidence blocked: {body}"
        );
        assert_eq!(body["score"], 0, "{shape}: {body}");
        for live in ["203.0.113.10", "203.0.113.11"] {
            let (status, _) = gateway_score(&reloaded, live).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{shape}: live {live}");
        }
    }
}

#[tokio::test]
async fn all_revoked_or_malformed_revocation_rejects_without_mutation() {
    for shape in ["stix", "opencti", "entities"] {
        for flag in [json!(true), json!("false"), json!(1), json!(null)] {
            let fixture = Fixture::new();
            let app = app(&fixture).await;
            block_route(&app).await;
            let before = snapshot(&app).await;
            let bytes = std::fs::read(fixture.state()).unwrap();
            let doc = document(
                shape,
                vec![indicator(shape, "203.0.113.66", Some(flag.clone()))],
            );
            let (status, _) = request(&app, "POST", &path(shape), false, None, Some(&doc)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(snapshot(&app).await, before);
            let (status, body) = request(&app, "POST", &path(shape), true, None, Some(&doc)).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{shape}: revoked={flag} admitted as enforcement evidence: {body}"
            );
            assert_eq!(snapshot(&app).await, before, "{shape}: revoked={flag}");
            assert_eq!(std::fs::read(fixture.state()).unwrap(), bytes);
            let (status, body) = gateway_score(&app, "203.0.113.66").await;
            assert_eq!(status, StatusCode::OK, "{shape}: revoked={flag}");
            assert_eq!(body["score"], 0);
        }
    }
}
