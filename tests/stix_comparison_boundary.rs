//! Shared STIX comparison projection through actual management and persistence.
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
            "wardnet-stix-comparison-{}-{}",
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
            admin_token: Some("synthetic-stix-token".into()),
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
    value: Option<&Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if token {
        builder = builder.header("x-admin-token", "synthetic-stix-token");
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
        let (status, body) = request(app, "GET", path, true, None).await;
        assert_eq!(status, StatusCode::OK);
        out.insert(path.into(), body);
    }
    Value::Object(out)
}
fn document(shape: &str, pattern: &str) -> Value {
    let indicator =
        json!({"type": "indicator", "pattern_type": "stix", "pattern": pattern, "confidence": 80});
    match shape {
        "stix" | "opencti" => indicator,
        "entities" => {
            json!({"entities": [{"entity_type": "Indicator", "standard_id": "indicator--fixture", "pattern_type": "stix", "pattern": pattern, "confidence": 80}]})
        }
        _ => panic!("unknown fixture shape"),
    }
}
fn path(shape: &str) -> String {
    let endpoint = if shape == "stix" { "stix" } else { "opencti" };
    format!(
        "/api/threat-intel/{endpoint}?feed_id=comparison&source=fixture:comparison&ttl_seconds=600"
    )
}
async fn rejection(shape: &str, pattern: &str) {
    let fixture = Fixture::new();
    let app = app(&fixture).await;
    let route = json!({"id":"comparison", "path_prefix":"/comparison", "upstream":"mock://fixture", "mode":"block", "enabled":true});
    assert_eq!(
        request(&app, "POST", "/api/routes", true, Some(&route))
            .await
            .0,
        StatusCode::CREATED
    );
    let before = snapshot(&app).await;
    let bytes = std::fs::read(fixture.state()).unwrap();
    let doc = document(shape, pattern);
    assert_eq!(
        request(&app, "POST", &path(shape), false, Some(&doc))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(snapshot(&app).await, before);
    assert_eq!(std::fs::read(fixture.state()).unwrap(), bytes);
    let (status, _) = request(&app, "POST", &path(shape), true, Some(&doc)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{shape}: unsupported comparison projected into a positive indicator: {pattern}"
    );
    assert_eq!(snapshot(&app).await, before);
    assert_eq!(std::fs::read(fixture.state()).unwrap(), bytes);
    let reloaded = self::app(&fixture).await;
    assert_eq!(snapshot(&reloaded).await, before);
    let (status, body) = request(
        &reloaded,
        "GET",
        "/gateway/comparison/status.example",
        false,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["score"], 0);
}
#[tokio::test]
async fn non_equality_does_not_project_a_positive_domain_indicator() {
    for shape in ["stix", "opencti", "entities"] {
        for operator in ["!=", ">=", "<=", "=="] {
            rejection(
                shape,
                &format!("[domain-name:value {operator} 'status.example']"),
            )
            .await;
        }
    }
}
#[tokio::test]
async fn unrelated_property_does_not_project_the_domain_value() {
    for shape in ["stix", "opencti", "entities"] {
        for property in [
            "x_note",
            "resolves_to_refs",
            "value NOT",
            "value!",
            "value.other",
        ] {
            rejection(
                shape,
                &format!("[domain-name:{property} = 'status.example']"),
            )
            .await;
        }
    }
}
#[tokio::test]
async fn literal_value_equality_preserves_authorized_rows_and_reload() {
    for shape in ["stix", "opencti", "entities"] {
        let fixture = Fixture::new();
        let app = app(&fixture).await;
        let pattern = "[domain-name:value = 'STATUS.EXAMPLE']";
        let (status, result) = request(
            &app,
            "POST",
            &path(shape),
            true,
            Some(&document(shape, pattern)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(result["upserted_threats"], 1);
        assert_eq!(result["upserted_dnsbl"], 0);
        let before = snapshot(&app).await;
        let rows: Vec<_> = before["/api/threats"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["source"] == "fixture:comparison")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0],
            &json!({"value":"status.example","indicator_type":"domain","severity":"critical","source":"fixture:comparison","ttl_seconds":600})
        );
        let reloaded = self::app(&fixture).await;
        assert_eq!(snapshot(&reloaded).await, before);
    }
}
