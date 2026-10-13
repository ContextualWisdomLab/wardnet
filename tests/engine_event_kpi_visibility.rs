//! SOC KPI visibility for proven-engine events.
//! docs/analytics/soc-kpis.md: `GET /api/kpis` counts "blocked events, monitored
//! events"; docs/architecture.md: Suricata alerts "become `SecurityEvent` rows for
//! SOC export/KPI". Gateway decisions record `blocked`/`monitored`, while the
//! Suricata EVE and Coraza audit adapters record `block`/`monitor`. Both
//! vocabularies must reach the same KPI, Prometheus and triage-filter classes.
//! Synthetic in-memory state and credentials only; no network.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

const TOKEN: &str = "synthetic-kpi-token";

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, bytes.to_vec())
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn post(path: &str, token: bool, content_type: &str, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", content_type);
    if token {
        builder = builder.header("x-admin-token", TOKEN);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn json(app: &axum::Router, path: &str) -> Value {
    let (status, bytes) = send(app, get(path)).await;
    assert_eq!(status, StatusCode::OK, "{path}");
    serde_json::from_slice(&bytes).unwrap()
}

fn metric(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap_or_else(|| panic!("missing metric {name}: {text}"))
        .trim()
        .parse()
        .unwrap()
}

const SURICATA: &str = concat!(
    r#"{"event_type":"alert","src_ip":"203.0.113.51","alert":{"signature":"ET block sev1","severity":1},"http":{"url":"/a"}}"#,
    "\n",
    r#"{"event_type":"alert","src_ip":"203.0.113.52","alert":{"signature":"ET monitor sev3","severity":3},"http":{"url":"/b"}}"#,
    "\n"
);
const CORAZA: &str = r#"{"transaction":{"client_ip":"203.0.113.53","is_interrupted":true,"request":{"uri":"/c"},"response":{"http_code":403}},"messages":[{"message":"SQLi","data":{"id":942100,"severity":2}}]}"#;

#[tokio::test]
async fn engine_events_are_counted_in_blocked_and_monitored_kpis() {
    let app = build_app(AppState::seeded(Some(TOKEN.to_string())));

    // Positive control: the seeded monitor route records one gateway `monitored` event.
    let (status, _) = send(&app, get("/gateway/demo/probe?q=union%20select")).await;
    assert_eq!(status, StatusCode::OK);
    let control = json(&app, "/api/kpis").await;
    assert_eq!(control["event_count"], 1, "{control}");
    assert_eq!(control["monitor_event_count"], 1, "{control}");
    assert_eq!(control["blocked_event_count"], 0, "{control}");

    // Unauthenticated engine ingest is rejected and does not change the KPIs.
    for (path, content_type, body) in [
        ("/api/ids/suricata/eve", "application/x-ndjson", SURICATA),
        ("/api/waf/coraza/audit", "application/json", CORAZA),
    ] {
        let (status, _) = send(&app, post(path, false, content_type, body)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
    assert_eq!(json(&app, "/api/kpis").await, control);

    let (status, body) = send(
        &app,
        post(
            "/api/ids/suricata/eve",
            true,
            "application/x-ndjson",
            SURICATA,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = send(
        &app,
        post("/api/waf/coraza/audit", true, "application/json", CORAZA),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );

    // The adapters keep their own vocabulary in stored events.
    let events = json(&app, "/api/events").await;
    let mut actions: Vec<String> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["action"].as_str().unwrap().to_string())
        .collect();
    actions.sort();
    assert_eq!(actions, ["block", "block", "monitor", "monitored"]);

    // Every recorded event belongs to exactly one KPI class.
    let kpis = json(&app, "/api/kpis").await;
    assert_eq!(kpis["event_count"], 4, "{kpis}");
    assert_eq!(kpis["blocked_event_count"], 2, "{kpis}");
    assert_eq!(kpis["monitor_event_count"], 2, "{kpis}");

    let (status, bytes) = send(&app, get("/metrics")).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(metric(&text, "waf_ids_security_events"), 4);
    assert_eq!(metric(&text, "waf_ids_security_events_blocked"), 2);
    assert_eq!(metric(&text, "waf_ids_security_events_monitored"), 2);

    // SOC triage filters by class in both vocabularies.
    for (filter, expected) in [
        ("blocked", 2),
        ("block", 2),
        ("monitored", 2),
        ("monitor", 2),
    ] {
        let filtered = json(&app, &format!("/api/events?action={filter}")).await;
        assert_eq!(
            filtered.as_array().unwrap().len(),
            expected,
            "action={filter}: {filtered}"
        );
    }
    let unknown = json(&app, "/api/events?action=allowed").await;
    assert_eq!(unknown.as_array().unwrap().len(), 0);
}
