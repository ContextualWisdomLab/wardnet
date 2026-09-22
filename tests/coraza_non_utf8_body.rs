use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    routing::post,
};
use serde_json::Value;
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, ProvenEngineConfig, build_app};

type Calls = Arc<Mutex<Vec<Value>>>;

async fn clean_coraza(State(calls): State<Calls>, Json(payload): Json<Value>) -> Json<Value> {
    calls.lock().await.push(payload.clone());
    let request = &payload["transaction"]["request"];
    let correlation_id = payload["wardnet"]["correlation_id"]
        .as_str()
        .unwrap_or("");
    Json(serde_json::json!({
        "transaction": {
            "is_interrupted": false,
            "request": {
                "method": request["method"].as_str().unwrap_or("POST"),
                "uri": request["uri"].as_str().unwrap_or("/")
            },
            "response": {"http_code": 200}
        },
        "wardnet": {"correlation_id": correlation_id},
        "messages": [],
        "engine": {"name":"coraza", "ruleset":"owasp-crs-test-fixture"}
    }))
}

async fn spawn_coraza_sidecar() -> (String, Calls, JoinHandle<()>) {
    let calls = Calls::default();
    let app = Router::new()
        .route("/evaluate", post(clean_coraza))
        .with_state(calls.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/evaluate"), calls, task)
}

async fn block_app(sidecar_url: &str) -> axum::Router {
    let state = AppState::seeded(Some("secret".to_string()))
        .with_proven_engine(ProvenEngineConfig::sidecar(sidecar_url).expect("loopback sidecar"));
    let app = build_app(state);
    let route = serde_json::json!({
        "id": "coraza-non-utf8-body",
        "path_prefix": "/non-utf8-body",
        "upstream": "mock://coraza-non-utf8-body",
        "mode": "block",
        "enabled": true,
        "block_threshold": null
    })
    .to_string();

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/routes")
                .header(CONTENT_TYPE, "application/json")
                .header("x-admin-token", "secret")
                .body(Body::from(route))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    app
}

#[tokio::test]
async fn block_route_never_authorizes_a_lossy_request_body_projection() {
    let (url, calls, task) = spawn_coraza_sidecar().await;
    let app = block_app(&url).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/gateway/non-utf8-body")
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(vec![b'a', 0xff, b'b']))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "block mode must fail closed when the v1 Coraza envelope cannot represent the exact request body"
    );
    assert_eq!(
        calls.lock().await.len(),
        0,
        "Wardnet must not ask Coraza to authorize a lossy UTF-8 replacement of the buyer request body"
    );
    task.abort();
}

#[tokio::test]
async fn block_route_preserves_valid_utf8_replacement_character() {
    let (url, calls, task) = spawn_coraza_sidecar().await;
    let app = block_app(&url).await;
    let body = "a\u{FFFD}b";

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/gateway/non-utf8-body")
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "valid UTF-8 containing U+FFFD must not be confused with a lossy replacement of invalid bytes"
    );
    let calls = calls.lock().await;
    assert_eq!(
        calls.len(),
        1,
        "valid UTF-8 must reach the proven engine exactly once"
    );
    assert_eq!(
        calls[0]["transaction"]["request"]["body"],
        Value::String(body.to_string()),
        "the proven engine must receive the exact valid UTF-8 body"
    );
    drop(calls);
    task.abort();
}
