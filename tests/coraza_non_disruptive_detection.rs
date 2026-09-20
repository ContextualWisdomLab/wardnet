use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    routing::post,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, ProvenEngineConfig, build_app};

async fn detection_only() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "transaction": {
            "client_ip": "203.0.113.44",
            "is_interrupted": false,
            "request": {"method": "GET", "uri": "/detect-only"},
            "response": {"http_code": 200}
        },
        "messages": [{
            "message": "Protocol Attack Detected",
            "data": {"id": 921110, "severity": 2}
        }],
        "engine": {"name": "coraza", "ruleset": "owasp-crs-test-fixture"}
    }))
}

async fn spawn_coraza_sidecar() -> (String, JoinHandle<()>) {
    let app = Router::new().route("/evaluate", post(detection_only));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/evaluate"), task)
}

async fn app_with_block_route(sidecar_url: &str) -> axum::Router {
    let state = AppState::seeded(Some("secret".to_string()))
        .with_proven_engine(ProvenEngineConfig::sidecar(sidecar_url).expect("loopback sidecar"));
    let app = build_app(state);
    let route = serde_json::json!({
        "id": "coraza-detect-only",
        "path_prefix": "/detect-only",
        "upstream": "mock://coraza-detect-only",
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
async fn block_route_does_not_escalate_non_disruptive_coraza_detection_to_block() {
    let (url, task) = spawn_coraza_sidecar().await;
    let app = app_with_block_route(&url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/detect-only")
                .header("user-agent", "wardnet-detection-probe/1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "non-interrupted HTTP 200 Coraza evidence with a CRS message must remain SOC detection evidence rather than implicit engine block authority"
    );
    task.abort();
}
