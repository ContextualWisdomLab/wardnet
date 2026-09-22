use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    routing::post,
};
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, ProvenEngineConfig, build_app};

async fn method_uri_only_clean(Json(payload): Json<Value>) -> Json<Value> {
    let request = &payload["transaction"]["request"];
    let method = request["method"].as_str().unwrap_or("POST");
    let uri = request["uri"].as_str().unwrap_or("/bind");

    Json(serde_json::json!({
        "transaction": {
            "is_interrupted": false,
            "request": {"method": method, "uri": uri},
            "response": {"http_code": 200}
        },
        "messages": [],
        "engine": {"name": "coraza", "ruleset": "owasp-crs-test-fixture"}
    }))
}

async fn spawn_sidecar() -> (String, JoinHandle<()>) {
    let app = Router::new().route("/evaluate", post(method_uri_only_clean));
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
        "id": "coraza-request-binding",
        "path_prefix": "/bind",
        "upstream": "mock://coraza-request-binding",
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
async fn block_route_rejects_clean_verdict_bound_only_to_method_and_uri() {
    let (url, task) = spawn_sidecar().await;
    let app = app_with_block_route(&url).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/gateway/bind")
                .header(CONTENT_TYPE, "application/json")
                .header("user-agent", "() { :;}; /bin/bash -c 'id'")
                .body(Body::from(r#"{"role":"admin","action":"transfer"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "method+URI-only Coraza evidence can be stale or misrouted across same-route requests; block mode must fail closed until the verdict is bound to this exact request"
    );

    task.abort();
}
