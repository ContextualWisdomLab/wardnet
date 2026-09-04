//! Architecture contract for the contextual-orchestrator consumer boundary.
//!
//! Wardnet may enforce ingress/admission security around LLM requests, but it
//! must not become the provider/model router. The production boundary is a
//! released contextual-orchestrator contract, not a Wardnet-owned provider
//! proxy or caller-selected concrete model.

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Method, Request, StatusCode},
    routing::post,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{fs, net::TcpListener};
use tower::ServiceExt;
use waf_ids_ai_soc::{AppConfig, AppState, SocLlmConfig, build_app};
use waf_ids_core::{AppData, SecurityEvent};

#[test]
fn wardnet_does_not_ship_a_provider_specific_llm_proxy() {
    assert!(
        !Path::new("src/bin/litellm-virtual-key-proxy.rs").exists(),
        "Wardnet must consume the released contextual-orchestrator contract instead of shipping a LiteLLM-specific proxy"
    );
}

#[derive(Clone)]
struct CaptureState {
    request_body: Arc<Mutex<Option<Value>>>,
}

async fn capture_chat_request(
    State(state): State<CaptureState>,
    request: Request<Body>,
) -> (StatusCode, [(&'static str, &'static str); 1], &'static str) {
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("capture request body");
    let json: Value = serde_json::from_slice(&body).expect("valid JSON request body");
    *state.request_body.lock().expect("capture state") = Some(json);
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        "{\"choices\":[{\"message\":{\"content\":\"triaged\"}}]}",
    )
}

fn temp_state_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("wardnet-{name}-{nanos}.json"))
}

fn sample_event() -> SecurityEvent {
    SecurityEvent {
        id: 1,
        timestamp_unix: 1000,
        client_ip: Some("203.0.113.5".parse().expect("test IP")),
        route_id: Some("demo".to_string()),
        action: "blocked".to_string(),
        reason: "sqli signature".to_string(),
        score: 90,
        path: "/gateway/demo".to_string(),
    }
}

async fn app_request(app: &Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("router response")
}

#[tokio::test]
async fn soc_request_delegates_model_and_provider_selection_to_contextual_orchestrator() {
    let capture = Arc::new(Mutex::new(None));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind capture upstream");
    let addr = listener.local_addr().expect("capture upstream address");
    let upstream = Router::new()
        .route("/v1/chat/completions", post(capture_chat_request))
        .with_state(CaptureState {
            request_body: capture.clone(),
        });
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("serve capture upstream");
    });

    let mut data = AppData::seeded();
    data.events.push(sample_event());
    let state_path = temp_state_path("llm-owner-boundary");
    fs::write(
        &state_path,
        serde_json::to_vec(&data).expect("serialize app data"),
    )
    .await
    .expect("write test state");

    let state = AppState::load(AppConfig {
        admin_token: None,
        state_path: Some(state_path.clone()),
        dnsbl_origin: "dnsbl.example".to_string(),
        event_limit: 10,
    })
    .await
    .expect("load state")
    .with_soc_llm(Some(SocLlmConfig {
        base_url: format!("http://{addr}"),
        token: "test-token".to_string(),
        model: "contextual-orchestrator".to_string(),
    }));
    let app = build_app(state);

    let response = app_request(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/api/soc/analyze")
            .header("content-type", "application/json")
            .body(Body::from(json!({"event_id": 1}).to_string()))
            .expect("SOC analyze request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let captured = capture
        .lock()
        .expect("capture state")
        .clone()
        .expect("captured request body");
    assert_eq!(captured["orchestration_mode"], "auto");
    assert!(captured.get("model").is_none());
    assert!(captured.get("provider").is_none());
    assert_eq!(captured["messages"][0]["role"], "system");
    assert!(
        captured["messages"][1]["content"]
            .as_str()
            .expect("user content")
            .contains("sqli signature")
    );

    upstream_task.abort();
    let _ = fs::remove_file(state_path).await;
}
