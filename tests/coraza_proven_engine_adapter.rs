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

async fn coraza_evaluate(State(calls): State<Calls>, Json(payload): Json<Value>) -> Json<Value> {
    calls.lock().await.push(payload.clone());
    let request = &payload["transaction"]["request"];
    let method = request["method"].as_str().unwrap_or("GET");
    let uri = request["uri"].as_str().unwrap_or("/");
    let correlation_id = payload["wardnet"]["correlation_id"].as_str().unwrap_or("");
    if uri == "/malformed" {
        return Json(serde_json::json!({"unexpected":"shape"}));
    }
    if uri == "/header-red" || uri == "/header-monitor" {
        return Json(serde_json::json!({
            "transaction": {
                "client_ip": "203.0.113.44",
                "is_interrupted": true,
                "request": {"method": method, "uri": uri},
                "response": {"http_code": 403}
            },
            "wardnet": {"correlation_id": correlation_id},
            "messages": [{
                "message": "Remote Command Execution: Shellshock",
                "data": {"id": 932170, "severity": 2}
            }],
            "engine": {"name":"coraza", "ruleset":"owasp-crs-test-fixture"}
        }));
    }
    Json(serde_json::json!({
        "transaction": {
            "is_interrupted": false,
            "request": {"method": method, "uri": uri},
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
        .route("/evaluate", post(coraza_evaluate))
        .with_state(calls.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/evaluate"), calls, task)
}

async fn app_with_route(
    route_id: &str,
    path_prefix: &str,
    mode: &str,
    sidecar_url: &str,
) -> axum::Router {
    let state = AppState::seeded(Some("secret".to_string()))
        .with_proven_engine(ProvenEngineConfig::sidecar(sidecar_url).expect("loopback sidecar"));
    let app = build_app(state);
    let route = serde_json::json!({
        "id": route_id,
        "path_prefix": path_prefix,
        "upstream": format!("mock://{route_id}"),
        "mode": mode,
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
async fn block_route_uses_coraza_for_header_only_attack_and_minimizes_credentials() {
    let (url, calls, task) = spawn_coraza_sidecar().await;
    let app = app_with_route("coraza-header-red", "/header-red", "block", &url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-red")
                .header("user-agent", "() { :;}; /bin/bash -c 'cat /etc/passwd'")
                .header("authorization", "Bearer must-not-forward")
                .header("cookie", "session=must-not-forward")
                .header("x-admin-token", "must-not-forward")
                .header("x-forwarded-for", "198.51.100.66")
                .header("x-real-ip", "198.51.100.77")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let calls = calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0]["wardnet"]["correlation_id"]
            .as_str()
            .is_some_and(|value| value.len() == 49),
        "every Coraza evaluation must carry one bounded Wardnet correlation id"
    );
    let headers = calls[0]["transaction"]["request"]["headers"]
        .as_array()
        .unwrap();
    assert!(headers.iter().any(|header| {
        header["name"] == "user-agent"
            && header["value"]
                .as_str()
                .is_some_and(|value| value.contains("() { :;}"))
    }));
    for forbidden in [
        "authorization",
        "cookie",
        "x-admin-token",
        "proxy-authorization",
        "x-forwarded-for",
        "x-real-ip",
    ] {
        assert!(
            headers.iter().all(|header| header["name"] != forbidden),
            "raw client-attribution header {forbidden} must not cross the Coraza sidecar boundary"
        );
    }
    drop(calls);
    task.abort();
}

#[tokio::test]
async fn benign_header_traffic_remains_allowed_after_proven_engine_evaluation() {
    let (url, calls, task) = spawn_coraza_sidecar().await;
    let app = app_with_route("coraza-header-benign", "/header-benign", "block", &url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-benign")
                .header("user-agent", "wardnet-buyer-probe/1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.lock().await.len(), 1);
    task.abort();
}

#[tokio::test]
async fn block_route_fails_closed_on_malformed_coraza_evidence() {
    let (url, _calls, task) = spawn_coraza_sidecar().await;
    let app = app_with_route("coraza-malformed", "/malformed", "block", &url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/malformed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    task.abort();
}

#[tokio::test]
async fn block_route_fails_closed_when_configured_coraza_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{addr}/evaluate");
    let app = app_with_route("coraza-unavailable", "/unavailable", "block", &url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/unavailable")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn monitor_route_records_coraza_hit_without_enforcement() {
    let (url, _calls, task) = spawn_coraza_sidecar().await;
    let app = app_with_route("coraza-header-monitor", "/header-monitor", "monitor", &url).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-monitor")
                .header("user-agent", "() { :;}; /bin/bash -c 'id'")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    task.abort();
}

#[tokio::test]
async fn block_route_fails_closed_before_sidecar_on_incomplete_header_envelope() {
    let (url, calls, task) = spawn_coraza_sidecar().await;
    let app = app_with_route("coraza-header-envelope", "/header-envelope", "block", &url).await;
    let oversized = "x".repeat(9_000);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/header-envelope")
                .header("user-agent", oversized.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an incomplete allowlisted-header projection must fail closed instead of accepting a clean Coraza verdict for a request the sidecar did not inspect in full"
    );
    assert_eq!(
        calls.lock().await.len(),
        0,
        "Wardnet must not ask Coraza to authorize a partial allowlisted-header envelope"
    );
    task.abort();
}
