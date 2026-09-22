//! Hostile transport acceptance for the live Coraza authority boundary.
//!
//! Reqwest enables system/environment proxies by default. A loopback-only URL
//! check is therefore insufficient if the dedicated Coraza client can still
//! honor `HTTP_PROXY`: the bounded inspection envelope can leave the host and a
//! proxy can impersonate the proven engine. This regression makes that boundary
//! executable by installing an attacker-controlled ambient proxy and requiring
//! the Coraza request to reach the configured loopback sidecar directly.

use std::{collections::HashMap, sync::Arc};

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
    let correlation_id = payload["wardnet"]["correlation_id"].as_str().unwrap_or("");
    Json(serde_json::json!({
        "transaction": {
            "is_interrupted": false,
            "request": {
                "method": request["method"].as_str().unwrap_or("GET"),
                "uri": request["uri"].as_str().unwrap_or("/")
            },
            "response": {"http_code": 200}
        },
        "wardnet": {"correlation_id": correlation_id},
        "messages": [],
        "engine": {"name": "coraza", "ruleset": "owasp-crs-proxy-boundary-fixture"}
    }))
}

async fn spawn_http_peer() -> (String, Calls, JoinHandle<()>) {
    let calls = Calls::default();
    let app = Router::new()
        .route("/evaluate", post(clean_coraza))
        .fallback(post(clean_coraza))
        .with_state(calls.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), calls, task)
}

struct EnvRestore(HashMap<&'static str, Option<String>>);

impl EnvRestore {
    fn capture(keys: &[&'static str]) -> Self {
        Self(
            keys.iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect(),
        )
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            // SAFETY: this integration-test binary contains only this test, so
            // process-global proxy variables cannot race another test thread.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[tokio::test]
async fn coraza_loopback_transport_ignores_attacker_controlled_system_proxy() {
    const PROXY_KEYS: [&str; 8] = [
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    ];
    let _restore = EnvRestore::capture(&PROXY_KEYS);

    let (sidecar_origin, sidecar_calls, sidecar_task) = spawn_http_peer().await;
    let (proxy_origin, proxy_calls, proxy_task) = spawn_http_peer().await;

    // SAFETY: this file is one integration-test binary with one test. The
    // environment is captured/restored above and no sibling test can observe it.
    unsafe {
        for key in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::set_var(key, &proxy_origin);
        }
        for key in ["NO_PROXY", "no_proxy", "HTTPS_PROXY", "https_proxy"] {
            std::env::remove_var(key);
        }
    }

    let state = AppState::seeded(Some("secret".to_string())).with_proven_engine(
        ProvenEngineConfig::sidecar(format!("{sidecar_origin}/evaluate"))
            .expect("loopback Coraza sidecar"),
    );
    let app = build_app(state);
    let route = serde_json::json!({
        "id": "coraza-proxy-boundary",
        "path_prefix": "/proxy-boundary",
        "upstream": "mock://proxy-boundary",
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

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/gateway/proxy-boundary")
                .header("user-agent", "wardnet-proxy-boundary/1.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        proxy_calls.lock().await.len(),
        0,
        "an ambient proxy must never observe or impersonate Wardnet's loopback-only Coraza authority"
    );
    assert_eq!(
        sidecar_calls.lock().await.len(),
        1,
        "the inspection envelope must reach the configured same-host Coraza sidecar exactly once"
    );

    proxy_task.abort();
    sidecar_task.abort();
}
