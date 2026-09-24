//! Hostile buyer acceptance for #442: a real upstream response larger than the
//! relay-memory budget must start reaching the buyer before the upstream tail
//! completes.
//!
//! This fixture is intentionally RED against protected `main`. The current
//! `proxy_request()` materializes the complete reqwest body, so even after the
//! upstream has made more than the test relay-memory budget available, Wardnet
//! withholds the downstream response until the held tail is released.

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    response::Response,
    routing::any,
};
use futures_util::{StreamExt, stream};
use tokio::sync::Notify;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

const RELAY_MEMORY_BUDGET_BYTES: usize = 1024 * 1024;
const LARGE_PREFIX_BYTES: usize = RELAY_MEMORY_BUDGET_BYTES + 64 * 1024;
const UPSTREAM_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Clone, Default)]
struct LargeResponseProbe {
    request_seen: Arc<Notify>,
    release_tail: Arc<Notify>,
}

async fn large_prefix_upstream(State(probe): State<LargeResponseProbe>) -> Response {
    probe.request_seen.notify_one();

    let release_tail = probe.release_tail.clone();
    let body_stream = stream::unfold(0usize, move |emitted| {
        let release_tail = release_tail.clone();
        async move {
            if emitted < LARGE_PREFIX_BYTES {
                let remaining = LARGE_PREFIX_BYTES - emitted;
                let chunk_len = remaining.min(UPSTREAM_CHUNK_BYTES);
                return Some((
                    Ok::<Bytes, Infallible>(Bytes::from(vec![0xA5; chunk_len])),
                    emitted + chunk_len,
                ));
            }

            if emitted == LARGE_PREFIX_BYTES {
                release_tail.notified().await;
                return Some((Ok(Bytes::from_static(b"tail")), LARGE_PREFIX_BYTES + 1));
            }

            None
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid loopback large streaming response")
}

async fn gateway_with_large_upstream() -> (Router, LargeResponseProbe, tokio::task::JoinHandle<()>)
{
    let probe = LargeResponseProbe::default();
    let upstream_app = Router::new()
        .route("/v1/large", any(large_prefix_upstream))
        .with_state(probe.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback upstream listener");
    let upstream_addr = listener.local_addr().expect("loopback upstream address");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream_app)
            .await
            .expect("loopback upstream must serve until test cleanup");
    });

    let app = build_app(AppState::seeded(Some("secret".to_string())));
    let route = serde_json::json!({
        "id": "streaming-large-response-red",
        "path_prefix": "/stream",
        "upstream": format!("http://{upstream_addr}"),
        "mode": "monitor",
        "enabled": true,
        "block_threshold": null
    });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/routes")
                .header(CONTENT_TYPE, "application/json")
                .header("x-admin-token", "secret")
                .body(Body::from(route.to_string()))
                .expect("valid route registration request"),
        )
        .await
        .expect("Wardnet must answer route registration");
    assert_eq!(created.status(), StatusCode::CREATED);

    (app, probe, upstream_task)
}

#[tokio::test]
async fn gateway_releases_large_prefix_before_held_tail() {
    assert!(
        UPSTREAM_CHUNK_BYTES < RELAY_MEMORY_BUDGET_BYTES,
        "the hostile fixture must not manufacture one upstream chunk larger than the relay budget"
    );

    let (app, probe, upstream_task) = gateway_with_large_upstream().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/large")
        .body(Body::empty())
        .expect("valid buyer request");

    let mut gateway_task = tokio::spawn(async move { app.oneshot(request).await });

    tokio::time::timeout(Duration::from_secs(2), probe.request_seen.notified())
        .await
        .expect("loopback upstream must receive the admitted request before the RED assertion");

    let response = match tokio::time::timeout(Duration::from_millis(500), &mut gateway_task).await {
        Ok(joined) => joined
            .expect("gateway task must not panic")
            .expect("gateway service must answer"),
        Err(_) => {
            probe.release_tail.notify_waiters();
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut gateway_task).await;
            upstream_task.abort();
            panic!(
                "Wardnet withheld a response whose available prefix exceeds the bounded relay-memory budget until the upstream tail completed"
            );
        }
    };

    assert_eq!(response.status(), StatusCode::OK);
    let mut downstream = response.into_body().into_data_stream();
    let mut admitted_prefix_bytes = 0usize;

    while admitted_prefix_bytes < LARGE_PREFIX_BYTES {
        let next = tokio::time::timeout(Duration::from_secs(2), downstream.next())
            .await
            .expect("the large admitted prefix must remain readable while the tail is held")
            .expect("the downstream body must not complete before the held tail")
            .expect("the admitted prefix must not become an error");
        admitted_prefix_bytes += next.len();
    }

    assert_eq!(
        admitted_prefix_bytes, LARGE_PREFIX_BYTES,
        "the bounded fixture must relay exactly the admitted prefix before the held tail"
    );
    assert!(
        admitted_prefix_bytes > RELAY_MEMORY_BUDGET_BYTES,
        "the buyer must receive more than the relay-memory budget before the upstream tail is released"
    );

    probe.release_tail.notify_waiters();
    let tail = tokio::time::timeout(Duration::from_secs(2), downstream.next())
        .await
        .expect("the released tail must arrive")
        .expect("the downstream body must produce the released tail")
        .expect("the released tail must not be an error");
    assert_eq!(tail, Bytes::from_static(b"tail"));

    upstream_task.abort();
}
