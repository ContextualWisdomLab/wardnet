//! Hostile buyer acceptance for #442: once Wardnet has admitted and exposed a
//! streaming response, downstream cancellation must stop the upstream body
//! instead of continuing to read it to completion in the background.
//!
//! This fixture is intentionally RED against protected `main`: current
//! `proxy_request()` collects the whole reqwest response before it can return an
//! Axum response, so the buyer cannot cancel the admitted body while the
//! upstream tail is still held.

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

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

#[derive(Clone, Default)]
struct CancellationProbe {
    request_seen: Arc<Notify>,
    release_tail: Arc<Notify>,
    upstream_body_dropped: Arc<AtomicBool>,
}

struct UpstreamBodyDropSignal(Arc<AtomicBool>);

impl Drop for UpstreamBodyDropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct CancellationStreamState {
    stage: u8,
    release_tail: Arc<Notify>,
    _drop_signal: UpstreamBodyDropSignal,
}

async fn cancellation_upstream(State(probe): State<CancellationProbe>) -> Response {
    probe.request_seen.notify_one();

    let body_stream = stream::unfold(
        CancellationStreamState {
            stage: 0,
            release_tail: probe.release_tail.clone(),
            _drop_signal: UpstreamBodyDropSignal(probe.upstream_body_dropped.clone()),
        },
        |mut state| async move {
            match state.stage {
                0 => {
                    state.stage = 1;
                    Some((
                        Ok::<Bytes, Infallible>(Bytes::from_static(b"first-")),
                        state,
                    ))
                }
                1 => {
                    state.release_tail.notified().await;
                    state.stage = 2;
                    Some((Ok(Bytes::from_static(b"tail")), state))
                }
                _ => None,
            }
        },
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid loopback cancellation response")
}

async fn gateway_with_cancellation_upstream() -> (
    Router,
    CancellationProbe,
    tokio::task::JoinHandle<()>,
) {
    let probe = CancellationProbe::default();
    let upstream_app = Router::new()
        .route("/v1/cancel", any(cancellation_upstream))
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
        "id": "streaming-cancellation-red",
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
async fn downstream_cancellation_drops_held_upstream_body() {
    let (app, probe, upstream_task) = gateway_with_cancellation_upstream().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/cancel")
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
                "Wardnet withheld the admitted response until the held upstream tail completed; downstream cancellation cannot propagate while the whole body is materialized"
            );
        }
    };

    assert_eq!(response.status(), StatusCode::OK);
    let mut downstream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_millis(500), downstream.next())
        .await
        .expect("the admitted prefix must be available before cancellation")
        .expect("the downstream stream must produce the admitted prefix")
        .expect("the admitted prefix must not be an error");
    assert_eq!(first, Bytes::from_static(b"first-"));

    drop(downstream);

    tokio::time::timeout(Duration::from_secs(2), async {
        while !probe.upstream_body_dropped.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dropping the admitted downstream body must promptly cancel the held upstream body");

    assert!(
        !probe.release_tail.notified().now_or_never().is_some(),
        "the test must not release the upstream tail to manufacture cancellation"
    );

    upstream_task.abort();
}
