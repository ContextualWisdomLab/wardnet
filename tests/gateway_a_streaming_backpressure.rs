//! Hostile buyer acceptance for #442: generic gateway streaming must preserve
//! downstream backpressure and remain usable under concurrent held streams.
//!
//! This file is test-only. Protected production source is intentionally left
//! unchanged until the serialized gateway writer lane is clear.

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
use futures_util::{StreamExt, future::join_all, stream};
use tokio::sync::Notify;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

const BACKPRESSURE_CHUNK_BYTES: usize = 64 * 1024;
const BACKPRESSURE_TOTAL_CHUNKS: usize = 1024; // 64 MiB if fully drained.
const MAX_UNPOLLED_CHUNKS: usize = 128; // 8 MiB bounded read-ahead witness.
const CONCURRENT_SLOW_REQUESTS: usize = 4;

#[derive(Clone, Default)]
struct BackpressureProbe {
    request_seen: Arc<Notify>,
    chunks_emitted: Arc<AtomicUsize>,
}

async fn backpressure_upstream(State(probe): State<BackpressureProbe>) -> Response {
    probe.request_seen.notify_one();

    let body_stream = stream::unfold(0usize, move |emitted| {
        let probe = probe.clone();
        async move {
            if emitted >= BACKPRESSURE_TOTAL_CHUNKS {
                return None;
            }

            probe.chunks_emitted.fetch_add(1, Ordering::Release);
            Some((
                Ok::<Bytes, Infallible>(Bytes::from(vec![0x5A; BACKPRESSURE_CHUNK_BYTES])),
                emitted + 1,
            ))
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid loopback backpressure response")
}

async fn gateway_with_backpressure_upstream()
-> (Router, BackpressureProbe, tokio::task::JoinHandle<()>) {
    let probe = BackpressureProbe::default();
    let upstream_app = Router::new()
        .route("/v1/backpressure", any(backpressure_upstream))
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
        "id": "streaming-backpressure-red",
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
async fn unpolled_buyer_body_does_not_drain_the_entire_large_upstream() {
    assert!(
        MAX_UNPOLLED_CHUNKS < BACKPRESSURE_TOTAL_CHUNKS,
        "the bounded read-ahead witness must be smaller than the hostile body"
    );

    let (app, probe, upstream_task) = gateway_with_backpressure_upstream().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/backpressure")
        .body(Body::empty())
        .expect("valid buyer request");

    let mut gateway_task = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(Duration::from_secs(2), probe.request_seen.notified())
        .await
        .expect("loopback upstream must receive the request before the backpressure assertion");

    let response = match tokio::time::timeout(Duration::from_secs(2), &mut gateway_task).await {
        Ok(joined) => joined
            .expect("gateway task must not panic")
            .expect("gateway service must answer"),
        Err(_) => {
            upstream_task.abort();
            panic!(
                "Wardnet did not expose a downstream response while a finite 64 MiB upstream was being drained; the relay must return a streaming body instead of waiting for whole-body materialization"
            );
        }
    };
    assert_eq!(response.status(), StatusCode::OK);

    let mut downstream = response.into_body().into_data_stream();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let emitted_while_buyer_idle = probe.chunks_emitted.load(Ordering::Acquire);
    assert!(
        emitted_while_buyer_idle <= MAX_UNPOLLED_CHUNKS,
        "an unpolled buyer body caused Wardnet/upstream read-ahead of {emitted_while_buyer_idle} x 64 KiB chunks; bounded relay backpressure must not drain the 64 MiB body in the background"
    );

    let first = tokio::time::timeout(Duration::from_secs(2), downstream.next())
        .await
        .expect("polling the buyer body must make one admitted chunk available")
        .expect("the downstream stream must produce data")
        .expect("the first admitted chunk must not be an error");
    assert!(!first.is_empty());

    drop(downstream);
    upstream_task.abort();
}

#[derive(Clone, Default)]
struct ConcurrentProbe {
    slow_requests_seen: Arc<AtomicUsize>,
    release_tails: Arc<Notify>,
    fast_request_seen: Arc<Notify>,
}

async fn concurrent_slow_upstream(State(probe): State<ConcurrentProbe>) -> Response {
    probe.slow_requests_seen.fetch_add(1, Ordering::Release);

    let release_tails = probe.release_tails.clone();
    let body_stream = stream::unfold(0u8, move |stage| {
        let release_tails = release_tails.clone();
        async move {
            match stage {
                0 => Some((Ok::<Bytes, Infallible>(Bytes::from_static(b"first-")), 1)),
                1 => {
                    release_tails.notified().await;
                    Some((Ok(Bytes::from_static(b"tail")), 2))
                }
                _ => None,
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid held loopback response")
}

async fn concurrent_fast_upstream(State(probe): State<ConcurrentProbe>) -> Response {
    probe.fast_request_seen.notify_one();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from("fast"))
        .expect("valid fast loopback response")
}

async fn gateway_with_concurrent_upstream() -> (Router, ConcurrentProbe, tokio::task::JoinHandle<()>)
{
    let probe = ConcurrentProbe::default();
    let upstream_app = Router::new()
        .route("/v1/slow", any(concurrent_slow_upstream))
        .route("/v1/fast", any(concurrent_fast_upstream))
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
        "id": "streaming-concurrency-red",
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
async fn concurrent_held_streams_expose_prefixes_and_do_not_block_fast_buyer_traffic() {
    let (app, probe, upstream_task) = gateway_with_concurrent_upstream().await;

    let mut slow_tasks = Vec::with_capacity(CONCURRENT_SLOW_REQUESTS);
    for _ in 0..CONCURRENT_SLOW_REQUESTS {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/gateway/stream/v1/slow")
            .body(Body::empty())
            .expect("valid slow buyer request");
        let app = app.clone();
        slow_tasks.push(tokio::spawn(async move { app.oneshot(request).await }));
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        while probe.slow_requests_seen.load(Ordering::Acquire) < CONCURRENT_SLOW_REQUESTS {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all concurrent slow requests must reach the loopback upstream");

    let joined = match tokio::time::timeout(Duration::from_millis(500), join_all(slow_tasks)).await
    {
        Ok(joined) => joined,
        Err(_) => {
            probe.release_tails.notify_waiters();
            upstream_task.abort();
            panic!(
                "concurrent held upstreams kept buyer response heads behind their unreleased tails; Wardnet must expose each admitted stream without whole-body buffering"
            );
        }
    };

    let mut slow_bodies = Vec::with_capacity(CONCURRENT_SLOW_REQUESTS);
    for joined in joined {
        let response = joined
            .expect("slow gateway task must not panic")
            .expect("slow gateway request must produce a response");
        assert_eq!(response.status(), StatusCode::OK);
        slow_bodies.push(response.into_body().into_data_stream());
    }

    for body in &mut slow_bodies {
        let first = tokio::time::timeout(Duration::from_millis(500), body.next())
            .await
            .expect("each concurrent buyer must receive its admitted prefix promptly")
            .expect("each held stream must produce a prefix")
            .expect("each admitted prefix must not be an error");
        assert_eq!(first, Bytes::from_static(b"first-"));
    }

    let fast_request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/fast")
        .body(Body::empty())
        .expect("valid fast buyer request");
    let fast_response = tokio::time::timeout(
        Duration::from_millis(500),
        app.clone().oneshot(fast_request),
    )
    .await
    .expect("unrelated fast buyer traffic must remain responsive while slow streams are held")
    .expect("fast gateway request must produce a response");
    assert_eq!(fast_response.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), probe.fast_request_seen.notified())
        .await
        .expect("the fast request must reach the real loopback upstream");

    drop(slow_bodies);
    probe.release_tails.notify_waiters();
    upstream_task.abort();
}
