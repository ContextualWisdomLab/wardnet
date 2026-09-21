//! Hostile buyer acceptance for #442: the generic gateway must not withhold an
//! admitted downstream response until the upstream body has completed.
//!
//! This test is intentionally RED against protected `main`. The current
//! `proxy_request()` materializes the complete reqwest body before constructing
//! an Axum response, so a long-lived or delayed upstream tail blocks the buyer
//! from receiving even the response head and first body chunk. Production
//! source is intentionally unchanged in this lane.

use std::{convert::Infallible, io, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{
        Method, Request, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::Response,
    routing::any,
};
use futures_util::{StreamExt, stream};
use tokio::sync::Notify;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, build_app};

const DISHONEST_CONTENT_LENGTH: &str = "8388608";

#[derive(Clone, Default)]
struct StreamProbe {
    request_seen: Arc<Notify>,
    release_tail: Arc<Notify>,
    release_failure: Arc<Notify>,
}

async fn delayed_chunk_upstream(State(probe): State<StreamProbe>) -> Response {
    probe.request_seen.notify_one();

    let release_tail = probe.release_tail.clone();
    let body_stream = stream::unfold(0u8, move |stage| {
        let release_tail = release_tail.clone();
        async move {
            match stage {
                0 => Some((Ok::<Bytes, Infallible>(Bytes::from_static(b"first-")), 1)),
                1 => {
                    release_tail.notified().await;
                    Some((Ok(Bytes::from_static(b"second")), 2))
                }
                _ => None,
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid loopback streaming response")
}

async fn dishonest_content_length_upstream(State(probe): State<StreamProbe>) -> Response {
    probe.request_seen.notify_one();

    let release_tail = probe.release_tail.clone();
    let body_stream = stream::unfold(0u8, move |stage| {
        let release_tail = release_tail.clone();
        async move {
            match stage {
                0 => Some((Ok::<Bytes, Infallible>(Bytes::from_static(b"first-")), 1)),
                1 => {
                    release_tail.notified().await;
                    Some((Ok(Bytes::from_static(b"short-tail")), 2))
                }
                _ => None,
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, DISHONEST_CONTENT_LENGTH)
        .body(Body::from_stream(body_stream))
        .expect("valid loopback response with hostile content length")
}

async fn partial_failure_upstream(State(probe): State<StreamProbe>) -> Response {
    probe.request_seen.notify_one();

    let release_failure = probe.release_failure.clone();
    let body_stream = stream::unfold(0u8, move |stage| {
        let release_failure = release_failure.clone();
        async move {
            match stage {
                0 => Some((Ok::<Bytes, io::Error>(Bytes::from_static(b"first-")), 1)),
                1 => {
                    release_failure.notified().await;
                    Some((
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "hostile upstream reset",
                        )),
                        2,
                    ))
                }
                _ => None,
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(body_stream))
        .expect("valid loopback partial-failure response")
}

async fn gateway_with_delayed_upstream() -> (Router, StreamProbe, tokio::task::JoinHandle<()>) {
    let probe = StreamProbe::default();
    let upstream_app = Router::new()
        .route("/v1/stream", any(delayed_chunk_upstream))
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
        "id": "streaming-red",
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

async fn gateway_with_dishonest_length_upstream() -> (
    Router,
    StreamProbe,
    tokio::task::JoinHandle<()>,
) {
    let probe = StreamProbe::default();
    let upstream_app = Router::new()
        .route("/v1/dishonest-length", any(dishonest_content_length_upstream))
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
        "id": "streaming-dishonest-length-red",
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

async fn gateway_with_partial_failure_upstream() -> (
    Router,
    StreamProbe,
    tokio::task::JoinHandle<()>,
) {
    let probe = StreamProbe::default();
    let upstream_app = Router::new()
        .route("/v1/partial", any(partial_failure_upstream))
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
        "id": "streaming-partial-failure-red",
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
async fn gateway_exposes_first_upstream_chunk_without_waiting_for_delayed_tail() {
    let (app, probe, upstream_task) = gateway_with_delayed_upstream().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/stream")
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
                "Wardnet withheld the downstream response until the delayed upstream tail was released; generic proxying must return a streaming response without whole-body materialization"
            );
        }
    };

    assert_eq!(response.status(), StatusCode::OK);
    let mut downstream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_millis(500), downstream.next())
        .await
        .expect("the first admitted downstream body chunk must be available promptly")
        .expect("the downstream stream must produce a first chunk")
        .expect("the first downstream chunk must not be an error");
    assert_eq!(first, Bytes::from_static(b"first-"));

    probe.release_tail.notify_waiters();
    let second = tokio::time::timeout(Duration::from_secs(2), downstream.next())
        .await
        .expect("the released tail must arrive")
        .expect("the downstream stream must produce the tail")
        .expect("the downstream tail must not be an error");
    assert_eq!(second, Bytes::from_static(b"second"));

    upstream_task.abort();
}

#[tokio::test]
async fn gateway_streams_prefix_before_trusting_dishonest_content_length() {
    let (app, probe, upstream_task) = gateway_with_dishonest_length_upstream().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/dishonest-length")
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
                "Wardnet trusted a hostile large Content-Length enough to withhold the admitted response prefix; relay admission must not require whole-body materialization"
            );
        }
    };

    assert_eq!(response.status(), StatusCode::OK);
    let mut downstream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_millis(500), downstream.next())
        .await
        .expect("the admitted prefix must stream before the declared body length is satisfied")
        .expect("the downstream stream must produce the admitted prefix")
        .expect("the admitted prefix must not be an error");
    assert_eq!(first, Bytes::from_static(b"first-"));

    probe.release_tail.notify_waiters();
    drop(downstream);
    upstream_task.abort();
}

#[tokio::test]
async fn gateway_exposes_admitted_prefix_before_partial_upstream_failure() {
    let (app, probe, upstream_task) = gateway_with_partial_failure_upstream().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/gateway/stream/v1/partial")
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
            probe.release_failure.notify_waiters();
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut gateway_task).await;
            upstream_task.abort();
            panic!(
                "Wardnet withheld the downstream response until the upstream stream failed; an admitted prefix must be relayed before a later upstream body failure"
            );
        }
    };

    assert_eq!(response.status(), StatusCode::OK);
    let mut downstream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_millis(500), downstream.next())
        .await
        .expect("the admitted prefix must be available before the upstream failure")
        .expect("the downstream stream must produce the admitted prefix")
        .expect("the admitted prefix must not be an error");
    assert_eq!(first, Bytes::from_static(b"first-"));

    probe.release_failure.notify_waiters();
    let failure = tokio::time::timeout(Duration::from_secs(2), downstream.next())
        .await
        .expect("the upstream failure must become observable promptly")
        .expect("the downstream stream must surface the upstream failure");
    assert!(
        failure.is_err(),
        "a partial upstream failure must not be converted into successful downstream body completion"
    );

    upstream_task.abort();
}
