#[path = "../src/litellm_guard_proxy.rs"]
mod litellm_guard_proxy;

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode, Uri,
        header::{
            ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, PRAGMA,
            WWW_AUTHENTICATE,
        },
    },
    response::Response,
    routing::any,
};
use futures_util::{StreamExt, stream};
use litellm_guard_proxy::{
    ProxyConfig, ProxyState, RuntimeConfigRegistry, build_router, configuration_path_from_args,
    serve,
};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    ffi::OsString,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify};
use tower::ServiceExt;

#[derive(Clone)]
struct UpstreamState {
    expected_key: String,
    hits: Arc<AtomicUsize>,
    final_chunk_release: Arc<Notify>,
}

async fn capture_upstream(
    State(state): State<UpstreamState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    if uri.path() == "/redirect" {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        response.headers_mut().insert(
            LOCATION,
            HeaderValue::from_static("https://credential-sink.invalid/collect"),
        );
        return response;
    }

    let authorization_matches = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        == Some(state.expected_key.as_str());
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    let payload = json!({
        "authorization_matches": authorization_matches,
        "baggage_forwarded": headers.contains_key("baggage"),
        "caller_x_litellm_forwarded": headers.contains_key("x-litellm-debug"),
        "request_id": request_id,
        "cookie_forwarded": headers.contains_key(COOKIE),
        "path": uri.path(),
        "query": uri.query()
    });

    let first_chunk =
        stream::once(async { Ok::<Bytes, Infallible>(Bytes::from_static(b"data: ")) });
    let final_chunk_release = state.final_chunk_release.clone();
    let final_payload = format!("{payload}\n\n");
    let final_chunk = stream::once(async move {
        final_chunk_release.notified().await;
        Ok::<Bytes, Infallible>(Bytes::from(final_payload))
    });
    let mut response = Response::new(Body::from_stream(first_chunk.chain(final_chunk)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response.headers_mut().insert(
        "x-ratelimit-remaining-requests",
        HeaderValue::from_static("99"),
    );
    response
}

async fn stall_after_first_chunk(State(state): State<UpstreamState>) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let stalled = stream::once(async { Ok::<Bytes, Infallible>(Bytes::from_static(b"data: ")) })
        .chain(stream::pending());
    let mut response = Response::new(Body::from_stream(stalled));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response
}

async fn periodic_sse(State(state): State<UpstreamState>) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let chunks = vec![
        Bytes::from_static(b"data: one\n\n"),
        Bytes::from_static(b"data: two\n\n"),
        Bytes::from_static(b"data: three\n\n"),
    ];
    let paced = futures_util::stream::iter(chunks.into_iter().map(Ok::<Bytes, Infallible>)).then(
        |chunk| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            chunk
        },
    );
    let mut response = Response::new(Body::from_stream(paced));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response
}

async fn app_request(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.expect("router response")
}

async fn body_text(response: Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    String::from_utf8(body.to_vec()).expect("UTF-8 response")
}

fn proxy_request(method: Method, path: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(CONTENT_TYPE, "application/json")
        .header("accept", "text/event-stream")
        .header("baggage", "tenant=must-not-cross-the-proxy")
        .header("x-request-id", "request-123")
        .header("x-litellm-debug", "drop-me")
        .header(COOKIE, "session=must-not-cross-the-proxy");
    if let Some(authorization) = authorization {
        builder = builder.header(AUTHORIZATION, authorization);
    }
    builder
        .body(Body::from(
            json!({"model": "auto", "messages": []}).to_string(),
        ))
        .expect("proxy request")
}

async fn assert_rejected(
    app: &Router,
    request: Request<Body>,
    expected_code: &str,
    forbidden_fragment: Option<&str>,
) {
    let response = app_request(app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if expected_code == "authorization_header_missing" {
        assert_eq!(challenge, "Bearer realm=\"litellm\"");
    } else {
        assert!(challenge.contains("invalid_token"));
    }
    let body = body_text(response).await;
    assert!(body.contains(expected_code));
    if let Some(fragment) = forbidden_fragment {
        assert!(!body.contains(fragment));
    }
}

fn test_proxy_state(upstream_address: SocketAddr, idle_timeout: Duration) -> ProxyState {
    let config = ProxyConfig::for_test_http_upstream(
        "127.0.0.1:0".parse().expect("bind address"),
        format!("http://{upstream_address}"),
        1024 * 1024,
        Duration::from_secs(3),
        idle_timeout,
    )
    .expect("test-only proxy config");
    ProxyState::new(&config).expect("proxy state")
}

#[tokio::test]
async fn bootstrap_contract_loads_registry_and_serves_until_shutdown() {
    let config_path = configuration_path_from_args(
        [
            "--config",
            "deploy/systemd/litellm-virtual-key-proxy.json.example",
        ]
        .into_iter()
        .map(OsString::from),
    )
    .expect("parse configuration path");
    let registry =
        RuntimeConfigRegistry::from_json_file(config_path).expect("load runtime configuration");
    let mut config = ProxyConfig::from_registry(&registry).expect("resolve proxy configuration");
    config.bind_address = "127.0.0.1:0".parse().expect("ephemeral bind address");

    serve(config, std::future::ready(()))
        .await
        .expect("serve and stop cleanly");
}

#[test]
fn operational_config_rejects_plaintext_upstreams() {
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse().expect("bind address"),
        "http://127.0.0.1:4000",
        1024 * 1024,
        Duration::from_secs(3),
        Duration::from_secs(3),
    );
    assert_eq!(
        config.expect_err("plaintext upstreams must be rejected"),
        "upstream URL must use https://"
    );
}

#[tokio::test]
async fn proxy_rejects_wrong_credentials_and_preserves_safe_streaming_semantics() {
    let valid_key = "sk-virtual-test_ABC123";
    let hits = Arc::new(AtomicUsize::new(0));
    let final_chunk_release = Arc::new(Notify::new());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = listener.local_addr().expect("upstream address");
    let upstream = Router::new()
        .route("/{*path}", any(capture_upstream))
        .with_state(UpstreamState {
            expected_key: valid_key.to_string(),
            hits: hits.clone(),
            final_chunk_release: final_chunk_release.clone(),
        });
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("serve upstream");
    });

    let app = build_router(test_proxy_state(upstream_address, Duration::from_secs(3)));

    let health = app_request(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/healthz")
            .body(Body::empty())
            .expect("health request"),
    )
    .await;
    assert_eq!(health.status(), StatusCode::OK);
    let health_body = body_text(health).await;
    assert!(health_body.contains("litellm_virtual_key"));
    assert!(health_body.contains("configuration_version"));
    assert!(health_body.contains("fixed_https_origin"));
    assert!(!health_body.contains(&upstream_address.to_string()));
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let telephone_shaped = "01000000000";
    let telephone_header = format!("Bearer {telephone_shaped}");
    assert_rejected(
        &app,
        proxy_request(
            Method::POST,
            "/v1/chat/completions",
            Some(&telephone_header),
        ),
        "credential_shape_invalid",
        Some(telephone_shaped),
    )
    .await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "rejected key reached upstream"
    );

    assert_rejected(
        &app,
        proxy_request(Method::POST, "/v1/chat/completions", None),
        "authorization_header_missing",
        None,
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    assert_rejected(
        &app,
        proxy_request(
            Method::POST,
            "/v1/chat/completions",
            Some("Basic c2stbm90LWEtdmlydHVhbC1rZXk="),
        ),
        "authorization_scheme_invalid",
        None,
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let mut duplicate = proxy_request(
        Method::POST,
        "/v1/chat/completions",
        Some("Bearer sk-first"),
    );
    duplicate
        .headers_mut()
        .append(AUTHORIZATION, HeaderValue::from_static("Bearer sk-second"));
    assert_rejected(&app, duplicate, "authorization_header_ambiguous", None).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let valid_header = format!("Bearer {valid_key}");
    let accepted = app_request(
        &app,
        proxy_request(
            Method::POST,
            "/v1/chat/completions?team=alpha",
            Some(&valid_header),
        ),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        accepted
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        accepted
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream; charset=utf-8")
    );
    assert_eq!(
        accepted
            .headers()
            .get("x-ratelimit-remaining-requests")
            .and_then(|value| value.to_str().ok()),
        Some("99")
    );

    let mut accepted_stream = accepted.into_body().into_data_stream();
    let first_chunk = tokio::time::timeout(Duration::from_secs(1), accepted_stream.next())
        .await
        .expect("proxy withheld the first upstream stream chunk")
        .expect("first upstream stream item")
        .expect("first upstream stream chunk");
    assert_eq!(first_chunk.as_ref(), b"data: ");

    final_chunk_release.notify_one();
    let final_chunk = tokio::time::timeout(Duration::from_secs(1), accepted_stream.next())
        .await
        .expect("proxy did not relay the released final stream chunk")
        .expect("final upstream stream item")
        .expect("final upstream stream chunk");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), accepted_stream.next())
            .await
            .expect("proxy stream did not terminate")
            .is_none()
    );

    let accepted_body = format!(
        "{}{}",
        String::from_utf8(first_chunk.to_vec()).expect("UTF-8 first chunk"),
        String::from_utf8(final_chunk.to_vec()).expect("UTF-8 final chunk")
    );
    let event_json = accepted_body
        .strip_prefix("data: ")
        .and_then(|value| value.strip_suffix("\n\n"))
        .expect("SSE payload");
    let observed: Value = serde_json::from_str(event_json).expect("upstream JSON");
    assert_eq!(observed["authorization_matches"], true);
    assert_eq!(observed["baggage_forwarded"], false);
    assert_eq!(observed["caller_x_litellm_forwarded"], false);
    assert_eq!(observed["request_id"], "request-123");
    assert_eq!(observed["cookie_forwarded"], false);
    assert_eq!(observed["path"], "/v1/chat/completions");
    assert_eq!(observed["query"], "team=alpha");
    assert!(!accepted_body.contains(valid_key));

    for method in [
        Method::TRACE,
        Method::CONNECT,
        Method::from_bytes(b"PURGE").expect("extension method"),
    ] {
        let unsupported = app_request(
            &app,
            proxy_request(method, "/v1/models", Some(&valid_header)),
        )
        .await;
        assert_eq!(unsupported.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(unsupported.headers().contains_key(ALLOW));
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let redirected = app_request(
        &app,
        proxy_request(Method::POST, "/redirect", Some(&valid_header)),
    )
    .await;
    assert_eq!(redirected.status(), StatusCode::BAD_GATEWAY);
    assert!(!redirected.headers().contains_key(LOCATION));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(
        body_text(redirected)
            .await
            .contains("upstream_redirect_rejected")
    );

    upstream_task.abort();
}

#[tokio::test]
async fn proxy_times_out_after_first_upstream_chunk_stalls() {
    let valid_key = "sk-virtual-test_ABC123";
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = listener.local_addr().expect("upstream address");
    let upstream = Router::new()
        .route("/stall", any(stall_after_first_chunk))
        .with_state(UpstreamState {
            expected_key: valid_key.to_string(),
            hits: Arc::new(AtomicUsize::new(0)),
            final_chunk_release: Arc::new(Notify::new()),
        });
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("serve upstream");
    });

    let app = build_router(test_proxy_state(
        upstream_address,
        Duration::from_millis(40),
    ));
    let valid_header = format!("Bearer {valid_key}");
    let accepted = app_request(
        &app,
        proxy_request(Method::POST, "/stall", Some(&valid_header)),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let mut stream = accepted.into_body().into_data_stream();
    let first_chunk = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("proxy withheld the first chunk")
        .expect("first stream item")
        .expect("first stream chunk");
    assert_eq!(first_chunk.as_ref(), b"data: ");
    let timeout_item = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("proxy did not surface the idle-timeout error")
        .expect("timeout item")
        .expect_err("stalled upstream must fail");
    assert!(
        timeout_item
            .to_string()
            .contains("upstream response idle timeout")
    );

    upstream_task.abort();
}

#[tokio::test]
async fn proxy_keeps_periodic_sse_chunks_alive() {
    let valid_key = "sk-virtual-test_ABC123";
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = listener.local_addr().expect("upstream address");
    let upstream = Router::new()
        .route("/periodic", any(periodic_sse))
        .with_state(UpstreamState {
            expected_key: valid_key.to_string(),
            hits: Arc::new(AtomicUsize::new(0)),
            final_chunk_release: Arc::new(Notify::new()),
        });
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("serve upstream");
    });

    let app = build_router(test_proxy_state(
        upstream_address,
        Duration::from_millis(80),
    ));
    let valid_header = format!("Bearer {valid_key}");
    let accepted = app_request(
        &app,
        proxy_request(Method::POST, "/periodic", Some(&valid_header)),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let mut stream = accepted.into_body().into_data_stream();
    let mut observed = Vec::new();
    while let Some(item) = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("proxy stream stalled unexpectedly")
    {
        observed.push(item.expect("periodic chunk"));
    }
    let body = observed
        .into_iter()
        .map(|chunk| String::from_utf8(chunk.to_vec()).expect("UTF-8 chunk"))
        .collect::<String>();
    assert!(body.contains("data: one\n\n"));
    assert!(body.contains("data: two\n\n"));
    assert!(body.contains("data: three\n\n"));

    upstream_task.abort();
}
