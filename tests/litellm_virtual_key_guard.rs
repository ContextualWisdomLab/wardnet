#[path = "../src/litellm_guard_proxy.rs"]
mod litellm_guard_proxy;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode, Uri,
        header::{ALLOW, AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, WWW_AUTHENTICATE},
    },
    response::Response,
    routing::any,
};
use litellm_guard_proxy::{ProxyConfig, ProxyState, build_router};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tower::ServiceExt;

#[derive(Clone)]
struct UpstreamState {
    expected_key: String,
    hits: Arc<AtomicUsize>,
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
        "request_id": request_id,
        "cookie_forwarded": headers.contains_key(COOKIE),
        "path": uri.path(),
        "query": uri.query()
    });
    let mut response = Response::new(Body::from(format!("data: {payload}\n\n")));
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
        .header("x-request-id", "request-123")
        .header(COOKIE, "session=must-not-cross-the-proxy");
    if let Some(authorization) = authorization {
        builder = builder.header(AUTHORIZATION, authorization);
    }
    builder
        .body(Body::from(r#"{"model":"auto","messages":[]}"#))
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
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if expected_code != "authorization_header_missing" {
        assert!(challenge.contains("invalid_token"));
    }
    let body = body_text(response).await;
    assert!(body.contains(expected_code));
    if let Some(fragment) = forbidden_fragment {
        assert!(!body.contains(fragment));
    }
}

#[tokio::test]
async fn proxy_rejects_wrong_credentials_and_preserves_safe_streaming_semantics() {
    let valid_key = "sk-virtual-test_ABC123";
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_address = listener.local_addr().expect("upstream address");
    let upstream = Router::new()
        .route("/{*path}", any(capture_upstream))
        .with_state(UpstreamState {
            expected_key: valid_key.to_string(),
            hits: hits.clone(),
        });
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("serve upstream");
    });

    let config = ProxyConfig::new(
        "127.0.0.1:0".parse().expect("bind address"),
        format!("http://{upstream_address}"),
        1024 * 1024,
        Duration::from_secs(3),
    )
    .expect("proxy config");
    let app = build_router(ProxyState::new(&config).expect("proxy state"));

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
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let phone_shaped = "061012345318";
    let phone_header = format!("Bearer {phone_shaped}");
    assert_rejected(
        &app,
        proxy_request(Method::POST, "/v1/chat/completions", Some(&phone_header)),
        "credential_shape_invalid",
        Some("0610"),
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "rejected key reached upstream");

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
    duplicate.headers_mut().append(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer sk-second"),
    );
    assert_rejected(
        &app,
        duplicate,
        "authorization_header_ambiguous",
        None,
    )
    .await;
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
    let accepted_body = body_text(accepted).await;
    let event_json = accepted_body
        .strip_prefix("data: ")
        .and_then(|value| value.strip_suffix("\n\n"))
        .expect("SSE payload");
    let observed: Value = serde_json::from_str(event_json).expect("upstream JSON");
    assert_eq!(observed["authorization_matches"], true);
    assert_eq!(observed["request_id"], "request-123");
    assert_eq!(observed["cookie_forwarded"], false);
    assert_eq!(observed["path"], "/v1/chat/completions");
    assert_eq!(observed["query"], "team=alpha");
    assert!(!accepted_body.contains(valid_key));

    let unsupported = app_request(
        &app,
        proxy_request(Method::TRACE, "/v1/models", Some(&valid_header)),
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(unsupported.headers().contains_key(ALLOW));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let redirected = app_request(
        &app,
        proxy_request(Method::POST, "/redirect", Some(&valid_header)),
    )
    .await;
    assert_eq!(redirected.status(), StatusCode::BAD_GATEWAY);
    assert!(!redirected.headers().contains_key(LOCATION));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(body_text(redirected).await.contains("upstream_redirect_rejected"));

    upstream_task.abort();
}
