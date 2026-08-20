use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;
use tower::ServiceExt;
use waf_ids_ai_soc::{AppState, SecurityEvent, build_app};

#[derive(Clone)]
struct UpstreamState {
    expected_key: String,
    hits: Arc<AtomicUsize>,
}

async fn capture_upstream(
    State(state): State<UpstreamState>,
    headers: HeaderMap,
) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    let payload = json!({
        "authorization_matches": authorization == Some(format!("Bearer {}", state.expected_key).as_str()),
        "request_id": request_id,
        "cookie_forwarded": headers.contains_key(COOKIE),
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

fn route_request(id: &str, path_prefix: &str, upstream: &str, guarded: bool) -> Request<Body> {
    let mut route = json!({
        "id": id,
        "path_prefix": path_prefix,
        "upstream": upstream,
        "mode": "monitor",
        "enabled": true
    });
    if guarded {
        route["authorization_policy"] = json!("litellm_virtual_key");
    }
    Request::builder()
        .method(Method::POST)
        .uri("/api/routes")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(route.to_string()))
        .expect("route request")
}

fn gateway_request(path: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
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
        .expect("gateway request")
}

#[tokio::test]
async fn litellm_virtual_key_policy_rejects_wrong_credential_class_before_upstream() {
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

    let app = build_app(AppState::seeded(None));
    let base_url = format!("http://{upstream_address}");
    let created = app_request(
        &app,
        route_request("llm", "/llm", &base_url, true),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let phone_shaped = "061012345318";
    let rejected = app_request(
        &app,
        gateway_request(
            "/gateway/llm/v1/chat/completions",
            Some(format!("Bearer {phone_shaped}").as_str()),
        ),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "rejected key reached upstream");
    let challenge = rejected
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(challenge.contains("invalid_token"));
    assert_eq!(
        rejected
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let rejected_body = body_text(rejected).await;
    assert!(!rejected_body.contains(phone_shaped));
    assert!(!rejected_body.contains("0610"));

    let missing = app_request(
        &app,
        gateway_request("/gateway/llm/v1/chat/completions", None),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let wrong_scheme = app_request(
        &app,
        gateway_request(
            "/gateway/llm/v1/chat/completions",
            Some("Basic c2stbm90LWEtdmlydHVhbC1rZXk="),
        ),
    )
    .await;
    assert_eq!(wrong_scheme.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let events_response = app_request(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/api/events?action=auth_rejected")
            .body(Body::empty())
            .expect("events request"),
    )
    .await;
    let events: Vec<SecurityEvent> =
        serde_json::from_str(&body_text(events_response).await).expect("events JSON");
    assert_eq!(events.len(), 3);
    assert!(
        events
            .iter()
            .all(|event| event.action == "auth_rejected")
    );
    assert!(
        events
            .iter()
            .any(|event| event.reason == "credential_shape_invalid")
    );
    assert!(
        events
            .iter()
            .any(|event| event.reason == "authorization_header_missing")
    );
    assert!(
        events
            .iter()
            .any(|event| event.reason == "authorization_scheme_invalid")
    );
    let serialized_events = serde_json::to_string(&events).expect("serialize events");
    assert!(!serialized_events.contains(phone_shaped));
    assert!(!serialized_events.contains("0610"));

    let accepted = app_request(
        &app,
        gateway_request(
            "/gateway/llm/v1/chat/completions",
            Some(format!("Bearer {valid_key}").as_str()),
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
    assert!(!accepted_body.contains(valid_key));

    let legacy_created = app_request(
        &app,
        route_request("legacy", "/legacy", &base_url, false),
    )
    .await;
    assert_eq!(legacy_created.status(), StatusCode::CREATED);
    let legacy = app_request(
        &app,
        gateway_request("/gateway/legacy/v1/models", None),
    )
    .await;
    assert_eq!(legacy.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    upstream_task.abort();
}
