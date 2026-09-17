#!/usr/bin/env bash
set -euo pipefail

cat > src/proven_engine.rs <<'RS'
//! Live Coraza/OWASP CRS request-evaluation boundary.
//!
//! Wardnet owns the route/policy decision, not WAF signatures. This
//! adapter sends a bounded, credential-minimized request envelope to a
//! same-host Coraza sidecar and accepts only response evidence that is
//! correlated to the exact method/URI. It deliberately does not
//! implement CRS rules or general-purpose egress policy.

use std::{net::IpAddr, time::Duration};

use futures_util::StreamExt;

use crate::coraza_audit::{CorazaIngestedHit, parse_coraza_audit_body};

pub const SIDECAR_TIMEOUT: Duration = Duration::from_millis(1_500);
pub const SIDECAR_MAX_BODY_BYTES: usize = 1_048_576;
pub const FORWARDED_HEADER_LIMIT: usize = 32;
pub const FORWARDED_HEADERS_MAX_BYTES: usize = 8_192;

/// Wardnet-owned configuration for the live WAF boundary.
///
/// The sidecar is intentionally restricted to loopback. Broader
/// executable outbound authorization belongs to EgressWeave and must
/// arrive through a released owner contract rather than being copied
/// into Wardnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenEngineConfig {
    sidecar_url: Option<String>,
}

impl ProvenEngineConfig {
    pub fn disabled() -> Self {
        Self { sidecar_url: None }
    }

    pub fn sidecar(url: impl Into<String>) -> Result<Self, String> {
        let url = url.into().trim().to_string();
        if url.is_empty() {
            return Err("Coraza sidecar URL must not be blank".to_string());
        }
        validate_loopback_sidecar_url(&url)?;
        Ok(Self {
            sidecar_url: Some(url),
        })
    }

    pub(crate) fn sidecar_url(&self) -> Option<&str> {
        self.sidecar_url.as_deref()
    }

    pub fn is_configured(&self) -> bool {
        self.sidecar_url.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvenEngineOutcome {
    NotConfigured,
    Clean,
    Hit(CorazaIngestedHit),
    Unavailable { reason: String },
}

fn validate_loopback_sidecar_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| format!("invalid Coraza sidecar URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Coraza sidecar URL must use http or https".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Coraza sidecar URL requires a host".to_string())?;
    if host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(
            "Coraza sidecar must be loopback-local until released EgressWeave authorization is available"
                .to_string(),
        )
    }
}

/// Bounded request-header allowlist sent to the WAF engine.
///
/// Credential-bearing fields such as `Authorization`, `Cookie`,
/// `Proxy-Authorization`, and `X-Admin-Token` are intentionally absent.
pub(crate) fn engine_forwarded_headers(
    headers: &axum::http::HeaderMap,
) -> Vec<(String, String)> {
    let allowlist = [
        "host",
        "user-agent",
        "accept",
        "content-type",
        "referer",
        "origin",
        "x-requested-with",
        "x-forwarded-for",
        "x-real-ip",
    ];
    let mut forwarded = Vec::new();
    let mut total = 0usize;
    for name in allowlist {
        for value in headers.get_all(name) {
            if forwarded.len() >= FORWARDED_HEADER_LIMIT {
                return forwarded;
            }
            let Ok(value) = value.to_str() else {
                continue;
            };
            let next = total.saturating_add(name.len()).saturating_add(value.len());
            if next > FORWARDED_HEADERS_MAX_BYTES {
                return forwarded;
            }
            total = next;
            forwarded.push((name.to_string(), value.to_string()));
        }
    }
    forwarded
}

fn sidecar_request_body(
    method: &str,
    uri: &str,
    body: &str,
    client_ip: Option<IpAddr>,
    headers: &[(String, String)],
    policy_id: &str,
) -> serde_json::Value {
    let mut request = serde_json::json!({
        "method": method,
        "uri": uri,
        "headers": headers
            .iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect::<Vec<_>>(),
    });
    if !body.is_empty() {
        request["body"] = serde_json::Value::String(body.to_string());
    }
    let mut transaction = serde_json::json!({ "request": request });
    if let Some(ip) = client_ip {
        transaction["client_ip"] = serde_json::Value::String(ip.to_string());
    }
    serde_json::json!({
        "transaction": transaction,
        "wardnet": {
            "policy_id": policy_id,
            "contract": "coraza-live-evaluate-v1"
        }
    })
}

async fn bounded_sidecar_text(response: reqwest::Response) -> Result<String, String> {
    if let Some(length) = response.content_length()
        && length as usize > SIDECAR_MAX_BODY_BYTES
    {
        return Err(format!(
            "Coraza sidecar response exceeds {SIDECAR_MAX_BODY_BYTES} bytes"
        ));
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "Coraza sidecar response read failed".to_string())?;
        if bytes.len().saturating_add(chunk.len()) > SIDECAR_MAX_BODY_BYTES {
            return Err(format!(
                "Coraza sidecar response exceeds {SIDECAR_MAX_BODY_BYTES} bytes"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "Coraza sidecar response was not UTF-8".to_string())
}

fn response_request(value: &serde_json::Value) -> Option<&serde_json::Value> {
    value
        .get("transaction")
        .and_then(|tx| tx.get("request"))
        .or_else(|| value.get("request"))
}

fn response_correlates(value: &serde_json::Value, method: &str, uri: &str) -> bool {
    let Some(request) = response_request(value) else {
        return false;
    };
    let returned_method = request
        .get("method")
        .or_else(|| request.pointer("/http/method"))
        .and_then(|value| value.as_str());
    let returned_uri = request
        .get("uri")
        .or_else(|| request.pointer("/http/uri"))
        .and_then(|value| value.as_str());
    returned_method.is_some_and(|returned| returned.eq_ignore_ascii_case(method))
        && returned_uri == Some(uri)
}

fn response_proves_clean(value: &serde_json::Value) -> bool {
    let tx = value.get("transaction").unwrap_or(value);
    let interrupted = tx
        .get("is_interrupted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let status = tx
        .pointer("/response/http_code")
        .or_else(|| tx.pointer("/response/status"))
        .and_then(|value| value.as_u64());
    let messages = value
        .get("messages")
        .or_else(|| tx.get("messages"))
        .and_then(|value| value.as_array());
    !interrupted
        && status.is_some_and(|code| code < 400)
        && messages.is_some_and(|items| items.is_empty())
}

fn evidence_suffix(value: &serde_json::Value, policy_id: &str) -> String {
    let ruleset = value
        .pointer("/engine/ruleset")
        .or_else(|| value.pointer("/producer/ruleset"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match ruleset {
        Some(ruleset) => format!("engine=coraza; policy={policy_id}; ruleset={ruleset}"),
        None => format!("engine=coraza; policy={policy_id}"),
    }
}

fn outcome_from_sidecar_response(
    status: reqwest::StatusCode,
    body: &str,
    method: &str,
    uri: &str,
    client_ip: Option<IpAddr>,
    policy_id: &str,
) -> ProvenEngineOutcome {
    if !status.is_success() && !matches!(status.as_u16(), 403 | 406) {
        return ProvenEngineOutcome::Unavailable {
            reason: format!("Coraza sidecar HTTP {status}"),
        };
    }
    let value = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(value) => value,
        Err(_) => {
            return ProvenEngineOutcome::Unavailable {
                reason: "Coraza sidecar returned malformed JSON evidence".to_string(),
            };
        }
    };
    if !response_correlates(&value, method, uri) {
        return ProvenEngineOutcome::Unavailable {
            reason: "Coraza sidecar evidence did not correlate to the exact request".to_string(),
        };
    }
    let suffix = evidence_suffix(&value, policy_id);
    match parse_coraza_audit_body(body) {
        Ok(mut parsed) if !parsed.hits.is_empty() => {
            let idx = parsed
                .hits
                .iter()
                .position(|hit| hit.action == "block")
                .unwrap_or(0);
            let mut hit = parsed.hits.swap_remove(idx);
            hit.reason = format!("{}; {suffix}", hit.reason);
            if matches!(status.as_u16(), 403 | 406) {
                hit.action = "block".to_string();
            }
            ProvenEngineOutcome::Hit(hit)
        }
        Ok(_) if matches!(status.as_u16(), 403 | 406) => {
            ProvenEngineOutcome::Hit(CorazaIngestedHit {
                client_ip,
                action: "block".to_string(),
                reason: format!("coraza/crs: transaction interrupted ({status}); {suffix}"),
                score: 50,
                path: uri.to_string(),
                timestamp_unix: None,
            })
        }
        Ok(_) if response_proves_clean(&value) => ProvenEngineOutcome::Clean,
        Ok(_) => ProvenEngineOutcome::Unavailable {
            reason: "Coraza sidecar evidence did not prove a clean or interrupted transaction".to_string(),
        },
        Err(reason) => ProvenEngineOutcome::Unavailable {
            reason: format!("Coraza sidecar audit evidence invalid: {reason}"),
        },
    }
}

pub(crate) async fn evaluate_sidecar(
    client: &reqwest::Client,
    config: &ProvenEngineConfig,
    method: &str,
    uri: &str,
    body: &str,
    client_ip: Option<IpAddr>,
    headers: &[(String, String)],
    policy_id: &str,
) -> ProvenEngineOutcome {
    let Some(url) = config.sidecar_url() else {
        return ProvenEngineOutcome::NotConfigured;
    };
    let payload = sidecar_request_body(method, uri, body, client_ip, headers, policy_id);
    let response = match client
        .post(url)
        .json(&payload)
        .timeout(SIDECAR_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let reason = if error.is_timeout() {
                "Coraza sidecar timed out"
            } else if error.is_connect() {
                "Coraza sidecar is unreachable"
            } else {
                "Coraza sidecar request failed"
            };
            return ProvenEngineOutcome::Unavailable {
                reason: reason.to_string(),
            };
        }
    };
    let status = response.status();
    let body = match bounded_sidecar_text(response).await {
        Ok(body) => body,
        Err(reason) => return ProvenEngineOutcome::Unavailable { reason },
    };
    outcome_from_sidecar_response(status, &body, method, uri, client_ip, policy_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn sidecar_is_loopback_only() {
        assert!(ProvenEngineConfig::sidecar("http://127.0.0.1:9000/evaluate").is_ok());
        assert!(ProvenEngineConfig::sidecar("http://[::1]:9000/evaluate").is_ok());
        assert!(ProvenEngineConfig::sidecar("http://localhost:9000/evaluate").is_ok());
        assert!(ProvenEngineConfig::sidecar("https://example.com/evaluate").is_err());
        assert!(ProvenEngineConfig::sidecar("file:///tmp/coraza").is_err());
    }

    #[test]
    fn header_forwarding_is_bounded_and_excludes_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("wardnet.example"));
        headers.insert("user-agent", HeaderValue::from_static("buyer-probe/1"));
        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        headers.insert("cookie", HeaderValue::from_static("sid=secret"));
        headers.insert("x-admin-token", HeaderValue::from_static("admin-secret"));
        let forwarded = engine_forwarded_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["host", "user-agent"]);

        let mut oversized = HeaderMap::new();
        oversized.insert(
            "user-agent",
            HeaderValue::from_str(&"x".repeat(FORWARDED_HEADERS_MAX_BYTES + 1)).unwrap(),
        );
        assert!(engine_forwarded_headers(&oversized).is_empty());
    }

    #[test]
    fn clean_evidence_requires_exact_request_correlation() {
        let clean = r#"{
          "transaction": {
            "request": {"method":"GET","uri":"/ok"},
            "response": {"http_code":200}
          },
          "messages": [],
          "engine": {"ruleset":"owasp-crs-test"}
        }"#;
        assert_eq!(
            outcome_from_sidecar_response(
                reqwest::StatusCode::OK,
                clean,
                "GET",
                "/ok",
                None,
                "route:test"
            ),
            ProvenEngineOutcome::Clean
        );
        assert!(matches!(
            outcome_from_sidecar_response(
                reqwest::StatusCode::OK,
                clean,
                "GET",
                "/different",
                None,
                "route:test"
            ),
            ProvenEngineOutcome::Unavailable { .. }
        ));
    }
}
RS

cat > tests/coraza_live_enforcement.rs <<'RS'
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
            "messages": [{
                "message": "Remote Command Execution: Shellshock",
                "data": {"id": 932170, "severity": 2}
            }],
            "engine": {"name":"coraza", "ruleset":"owasp-crs-test-fixture"}
        }));
    }
    Json(serde_json::json!({
        "transaction": {
            "request": {"method": method, "uri": uri},
            "response": {"http_code": 200}
        },
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
    let state = AppState::seeded(Some("secret".to_string())).with_proven_engine(
        ProvenEngineConfig::sidecar(sidecar_url).expect("loopback sidecar"),
    );
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
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let calls = calls.lock().await;
    assert_eq!(calls.len(), 1);
    let headers = calls[0]["transaction"]["request"]["headers"]
        .as_array()
        .unwrap();
    assert!(headers.iter().any(|header| {
        header["name"] == "user-agent"
            && header["value"].as_str().is_some_and(|value| value.contains("() { :;}"))
    }));
    for forbidden in ["authorization", "cookie", "x-admin-token", "proxy-authorization"] {
        assert!(headers.iter().all(|header| header["name"] != forbidden));
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
RS

mkdir -p docs/doctoring
cat > docs/doctoring/in-path-coraza-adapter.md <<'MD'
# In-path Coraza request adapter

## Decision boundary

Wardnet owns route selection, monitor/block policy, security-event production, and the decision to forward a request. It does not own OWASP CRS detection logic. When a `ProvenEngineConfig` sidecar is configured, Wardnet submits each matched live gateway request to a same-host Coraza/OWASP CRS evaluator before forwarding. The adapter is intentionally loopback-only; executable general-purpose egress authorization remains EgressWeave ownership and is not copied into Wardnet.

The request envelope contains method, effective gateway URI, body, client address when known, a bounded non-secret header allowlist, Wardnet route-policy identity, and contract identifier `coraza-live-evaluate-v1`. `Authorization`, `Cookie`, `Proxy-Authorization`, and `X-Admin-Token` are never forwarded. Header forwarding is capped at 32 fields / 8 KiB. Sidecar evaluation has a 1.5 s timeout and a 1 MiB response cap.

A sidecar response is not accepted merely because it is HTTP 2xx. Wardnet requires parseable JSON evidence correlated to the exact request method and URI. A clean decision additionally requires an explicit non-interrupted transaction, a response status below 400, and an empty messages array. Block evidence retains Coraza/CRS rule text/ID from the audit adapter and adds Wardnet policy identity plus sidecar ruleset identity when supplied. Malformed, oversized, uncorrelated, timed-out, or unreachable evidence is `engine_unavailable`; a block-mode route fails closed with HTTP 503. Monitor mode records the degraded evidence and may continue, preserving route-scoped semantics.

`tests/coraza_live_enforcement.rs` uses a protocol fixture, not a substitute detector. The fixture returns Coraza-shaped block/clean evidence by test URI so the test proves Wardnet forwards the hostile `User-Agent`, excludes credential-bearing headers, correlates the response, enforces block versus monitor semantics, and fails closed on unusable engine evidence. Production detection authority remains a real Coraza deployment with a pinned OWASP CRS ruleset.

## Operational acceptance

Before exposing a block-mode route through this boundary, deploy the Coraza evaluator on loopback, pin and inventory the CRS policy/ruleset, then construct `AppState` with `ProvenEngineConfig::sidecar(...)`. The current bounded slice does not add a new environment-variable or database configuration source because Runtime Configuration is owned by its separate Wardnet lane. That owner must expose the released/configured adapter without reintroducing handler-time environment reads before this becomes a packaged production default.

Treat `engine_unavailable` events as protection-loss evidence. Do not convert malformed or uncorrelated evidence to `Clean`, and do not add local request signatures to compensate for a missing Coraza engine.

## Traceability

Coraza. (n.d.). *Coraza Web Application Firewall documentation*. https://coraza.io/docs/

National Institute of Standards and Technology. (2007). *Guide to intrusion detection and prevention systems (IDPS)* (NIST Special Publication 800-94). https://doi.org/10.6028/NIST.SP.800-94

OWASP Foundation. (2025). *OWASP Core Rule Set documentation*. https://coreruleset.org/docs/

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308. https://doi.org/10.1109/PROC.1975.9939

These references ground the use of a proven WAF/ruleset authority and fail-safe treatment of unavailable or unverifiable decisions. They are rationale, not evidence that a specific Coraza/CRS build has been deployed or released. No paper PDF is added in this lane because redistribution permission for the exact retrieved versions was not independently established.
MD

python - <<'PY'
from pathlib import Path

path = Path("src/lib.rs")
text = path.read_text()

replacements = [
    (
        "mod opencti_import;\nmod stix_import;",
        "mod opencti_import;\nmod proven_engine;\nmod stix_import;",
    ),
    (
        "pub use credentials::{listen_is_loopback_only, require_write_auth_for_bind};\n",
        "pub use credentials::{listen_is_loopback_only, require_write_auth_for_bind};\npub use proven_engine::ProvenEngineConfig;\n",
    ),
    (
        "    http: reqwest::Client,\n    feed_http: reqwest::Client,\n    admin_token: Option<String>,",
        "    http: reqwest::Client,\n    feed_http: reqwest::Client,\n    waf_http: reqwest::Client,\n    proven_engine: ProvenEngineConfig,\n    admin_token: Option<String>,",
    ),
    (
        "            feed_http: reqwest::Client::builder()\n                .redirect(reqwest::redirect::Policy::none())\n                .build()\n                .expect(\"failed to build no-redirect feed client\"),\n            admin_token: config.admin_token,",
        "            feed_http: reqwest::Client::builder()\n                .redirect(reqwest::redirect::Policy::none())\n                .build()\n                .expect(\"failed to build no-redirect feed client\"),\n            waf_http: reqwest::Client::builder()\n                .redirect(reqwest::redirect::Policy::none())\n                .build()\n                .expect(\"failed to build no-redirect WAF client\"),\n            proven_engine: ProvenEngineConfig::disabled(),\n            admin_token: config.admin_token,",
    ),
    (
        "    pub fn with_max_body_size(mut self, max_body_bytes: usize) -> Self {\n        self.max_body_bytes = max_body_bytes;\n        self\n    }\n",
        "    pub fn with_max_body_size(mut self, max_body_bytes: usize) -> Self {\n        self.max_body_bytes = max_body_bytes;\n        self\n    }\n\n    /// Configure live request evaluation by the Wardnet-owned proven-engine port.\n    pub fn with_proven_engine(mut self, config: ProvenEngineConfig) -> Self {\n        self.proven_engine = config;\n        self\n    }\n",
    ),
]
for old, new in replacements:
    if text.count(old) != 1:
        raise SystemExit(f"expected exactly one lib.rs seam, found {text.count(old)} for {old[:80]!r}")
    text = text.replace(old, new, 1)

needle = '''    let body_text = String::from_utf8_lossy(&body);
    let scored = score_request(
'''
insertion = '''    let body_text = String::from_utf8_lossy(&body);
    let engine_uri = match uri.query() {
        Some(query) if !query.is_empty() => format!("{gateway_path}?{query}"),
        _ => gateway_path.to_string(),
    };
    let forwarded_headers = proven_engine::engine_forwarded_headers(&headers);
    let mut proven_engine_recorded = false;
    match proven_engine::evaluate_sidecar(
        &state.waf_http,
        &state.proven_engine,
        method.as_str(),
        &engine_uri,
        &body_text,
        client_ip,
        &forwarded_headers,
        &route.id,
    )
    .await
    {
        proven_engine::ProvenEngineOutcome::NotConfigured
        | proven_engine::ProvenEngineOutcome::Clean => {}
        proven_engine::ProvenEngineOutcome::Hit(hit) => {
            let disruptive = hit.action == "block";
            let action = if route.mode == EnforcementMode::Block && disruptive {
                "blocked"
            } else {
                "monitored"
            };
            record_event(
                &state,
                client_ip,
                Some(route.id.clone()),
                action,
                hit.reason.clone(),
                hit.score,
                gateway_path,
            )
            .await;
            proven_engine_recorded = true;
            if action == "blocked" {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "action": "blocked",
                        "route_id": route.id,
                        "score": hit.score,
                        "reason": hit.reason,
                        "engine": "coraza"
                    })),
                )
                    .into_response();
            }
        }
        proven_engine::ProvenEngineOutcome::Unavailable { reason } => {
            record_event(
                &state,
                client_ip,
                Some(route.id.clone()),
                "engine_unavailable",
                reason.clone(),
                0,
                gateway_path,
            )
            .await;
            proven_engine_recorded = true;
            if route.mode == EnforcementMode::Block {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "action": "engine_unavailable",
                        "route_id": route.id,
                        "reason": reason,
                        "engine": "coraza"
                    })),
                )
                    .into_response();
            }
        }
    }

    let scored = score_request(
'''
if text.count(needle) != 1:
    raise SystemExit(f"expected one gateway scoring seam, found {text.count(needle)}")
text = text.replace(needle, insertion, 1)

monitored = '''    record_event(
        &state,
        client_ip,
        Some(route.id.clone()),
        "monitored",
        scored.reason.clone(),
        scored.score,
        gateway_path,
    )
    .await;
'''
monitored_replacement = '''    if !proven_engine_recorded {
        record_event(
            &state,
            client_ip,
            Some(route.id.clone()),
            "monitored",
            scored.reason.clone(),
            scored.score,
            gateway_path,
        )
        .await;
    }
'''
if text.count(monitored) != 1:
    raise SystemExit(f"expected one gateway monitored seam, found {text.count(monitored)}")
text = text.replace(monitored, monitored_replacement, 1)
path.write_text(text)

architecture = Path("docs/architecture.md")
doc = architecture.read_text()
old = "- **WAF**: Coraza/OWASP CRS audit JSON/NDJSON ingest is available at `POST /api/waf/coraza/audit` (admin token). Interrupted transactions and CRS rule messages become `SecurityEvent` rows and feed gateway enforcement (DNSBL + `client_ip`/`path` threat indicators) so subsequent gateway decisions block matching clients. In-process Coraza embedding remains a follow-up — do not replace CRS with hand-rolled rules."
new = "- **WAF**: Coraza/OWASP CRS audit JSON/NDJSON ingest is available at `POST /api/waf/coraza/audit` (admin token). The bounded `ProvenEngineConfig` port can also evaluate each live matched gateway request through a loopback Coraza sidecar before forwarding; Wardnet sends only method/effective URI/body/client IP plus a capped non-secret header allowlist, correlates response evidence to the exact request, fails block-mode traffic closed on unusable configured-engine evidence, and preserves Coraza/CRS as detection authority. Runtime Configuration still owns how packaged deployments expose that adapter. Do not replace CRS with hand-written signatures or duplicate EgressWeave transport policy."
if doc.count(old) != 1:
    raise SystemExit("architecture WAF seam changed")
architecture.write_text(doc.replace(old, new, 1))

threat = Path("docs/security/threat-model.md")
doc = threat.read_text()
old = "- Threat feed import payloads are untrusted operator-supplied data.\n"
new = old + "- A configured Coraza sidecar is an external security-decision authority. Wardnet accepts it only over loopback, forwards a bounded credential-minimized request envelope, and treats malformed, oversized, uncorrelated, timed-out, or unreachable evidence as `engine_unavailable`; block-mode routes fail closed.\n"
if doc.count(old) != 1:
    raise SystemExit("threat-model trust-boundary seam changed")
doc = doc.replace(old, new, 1)
old_row = "| Gateway DoS | Availability loss | Rust memory safety, event retention limit | Rate limits, body limits, async event sink |"
new_row = old_row + "\n| WAF authority confusion or sidecar spoofing | Attack bypass or false block | Loopback-only Coraza sidecar, exact method/URI response correlation, bounded response/time, explicit `engine_unavailable` evidence | Pin/inventory production Coraza + CRS release identity and expose configuration through the Runtime Configuration owner lane |"
if doc.count(old_row) != 1:
    raise SystemExit("threat-model table seam changed")
threat.write_text(doc.replace(old_row, new_row, 1))

runbook = Path("docs/runbooks/operations.md")
doc = runbook.read_text()
old = "- In-process Coraza embedding (HTTP audit ingest at `POST /api/waf/coraza/audit` already fuses block hits into DNSBL/`client_ip` indicators for gateway enforcement)"
new = "- Package the live Coraza boundary: the code-level `ProvenEngineConfig` loopback sidecar port now evaluates matched requests and fails block mode closed on unusable configured-engine evidence, while Runtime Configuration still owns its deployment/bootstrap surface. Audit ingest at `POST /api/waf/coraza/audit` remains available for SOC evidence."
if doc.count(old) != 1:
    raise SystemExit("operations Coraza seam changed")
runbook.write_text(doc.replace(old, new, 1))
PY

cargo fmt
git diff --check
changed="$(git status --short | awk '{print $2}' | sort)"
expected="$(printf '%s\n' \
  docs/architecture.md \
  docs/doctoring/in-path-coraza-adapter.md \
  docs/runbooks/operations.md \
  docs/security/threat-model.md \
  src/lib.rs \
  src/proven_engine.rs \
  tests/coraza_live_enforcement.rs | sort)"
test "$changed" = "$expected"
