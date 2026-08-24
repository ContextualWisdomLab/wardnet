//! In-path Coraza adapter (issue #86).
//!
//! Wardnet does not reimplement OWASP CRS. Live `/gateway` transactions are
//! evaluated by a proven engine in this order:
//!
//! 1. In-process libcoraza (`CORAZA_LIB_PATH`) when loaded.
//! 2. Otherwise an HTTP sidecar (`CORAZA_WAF_URL`) parsed with the existing
//!    Coraza audit adapter.
//!
//! Unreachable engines are either fail-closed or explicitly degraded — never
//! a silent ruleset skip.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::coraza_audit::{CorazaIngestedHit, parse_coraza_audit_body};
use crate::coraza_inprocess::InProcessCoraza;

/// Sidecar HTTP timeout. Bounded so a hung WAF cannot stall the gateway.
pub const SIDECAR_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Operator-configured Coraza sidecar and/or in-process libcoraza consult.
#[derive(Debug, Clone)]
pub struct ProvenEngineConfig {
    /// Full HTTP URL of the Coraza evaluate endpoint. `None` keeps ingest-hint
    /// enforcement only when in-process libcoraza is also unset.
    pub sidecar_url: Option<String>,
    /// When true, a configured engine that is unreachable or denied by
    /// destination policy fails the transaction (503) instead of falling back
    /// to builtin scoring.
    pub fail_closed: bool,
    /// Loaded libcoraza instance. When set, live transactions evaluate here
    /// and the sidecar is not consulted.
    pub in_process: Option<Arc<InProcessCoraza>>,
}

impl ProvenEngineConfig {
    /// No sidecar and no in-process engine; gateway scoring uses ingest hints
    /// and builtin signatures.
    pub fn disabled() -> Self {
        Self {
            sidecar_url: None,
            fail_closed: false,
            in_process: None,
        }
    }

    /// Live sidecar consult for `url`. Empty/whitespace URLs are treated as unset.
    pub fn sidecar(url: impl Into<String>, fail_closed: bool) -> Self {
        let trimmed = url.into();
        let sidecar_url = if trimmed.trim().is_empty() {
            None
        } else {
            Some(trimmed)
        };
        Self {
            sidecar_url,
            fail_closed,
            in_process: None,
        }
    }

    /// In-process libcoraza. Sidecar URL is left unset.
    pub fn in_process(engine: Arc<InProcessCoraza>, fail_closed: bool) -> Self {
        Self {
            sidecar_url: None,
            fail_closed,
            in_process: Some(engine),
        }
    }

    /// True when a non-empty sidecar URL is configured.
    pub fn sidecar_configured(&self) -> bool {
        self.sidecar_url
            .as_deref()
            .is_some_and(|url| !url.trim().is_empty())
    }

    /// True when in-process libcoraza or a sidecar is configured.
    pub fn in_path(&self) -> bool {
        self.in_process.is_some() || self.sidecar_configured()
    }

    /// Operator-visible mode label.
    pub fn mode(&self) -> &'static str {
        if self.in_process.is_some() {
            "coraza_in_process"
        } else if self.sidecar_configured() {
            "coraza_sidecar"
        } else {
            "ingest_hints_only"
        }
    }
}

/// Outcome of one sidecar consult for a live HTTP transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenEngineOutcome {
    /// No sidecar URL is configured.
    NotConfigured,
    /// Sidecar returned a transaction with no CRS interruption.
    Clean,
    /// Sidecar returned a Coraza/CRS hit.
    Hit(CorazaIngestedHit),
    /// Sidecar was unreachable, denied, or returned an unusable body.
    Unavailable { reason: String },
}

/// Compact Coraza-shaped transaction envelope sent to the sidecar.
pub fn sidecar_request_body(
    method: &str,
    uri: &str,
    body: &str,
    client_ip: Option<IpAddr>,
    headers: &[(String, String)],
) -> serde_json::Value {
    let mut request = serde_json::json!({
        "method": method,
        "uri": uri,
    });
    if !body.is_empty() {
        request["body"] = serde_json::Value::String(body.to_string());
    }
    if !headers.is_empty() {
        request["headers"] = serde_json::Value::Array(
            headers
                .iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect(),
        );
    }
    let mut transaction = serde_json::json!({ "request": request });
    if let Some(ip) = client_ip {
        transaction["client_ip"] = serde_json::Value::String(ip.to_string());
    }
    serde_json::json!({ "transaction": transaction })
}

/// Map a sidecar response body onto a proven-engine outcome.
///
/// Empty bodies are clean (sidecar had nothing to add). Invalid JSON is
/// unavailable so fail-closed deployments do not treat parser failure as allow.
pub fn outcome_from_sidecar_body(body: &str) -> ProvenEngineOutcome {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return ProvenEngineOutcome::Clean;
    }
    match parse_coraza_audit_body(trimmed) {
        Ok(mut parsed) => {
            if parsed.hits.is_empty() {
                ProvenEngineOutcome::Clean
            } else {
                let idx = parsed
                    .hits
                    .iter()
                    .position(|hit| hit.action == "block")
                    .unwrap_or(0);
                ProvenEngineOutcome::Hit(parsed.hits.swap_remove(idx))
            }
        }
        Err(reason) => ProvenEngineOutcome::Unavailable { reason },
    }
}

/// Reason strings for transport errors. Never includes the sidecar URL.
pub fn sidecar_transport_reason(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "coraza sidecar timeout".to_string()
    } else if error.is_connect() {
        "coraza sidecar unreachable".to_string()
    } else {
        "coraza sidecar request failed".to_string()
    }
}

/// Upper bound for a sidecar response body. Audit JSON for one transaction is
/// far below this; anything larger is treated as a transport anomaly so a
/// runaway sidecar cannot buffer unbounded memory per request.
pub const SIDECAR_MAX_BODY_BYTES: usize = 1_048_576;

/// Maximum number of client headers forwarded to a proven engine.
pub const FORWARDED_HEADER_LIMIT: usize = 32;

/// Maximum total bytes of forwarded header names + values.
pub const FORWARDED_HEADERS_MAX_BYTES: usize = 8_192;

/// Bounded allowlist of request headers forwarded to Coraza. `Authorization`
/// is deliberately absent: credentials must not leave the gateway into sidecar
/// logs, and CRS coverage for it does not justify the exposure.
pub fn engine_forwarded_headers(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
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
        "cookie",
    ];
    let mut forwarded: Vec<(String, String)> = Vec::new();
    let mut total = 0usize;
    for name in allowlist {
        for value in headers.get_all(name) {
            if forwarded.len() >= FORWARDED_HEADER_LIMIT {
                return forwarded;
            }
            let Ok(value) = value.to_str() else {
                continue;
            };
            total += name.len() + value.len();
            if total > FORWARDED_HEADERS_MAX_BYTES {
                return forwarded;
            }
            forwarded.push((name.to_ascii_lowercase(), value.to_string()));
        }
    }
    forwarded
}

async fn bounded_sidecar_text(response: reqwest::Response) -> Result<String, String> {
    if let Some(length) = response.content_length()
        && length as usize > SIDECAR_MAX_BODY_BYTES
    {
        return Err(format!(
            "coraza sidecar response exceeds {SIDECAR_MAX_BODY_BYTES} bytes"
        ));
    }
    let mut response = response;
    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| sidecar_transport_reason(&error))?
    {
        if buffer.len().saturating_add(chunk.len()) > SIDECAR_MAX_BODY_BYTES {
            return Err(format!(
                "coraza sidecar response exceeds {SIDECAR_MAX_BODY_BYTES} bytes"
            ));
        }
        buffer.extend_from_slice(&chunk);
    }
    String::from_utf8(buffer).map_err(|_| "coraza sidecar response was not UTF-8".to_string())
}

/// POST one transaction to the Coraza sidecar and parse the audit response.
///
/// Status contract: 2xx carries audit JSON (an empty body stays clean), 403
/// without parseable audit JSON is still an interruption, and every other
/// status is `Unavailable` so fail-closed deployments never treat a confused
/// sidecar answer as allow.
pub async fn evaluate_sidecar(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    uri: &str,
    body: &str,
    client_ip: Option<IpAddr>,
    headers: &[(String, String)],
) -> ProvenEngineOutcome {
    let payload = sidecar_request_body(method, uri, body, client_ip, headers);
    match client
        .post(url)
        .json(&payload)
        .timeout(SIDECAR_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if !status.is_success() && status.as_u16() != 403 {
                return ProvenEngineOutcome::Unavailable {
                    reason: format!("coraza sidecar HTTP {status}"),
                };
            }
            match bounded_sidecar_text(response).await {
                Ok(text) => {
                    let outcome = outcome_from_sidecar_body(&text);
                    if matches!(outcome, ProvenEngineOutcome::Clean) && status.as_u16() == 403 {
                        ProvenEngineOutcome::Hit(CorazaIngestedHit {
                            client_ip,
                            action: "block".to_string(),
                            reason: "coraza/crs: transaction interrupted".to_string(),
                            score: 50,
                            path: uri.to_string(),
                            timestamp_unix: None,
                        })
                    } else {
                        outcome
                    }
                }
                Err(reason) => ProvenEngineOutcome::Unavailable { reason },
            }
        }
        Err(error) => ProvenEngineOutcome::Unavailable {
            reason: sidecar_transport_reason(&error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;

    #[test]
    fn disabled_config_is_ingest_hints_only() {
        let config = ProvenEngineConfig::disabled();
        assert!(!config.in_path());
        assert_eq!(config.mode(), "ingest_hints_only");
        assert!(!config.fail_closed);
        let blank = ProvenEngineConfig::sidecar("  ", true);
        assert!(!blank.in_path());
        assert_eq!(blank.mode(), "ingest_hints_only");
    }

    #[test]
    fn sidecar_config_is_in_path() {
        let config = ProvenEngineConfig::sidecar("http://127.0.0.1:9000/waf", true);
        assert!(config.in_path());
        assert!(config.sidecar_configured());
        assert_eq!(config.mode(), "coraza_sidecar");
        assert!(config.fail_closed);
        assert_eq!(
            config.sidecar_url.as_deref(),
            Some("http://127.0.0.1:9000/waf")
        );
    }

    #[test]
    fn in_process_config_wins_mode_label() {
        let engine = crate::coraza_inprocess::load_stub_engine();
        let config = ProvenEngineConfig::in_process(engine, true);
        assert!(config.in_path());
        assert!(!config.sidecar_configured());
        assert_eq!(config.mode(), "coraza_in_process");
        assert!(config.fail_closed);
    }

    #[test]
    fn sidecar_request_body_includes_method_uri_and_optional_body() {
        let json = sidecar_request_body(
            "POST",
            "/search?q=1",
            "a=b",
            Some("203.0.113.9".parse().unwrap()),
            &[
                ("host".to_string(), "wardnet.example".to_string()),
                ("user-agent".to_string(), "sqlmap/1.8".to_string()),
            ],
        );
        assert_eq!(json["transaction"]["request"]["method"], "POST");
        assert_eq!(json["transaction"]["request"]["uri"], "/search?q=1");
        assert_eq!(json["transaction"]["request"]["body"], "a=b");
        assert_eq!(json["transaction"]["client_ip"], "203.0.113.9");
        let headers = json["transaction"]["request"]["headers"]
            .as_array()
            .unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0]["name"], "host");
        assert_eq!(headers[1]["value"], "sqlmap/1.8");
        let get = sidecar_request_body("GET", "/demo", "", None, &[]);
        assert!(get["transaction"]["request"].get("body").is_none());
        assert!(get["transaction"].get("client_ip").is_none());
        assert!(get["transaction"]["request"].get("headers").is_none());
    }

    #[test]
    fn forwarded_header_allowlist_is_bounded_and_skips_credentials() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("Host", "wardnet.example".parse().unwrap());
        headers.insert("User-Agent", "curl/8".parse().unwrap());
        headers.insert("Cookie", "session=abc".parse().unwrap());
        headers.insert("Authorization", "Bearer secret".parse().unwrap());

        let forwarded = engine_forwarded_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["host", "user-agent", "cookie"]);

        let mut oversized = axum::http::HeaderMap::new();
        let big_value = "x".repeat(FORWARDED_HEADERS_MAX_BYTES + 1);
        oversized.insert("User-Agent", big_value.parse().unwrap());
        assert!(
            engine_forwarded_headers(&oversized).is_empty(),
            "oversized header values must forward nothing"
        );
    }

    #[tokio::test]
    async fn sidecar_non_success_status_is_unavailable() {
        let app =
            axum::Router::new().route("/", post(|| async { (StatusCode::NOT_FOUND, "nope") }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        let client = reqwest::Client::new();
        match evaluate_sidecar(
            &client,
            &format!("http://{addr}/"),
            "GET",
            "/app?q=hello",
            "",
            None,
            &[],
        )
        .await
        {
            ProvenEngineOutcome::Unavailable { reason } => {
                assert!(reason.contains("404"), "{reason}");
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sidecar_oversized_response_is_unavailable() {
        let big = "x".repeat(SIDECAR_MAX_BODY_BYTES + 1);
        let app = axum::Router::new().route(
            "/",
            post(move || {
                let big = big.clone();
                async move { (StatusCode::OK, big) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        let client = reqwest::Client::new();
        match evaluate_sidecar(
            &client,
            &format!("http://{addr}/"),
            "GET",
            "/app?q=hello",
            "",
            None,
            &[],
        )
        .await
        {
            ProvenEngineOutcome::Unavailable { reason } => {
                assert!(reason.contains("exceeds"), "{reason}");
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn empty_sidecar_body_is_clean() {
        assert_eq!(
            outcome_from_sidecar_body("  \n"),
            ProvenEngineOutcome::Clean
        );
    }

    #[test]
    fn interrupted_audit_json_is_a_block_hit() {
        let raw = r#"{
          "transaction": {
            "is_interrupted": true,
            "request": { "uri": "/search?crs-probe=1" },
            "response": { "http_code": 403 }
          },
          "messages": [
            {
              "message": "SQL Injection Attack Detected via libinjection",
              "data": { "id": 942100, "severity": 2 }
            }
          ]
        }"#;
        match outcome_from_sidecar_body(raw) {
            ProvenEngineOutcome::Hit(hit) => {
                assert_eq!(hit.action, "block");
                assert!(hit.reason.contains("942100"));
                assert_eq!(hit.path, "/search?crs-probe=1");
                assert!(hit.score >= 50);
            }
            other => panic!("expected hit, got {other:?}"),
        }
    }

    #[test]
    fn clean_audit_json_without_messages_is_clean() {
        let raw =
            r#"{"transaction":{"is_interrupted":false,"request":{"uri":"/demo"}},"messages":[]}"#;
        assert_eq!(outcome_from_sidecar_body(raw), ProvenEngineOutcome::Clean);
    }

    #[test]
    fn invalid_sidecar_json_is_unavailable() {
        match outcome_from_sidecar_body("not-json {") {
            ProvenEngineOutcome::Unavailable { reason } => {
                assert!(reason.contains("Coraza") || reason.contains("JSON"));
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }
}
