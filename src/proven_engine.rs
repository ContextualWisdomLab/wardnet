//! In-path Coraza sidecar adapter (issue #86).
//!
//! Wardnet does not reimplement OWASP CRS. When a sidecar URL is configured,
//! each gateway transaction is POSTed there and the response is parsed with
//! the existing Coraza audit adapter. Unreachable engines are either
//! fail-closed or explicitly degraded — never a silent ruleset skip.

use std::net::IpAddr;
use std::time::Duration;

use crate::coraza_audit::{CorazaIngestedHit, parse_coraza_audit_body};

/// Sidecar HTTP timeout. Bounded so a hung WAF cannot stall the gateway.
pub const SIDECAR_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Operator-configured Coraza sidecar consult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenEngineConfig {
    /// Full HTTP URL of the Coraza evaluate endpoint. `None` keeps ingest-hint
    /// enforcement only.
    pub sidecar_url: Option<String>,
    /// When true, a configured sidecar that is unreachable or denied by
    /// destination policy fails the transaction (503) instead of falling back
    /// to builtin scoring.
    pub fail_closed: bool,
}

impl ProvenEngineConfig {
    /// No sidecar; gateway scoring uses ingest hints and builtin signatures.
    pub fn disabled() -> Self {
        Self {
            sidecar_url: None,
            fail_closed: false,
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
        }
    }

    /// True when a non-empty sidecar URL is configured.
    pub fn in_path(&self) -> bool {
        self.sidecar_url
            .as_deref()
            .is_some_and(|url| !url.trim().is_empty())
    }

    /// Operator-visible mode label (`coraza_sidecar` or `ingest_hints_only`).
    pub fn mode(&self) -> &'static str {
        if self.in_path() {
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
) -> serde_json::Value {
    let mut request = serde_json::json!({
        "method": method,
        "uri": uri,
    });
    if !body.is_empty() {
        request["body"] = serde_json::Value::String(body.to_string());
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

/// POST one transaction to the Coraza sidecar and parse the audit response.
pub async fn evaluate_sidecar(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    uri: &str,
    body: &str,
    client_ip: Option<IpAddr>,
) -> ProvenEngineOutcome {
    let payload = sidecar_request_body(method, uri, body, client_ip);
    match client
        .post(url)
        .json(&payload)
        .timeout(SIDECAR_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            match response.text().await {
                Ok(text) => {
                    if status.is_server_error() {
                        return ProvenEngineOutcome::Unavailable {
                            reason: format!("coraza sidecar HTTP {status}"),
                        };
                    }
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
                Err(error) => ProvenEngineOutcome::Unavailable {
                    reason: sidecar_transport_reason(&error),
                },
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
        assert_eq!(config.mode(), "coraza_sidecar");
        assert!(config.fail_closed);
        assert_eq!(
            config.sidecar_url.as_deref(),
            Some("http://127.0.0.1:9000/waf")
        );
    }

    #[test]
    fn sidecar_request_body_includes_method_uri_and_optional_body() {
        let json = sidecar_request_body(
            "POST",
            "/search?q=1",
            "a=b",
            Some("203.0.113.9".parse().unwrap()),
        );
        assert_eq!(json["transaction"]["request"]["method"], "POST");
        assert_eq!(json["transaction"]["request"]["uri"], "/search?q=1");
        assert_eq!(json["transaction"]["request"]["body"], "a=b");
        assert_eq!(json["transaction"]["client_ip"], "203.0.113.9");
        let get = sidecar_request_body("GET", "/demo", "", None);
        assert!(get["transaction"]["request"].get("body").is_none());
        assert!(get["transaction"].get("client_ip").is_none());
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
