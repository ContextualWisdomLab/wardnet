//! Live Coraza/OWASP CRS request-evaluation boundary.
//!
//! Wardnet owns the route/policy decision, not WAF signatures. This
//! adapter sends a bounded, credential-minimized request envelope to a
//! same-host Coraza sidecar and accepts only response evidence that is
//! correlated to the exact method/URI. It deliberately does not
//! implement CRS rules or general-purpose egress policy.

use std::{borrow::Cow, net::IpAddr, sync::OnceLock, time::Duration};

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
    Clean,
    Hit(CorazaIngestedHit),
    Unavailable { reason: String },
}

fn validate_loopback_sidecar_url(url: &str) -> Result<(), String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|error| format!("invalid Coraza sidecar URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Coraza sidecar URL must use http or https".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Coraza sidecar URL requires a host".to_string())?;
    let numeric_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost")
        || numeric_host
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
) -> Result<Vec<(String, String)>, String> {
    let allowlist = [
        "host",
        "user-agent",
        "accept",
        "content-type",
        "referer",
        "origin",
        "x-requested-with",
    ];
    let mut forwarded = Vec::new();
    let mut total = 0usize;
    for name in allowlist {
        for value in headers.get_all(name) {
            if forwarded.len() >= FORWARDED_HEADER_LIMIT {
                return Err(format!(
                    "Coraza request header envelope exceeds {FORWARDED_HEADER_LIMIT} fields"
                ));
            }
            let value = value
                .to_str()
                .map_err(|_| format!("Coraza allowlisted request header {name} is not UTF-8"))?;
            let next = total.saturating_add(name.len()).saturating_add(value.len());
            if next > FORWARDED_HEADERS_MAX_BYTES {
                return Err(format!(
                    "Coraza request header envelope exceeds {FORWARDED_HEADERS_MAX_BYTES} bytes"
                ));
            }
            total = next;
            forwarded.push((name.to_string(), value.to_string()));
        }
    }
    Ok(forwarded)
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
    let explicitly_not_interrupted =
        tx.get("is_interrupted").and_then(|value| value.as_bool()) == Some(false);
    let status = tx
        .pointer("/response/http_code")
        .or_else(|| tx.pointer("/response/status"))
        .and_then(|value| value.as_u64());
    let messages = value
        .get("messages")
        .or_else(|| tx.get("messages"))
        .and_then(|value| value.as_array());
    explicitly_not_interrupted
        && status.is_some_and(|code| code < 400)
        && messages.is_some_and(|items| items.is_empty())
}

fn response_proves_disruption(
    value: &serde_json::Value,
    sidecar_status: reqwest::StatusCode,
) -> bool {
    if matches!(sidecar_status.as_u16(), 403 | 406) {
        return true;
    }
    let tx = value.get("transaction").unwrap_or(value);
    tx.get("is_interrupted").and_then(|value| value.as_bool()) == Some(true)
        || tx
            .pointer("/response/http_code")
            .or_else(|| tx.pointer("/response/status"))
            .and_then(|value| value.as_u64())
            .is_some_and(|code| matches!(code, 403 | 406))
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
            let disruptive = response_proves_disruption(&value, status);
            let idx = parsed
                .hits
                .iter()
                .position(|hit| hit.action == "block")
                .unwrap_or(0);
            let mut hit = parsed.hits.swap_remove(idx);
            hit.reason = format!("{}; {suffix}", hit.reason);
            hit.action = if disruptive { "block" } else { "monitor" }.to_string();
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
            reason: "Coraza sidecar evidence did not prove a clean or interrupted transaction"
                .to_string(),
        },
        Err(reason) => ProvenEngineOutcome::Unavailable {
            reason: format!("Coraza sidecar audit evidence invalid: {reason}"),
        },
    }
}

pub(crate) struct SidecarEvaluation<'request, 'body> {
    pub(crate) method: &'request str,
    pub(crate) uri: &'request str,
    pub(crate) body: &'request Cow<'body, str>,
    pub(crate) client_ip: Option<IpAddr>,
    pub(crate) headers: &'request axum::http::HeaderMap,
    pub(crate) policy_id: &'request str,
}

fn loopback_sidecar_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("failed to build isolated Coraza sidecar client")
    })
}

pub(crate) async fn evaluate_sidecar(
    _client: &reqwest::Client,
    config: &ProvenEngineConfig,
    request: SidecarEvaluation<'_, '_>,
) -> ProvenEngineOutcome {
    let Some(url) = config.sidecar_url() else {
        return ProvenEngineOutcome::Unavailable {
            reason: "Coraza proven engine is not configured".to_string(),
        };
    };
    // `String::from_utf8_lossy` returns a borrowed Cow only when the original
    // request bytes are valid UTF-8. Preserve valid text exactly, including a
    // literal U+FFFD, but refuse the owned replacement produced for invalid
    // bytes so Coraza can never authorize a lossy projection.
    if matches!(request.body, &Cow::Owned(_)) {
        return ProvenEngineOutcome::Unavailable {
            reason: "Wardnet cannot prove the Coraza v1 request body is byte-exact because the UTF-8 projection was lossy"
                .to_string(),
        };
    }
    let body = request.body.as_ref();
    let forwarded_headers = match engine_forwarded_headers(request.headers) {
        Ok(headers) => headers,
        Err(reason) => return ProvenEngineOutcome::Unavailable { reason },
    };
    let payload = sidecar_request_body(
        request.method,
        request.uri,
        body,
        request.client_ip,
        &forwarded_headers,
        request.policy_id,
    );
    let response = match loopback_sidecar_client()
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
    outcome_from_sidecar_response(
        status,
        &body,
        request.method,
        request.uri,
        request.client_ip,
        request.policy_id,
    )
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
        let forwarded = engine_forwarded_headers(&headers).expect("complete bounded headers");
        let names: Vec<&str> = forwarded.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["host", "user-agent"]);

        let mut oversized = HeaderMap::new();
        oversized.insert(
            "user-agent",
            HeaderValue::from_str(&"x".repeat(FORWARDED_HEADERS_MAX_BYTES + 1)).unwrap(),
        );
        assert!(engine_forwarded_headers(&oversized).is_err());

        let mut opaque = HeaderMap::new();
        opaque.insert("user-agent", HeaderValue::from_bytes(&[0x80]).unwrap());
        assert!(engine_forwarded_headers(&opaque).is_err());
    }

    #[test]
    fn clean_evidence_requires_exact_request_correlation() {
        let clean = r#"{
          "transaction": {
            "is_interrupted": false,
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
