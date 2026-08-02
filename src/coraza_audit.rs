//! Coraza / ModSecurity-compatible WAF audit-log ingest adapter.
//!
//! Maps proven Coraza (or CRS-emitting WAF) audit JSON into gateway
//! security-event fields. This is an integration boundary — not a hand-rolled
//! rule engine. Run Coraza/OWASP CRS outside the process and POST audit logs
//! here for SOC visibility and buyer-lab evidence.

use std::net::IpAddr;

use crate::suricata_eve::parse_suricata_timestamp;

/// One WAF interruption / rule match extracted from a Coraza audit log record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorazaIngestedHit {
    pub client_ip: Option<IpAddr>,
    /// `block` or `monitor` (gateway enforcement vocabulary).
    pub action: String,
    pub reason: String,
    pub score: u16,
    pub path: String,
    pub timestamp_unix: Option<u64>,
}

/// Result of parsing a Coraza audit body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorazaAuditParseResult {
    pub hits: Vec<CorazaIngestedHit>,
    pub skipped: usize,
}

/// Parse a Coraza/ModSecurity audit body: single object, JSON array, or NDJSON.
pub fn parse_coraza_audit_body(body: &str) -> Result<CorazaAuditParseResult, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty Coraza audit body".to_string());
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(hits_from_json_value(&value));
    }

    let mut hits = Vec::new();
    let mut skipped = 0usize;
    let mut saw_json = false;
    for (idx, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                saw_json = true;
                if let Some(hit) = coraza_hit_from_value(&value) {
                    hits.push(hit);
                } else {
                    skipped += 1;
                }
            }
            Err(error) => {
                return Err(format!(
                    "invalid Coraza audit JSON on line {}: {error}",
                    idx + 1
                ));
            }
        }
    }
    if !saw_json {
        return Err("no Coraza audit JSON records found".to_string());
    }
    Ok(CorazaAuditParseResult { hits, skipped })
}

fn hits_from_json_value(value: &serde_json::Value) -> CorazaAuditParseResult {
    match value {
        serde_json::Value::Array(items) => {
            let mut hits = Vec::new();
            let mut skipped = 0usize;
            for item in items {
                if let Some(hit) = coraza_hit_from_value(item) {
                    hits.push(hit);
                } else {
                    skipped += 1;
                }
            }
            CorazaAuditParseResult { hits, skipped }
        }
        other => {
            if let Some(hit) = coraza_hit_from_value(other) {
                CorazaAuditParseResult {
                    hits: vec![hit],
                    skipped: 0,
                }
            } else {
                CorazaAuditParseResult {
                    hits: vec![],
                    skipped: 1,
                }
            }
        }
    }
}

/// Map one Coraza audit JSON object into a hit when it carries rule messages
/// or an interrupted/blocked transaction.
pub fn coraza_hit_from_value(value: &serde_json::Value) -> Option<CorazaIngestedHit> {
    // Prefer Coraza JSON audit shape: { transaction: {...}, messages: [...] }.
    let tx = value.get("transaction").unwrap_or(value);

    let messages = value
        .get("messages")
        .or_else(|| tx.get("messages"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    let interrupted = tx
        .get("is_interrupted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || tx
            .pointer("/response/http_code")
            .and_then(|v| v.as_u64())
            .is_some_and(|code| code == 403 || code == 406)
        || value
            .get("action")
            .and_then(|v| v.as_str())
            .is_some_and(|a| {
                let a = a.to_ascii_lowercase();
                a.contains("block") || a.contains("deny") || a.contains("drop")
            });

    if messages.is_empty() && !interrupted {
        return None;
    }

    let (rule_id, severity, msg_text) = primary_message(&messages);
    let reason = match (rule_id, msg_text.as_str()) {
        (Some(id), text) if !text.is_empty() => format!("coraza/crs: rule {id}: {text}"),
        (Some(id), _) => format!("coraza/crs: rule {id}"),
        (None, text) if !text.is_empty() => format!("coraza/crs: {text}"),
        _ => "coraza/crs: transaction interrupted".to_string(),
    };

    let score = match severity.unwrap_or(2) {
        0 | 1 => 80,
        2 => 50,
        _ => 25,
    };

    let action = if interrupted || score >= 50 {
        "block".to_string()
    } else {
        "monitor".to_string()
    };

    let client_ip = tx
        .get("client_ip")
        .or_else(|| tx.get("remote_address"))
        .or_else(|| value.get("client_ip"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<IpAddr>().ok());

    let path = tx
        .pointer("/request/uri")
        .or_else(|| tx.pointer("/request/http/uri"))
        .or_else(|| value.get("uri"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "coraza://transaction".to_string());

    let timestamp_unix = tx
        .get("time_stamp")
        .or_else(|| tx.get("timestamp"))
        .or_else(|| value.get("timestamp"))
        .and_then(|v| v.as_str())
        .and_then(parse_suricata_timestamp);

    Some(CorazaIngestedHit {
        client_ip,
        action,
        reason,
        score,
        path,
        timestamp_unix,
    })
}

fn primary_message(messages: &[serde_json::Value]) -> (Option<u64>, Option<u8>, String) {
    let first = messages.first();
    let Some(first) = first else {
        return (None, None, String::new());
    };
    let data = first.get("data").unwrap_or(first);
    let rule_id = data
        .get("id")
        .or_else(|| first.get("id"))
        .and_then(|v| v.as_u64());
    let severity = data
        .get("severity")
        .or_else(|| first.get("severity"))
        .and_then(|v| v.as_u64())
        .map(|s| s.clamp(0, 7) as u8);
    let text = first
        .get("message")
        .or_else(|| data.get("msg"))
        .or_else(|| first.get("msg"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    (rule_id, severity, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn maps_coraza_audit_with_crs_message_to_block() {
        let raw = r#"{
          "transaction": {
            "client_ip": "203.0.113.77",
            "time_stamp": "2024-06-15T12:34:56+0000",
            "is_interrupted": true,
            "request": { "uri": "/search?q=1'+OR+1=1" },
            "response": { "http_code": 403 }
          },
          "messages": [
            {
              "message": "SQL Injection Attack Detected via libinjection",
              "data": { "id": 942100, "severity": 2, "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" }
            }
          ]
        }"#;
        let hit = coraza_hit_from_value(&serde_json::from_str(raw).unwrap()).unwrap();
        assert_eq!(hit.action, "block");
        assert_eq!(hit.score, 50);
        assert_eq!(
            hit.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)))
        );
        assert_eq!(hit.path, "/search?q=1'+OR+1=1");
        assert!(hit.reason.contains("942100"));
        assert!(hit.reason.contains("SQL Injection"));
        assert_eq!(hit.timestamp_unix, Some(1_718_454_896));
    }

    #[test]
    fn skips_benign_transaction_without_messages() {
        let raw = r#"{"transaction":{"client_ip":"203.0.113.1","request":{"uri":"/"},"response":{"http_code":200}}}"#;
        assert!(coraza_hit_from_value(&serde_json::from_str(raw).unwrap()).is_none());
    }

    #[test]
    fn parses_ndjson_mixed_batch() {
        let body = r#"
{"transaction":{"client_ip":"198.51.100.2","request":{"uri":"/ok"},"response":{"http_code":200}}}
{"transaction":{"client_ip":"198.51.100.3","is_interrupted":true,"request":{"uri":"/admin"},"response":{"http_code":403}},"messages":[{"message":"Access denied","data":{"id":949110,"severity":2}}]}
"#;
        let parsed = parse_coraza_audit_body(body).unwrap();
        assert_eq!(parsed.hits.len(), 1);
        assert_eq!(parsed.skipped, 1);
        assert_eq!(parsed.hits[0].path, "/admin");
    }

    #[test]
    fn rejects_empty_body() {
        assert!(parse_coraza_audit_body(" \n").is_err());
    }

    #[test]
    fn parse_never_panics_on_arbitrary_text() {
        for sample in ["", "{", "[]", "null", "\0", "{\"messages\":[]}"] {
            let _ = parse_coraza_audit_body(sample);
        }
    }
}
