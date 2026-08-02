//! STIX 2.x indicator import adapter.
//!
//! Parses STIX Indicator objects (standalone, array, or Bundle) into gateway
//! [`ThreatIndicator`] / [`DnsblEntry`] rows. This is a proven threat-intel
//! format boundary — not a hand-rolled detection engine. TAXII collection
//! polling remains a follow-up; operators POST STIX documents here.

use std::net::IpAddr;

use waf_ids_core::{DnsblEntry, Severity, ThreatIndicator};

/// Parsed STIX import ready for the existing threat-feed upsert path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StixImportMaterial {
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
    pub skipped_objects: usize,
}

/// Extract indicators from a STIX 2.x JSON document (bundle, indicator, or array).
pub fn stix_material_from_value(
    value: &serde_json::Value,
    source: &str,
    ttl_seconds: u64,
) -> Result<StixImportMaterial, String> {
    let mut threats = Vec::new();
    let mut dnsbl = Vec::new();
    let mut skipped_objects = 0usize;

    let objects: Vec<&serde_json::Value> = match value {
        serde_json::Value::Array(items) => items.iter().collect(),
        obj if obj.get("type").and_then(|t| t.as_str()) == Some("bundle") => obj
            .get("objects")
            .and_then(|o| o.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default(),
        obj if obj.get("type").and_then(|t| t.as_str()) == Some("indicator") => {
            vec![obj]
        }
        _ => {
            return Err(
                "STIX document must be a bundle, an indicator, or an array of STIX objects"
                    .to_string(),
            );
        }
    };

    if objects.is_empty() {
        return Err("STIX document contained no objects".to_string());
    }

    for obj in objects {
        let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if obj_type != "indicator" {
            skipped_objects += 1;
            continue;
        }
        let pattern = obj
            .get("pattern")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .trim();
        if pattern.is_empty() {
            skipped_objects += 1;
            continue;
        }
        let name = obj
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("stix-indicator");
        let severity = severity_from_stix(obj);
        let extracted = extract_pattern_observables(pattern);
        if extracted.is_empty() {
            skipped_objects += 1;
            continue;
        }
        for (kind, value) in extracted {
            match kind.as_str() {
                "ipv4-addr" | "ipv6-addr" => {
                    if let Ok(ip) = value.parse::<IpAddr>() {
                        dnsbl.push(DnsblEntry {
                            address: ip,
                            code: "127.0.0.2".to_string(),
                            reason: format!("stix:{name}"),
                            source: source.to_string(),
                            ttl_seconds,
                            prefix_len: None,
                        });
                        threats.push(ThreatIndicator {
                            value: ip.to_string(),
                            indicator_type: "client_ip".to_string(),
                            severity: severity.clone(),
                            source: source.to_string(),
                            ttl_seconds,
                        });
                    } else {
                        skipped_objects += 1;
                    }
                }
                "domain-name" | "hostname" => {
                    threats.push(ThreatIndicator {
                        value: value.to_ascii_lowercase(),
                        indicator_type: "domain".to_string(),
                        severity: severity.clone(),
                        source: source.to_string(),
                        ttl_seconds,
                    });
                }
                "url" => {
                    threats.push(ThreatIndicator {
                        value: value.clone(),
                        indicator_type: "url".to_string(),
                        severity: severity.clone(),
                        source: source.to_string(),
                        ttl_seconds,
                    });
                }
                other => {
                    threats.push(ThreatIndicator {
                        value,
                        indicator_type: other.to_string(),
                        severity: severity.clone(),
                        source: source.to_string(),
                        ttl_seconds,
                    });
                }
            }
        }
    }

    if threats.is_empty() && dnsbl.is_empty() {
        return Err(
            "no STIX indicator patterns could be mapped (supported: ipv4-addr, ipv6-addr, domain-name, hostname, url)"
                .to_string(),
        );
    }

    Ok(StixImportMaterial {
        threats,
        dnsbl,
        skipped_objects,
    })
}

/// Parse a STIX JSON body string.
pub fn parse_stix_document(
    body: &str,
    source: &str,
    ttl_seconds: u64,
) -> Result<StixImportMaterial, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty STIX body".to_string());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|error| format!("invalid STIX JSON: {error}"))?;
    stix_material_from_value(&value, source, ttl_seconds)
}

fn severity_from_stix(obj: &serde_json::Value) -> Severity {
    // Optional STIX 2.1 confidence 0-100 → severity bands.
    match obj.get("confidence").and_then(|c| c.as_u64()).unwrap_or(50) {
        0..=24 => Severity::Low,
        25..=49 => Severity::Medium,
        50..=74 => Severity::High,
        _ => Severity::Critical,
    }
}

/// Extract `(sco_type, value)` pairs from a STIX pattern string.
/// Supports simple equality comparisons used by most indicator feeds.
fn extract_pattern_observables(pattern: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Match: [type:value = 'literal'] or [type:value = "literal"]
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some((kind, value, next)) = parse_bracket_comparison(&pattern[i..])
        {
            out.push((kind, value));
            i += next;
            continue;
        }
        i += 1;
    }
    out
}

fn parse_bracket_comparison(s: &str) -> Option<(String, String, usize)> {
    // s starts with '['
    let end = s.find(']')?;
    let inner = s[1..end].trim();
    // type:property = 'value'
    let eq = inner.find('=')?;
    let left = inner[..eq].trim();
    let right = inner[eq + 1..].trim();
    let sco_type = left.split(':').next()?.trim();
    if sco_type.is_empty() {
        return None;
    }
    let value = unquote_stix_string(right)?;
    if value.is_empty() {
        return None;
    }
    Some((sco_type.to_string(), value, end + 1))
}

fn unquote_stix_string(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 {
        let b = s.as_bytes();
        if (b[0] == b'\'' && b[s.len() - 1] == b'\'') || (b[0] == b'"' && b[s.len() - 1] == b'"') {
            return Some(s[1..s.len() - 1].to_string());
        }
    }
    // Unquoted token (rare)
    if !s.is_empty() && !s.contains(char::is_whitespace) {
        return Some(s.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn maps_stix_bundle_ipv4_and_domain() {
        let raw = r#"{
          "type": "bundle",
          "id": "bundle--11111111-1111-4111-8111-111111111111",
          "objects": [
            {
              "type": "indicator",
              "id": "indicator--22222222-2222-4222-8222-222222222222",
              "name": "malicious host",
              "pattern": "[ipv4-addr:value = '203.0.113.66']",
              "pattern_type": "stix",
              "valid_from": "2024-01-01T00:00:00Z",
              "confidence": 80
            },
            {
              "type": "indicator",
              "id": "indicator--33333333-3333-4333-8333-333333333333",
              "name": "phish domain",
              "pattern": "[domain-name:value = 'evil.example']",
              "pattern_type": "stix",
              "valid_from": "2024-01-01T00:00:00Z",
              "confidence": 60
            },
            {
              "type": "malware",
              "id": "malware--44444444-4444-4444-8444-444444444444",
              "name": "ignored"
            }
          ]
        }"#;
        let material = parse_stix_document(raw, "stix:test", 3600).unwrap();
        assert_eq!(material.skipped_objects, 1);
        assert!(
            material
                .dnsbl
                .iter()
                .any(|d| d.address == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66)))
        );
        assert!(
            material
                .threats
                .iter()
                .any(|t| t.indicator_type == "domain" && t.value == "evil.example")
        );
        assert!(
            material
                .threats
                .iter()
                .any(|t| t.indicator_type == "client_ip" && t.value == "203.0.113.66")
        );
    }

    #[test]
    fn extracts_url_pattern() {
        let pattern = "[url:value = 'http://evil.example/login']";
        let pairs = extract_pattern_observables(pattern);
        assert_eq!(
            pairs,
            vec![("url".to_string(), "http://evil.example/login".to_string())]
        );
    }

    #[test]
    fn rejects_empty_and_non_stix() {
        assert!(parse_stix_document("", "s", 60).is_err());
        assert!(parse_stix_document("{\"type\":\"report\"}", "s", 60).is_err());
    }
}
