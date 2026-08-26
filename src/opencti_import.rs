//! OpenCTI observable / indicator import adapter.
//!
//! Parses common OpenCTI JSON exports into gateway [`ThreatIndicator`] /
//! [`DnsblEntry`] rows:
//! - GraphQL-style `data.stixCyberObservables.edges[].node`
//! - GraphQL-style `data.indicators.edges[].node` (STIX pattern or value)
//! - Flat arrays / `{ "entities": [...] }` list exports
//! - STIX 2.x bundles (delegated to the STIX importer)
//!
//! This is a proven threat-intel platform boundary — not a hand-rolled
//! detection engine. Live OpenCTI GraphQL pull remains a follow-up; operators
//! POST export documents here.

use std::net::IpAddr;

use wardnet_core::{DnsblEntry, Severity, ThreatIndicator};

use crate::stix_import;

/// Parsed OpenCTI import ready for the existing threat-feed upsert path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCtiImportMaterial {
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
    pub skipped_objects: usize,
}

/// Extract indicators from an OpenCTI JSON document.
pub fn opencti_material_from_value(
    value: &serde_json::Value,
    source: &str,
    ttl_seconds: u64,
) -> Result<OpenCtiImportMaterial, String> {
    // Prefer pure STIX when the document already is a STIX bundle/indicator.
    if is_stix_document(value) {
        let material = stix_import::stix_material_from_value(value, source, ttl_seconds)?;
        return Ok(OpenCtiImportMaterial {
            threats: material.threats,
            dnsbl: material.dnsbl,
            skipped_objects: material.skipped_objects,
        });
    }

    let mut threats = Vec::new();
    let mut dnsbl = Vec::new();
    let mut skipped_objects = 0usize;
    let mut nodes: Vec<&serde_json::Value> = Vec::new();

    collect_opencti_nodes(value, &mut nodes, &mut skipped_objects);

    if nodes.is_empty() {
        return Err(
            "OpenCTI document must include observables, indicators, entities, or STIX objects"
                .to_string(),
        );
    }

    for node in nodes {
        match materialize_node(node, source, ttl_seconds) {
            NodeOutcome::Mapped {
                threats: t,
                dnsbl: d,
            } => {
                threats.extend(t);
                dnsbl.extend(d);
            }
            NodeOutcome::Skipped => skipped_objects += 1,
        }
    }

    if threats.is_empty() && dnsbl.is_empty() {
        return Err(
            "no OpenCTI observables/indicators could be mapped (supported: IPv4/IPv6, Domain-Name, Hostname, Url, StixFile hashes, Email-Addr, STIX patterns)"
                .to_string(),
        );
    }

    Ok(OpenCtiImportMaterial {
        threats,
        dnsbl,
        skipped_objects,
    })
}

/// Parse an OpenCTI JSON body string.
pub fn parse_opencti_document(
    body: &str,
    source: &str,
    ttl_seconds: u64,
) -> Result<OpenCtiImportMaterial, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty OpenCTI body".to_string());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|error| format!("invalid OpenCTI JSON: {error}"))?;
    opencti_material_from_value(&value, source, ttl_seconds)
}

enum NodeOutcome {
    Mapped {
        threats: Vec<ThreatIndicator>,
        dnsbl: Vec<DnsblEntry>,
    },
    Skipped,
}

fn is_stix_document(value: &serde_json::Value) -> bool {
    matches!(
        value.get("type").and_then(|t| t.as_str()),
        Some("bundle") | Some("indicator")
    ) || value
        .as_array()
        .map(|items| {
            !items.is_empty()
                && items.iter().all(|item| {
                    matches!(
                        item.get("type").and_then(|t| t.as_str()),
                        Some("indicator")
                            | Some("bundle")
                            | Some("malware")
                            | Some("observed-data")
                    )
                })
        })
        .unwrap_or(false)
}

fn collect_opencti_nodes<'a>(
    value: &'a serde_json::Value,
    nodes: &mut Vec<&'a serde_json::Value>,
    skipped: &mut usize,
) {
    // GraphQL: data.stixCyberObservables.edges / data.indicators.edges
    if let Some(data) = value.get("data") {
        collect_connection(data.get("stixCyberObservables"), nodes, skipped);
        collect_connection(data.get("indicators"), nodes, skipped);
        collect_connection(data.get("stixDomainObjects"), nodes, skipped);
        if nodes.is_empty() {
            // Unknown GraphQL payload — nothing usable.
        }
        return;
    }

    // List export: { "entities": [ ... ] } or { "objects": [ ... ] }
    if let Some(arr) = value
        .get("entities")
        .or_else(|| value.get("objects"))
        .and_then(|a| a.as_array())
    {
        for item in arr {
            if looks_like_opencti_node(item) {
                nodes.push(item);
            } else {
                *skipped += 1;
            }
        }
        return;
    }

    // Bare array of observables/indicators
    if let Some(arr) = value.as_array() {
        for item in arr {
            if looks_like_opencti_node(item) {
                nodes.push(item);
            } else {
                *skipped += 1;
            }
        }
        return;
    }

    // Single node
    if looks_like_opencti_node(value) {
        nodes.push(value);
    }
}

fn collect_connection<'a>(
    connection: Option<&'a serde_json::Value>,
    nodes: &mut Vec<&'a serde_json::Value>,
    skipped: &mut usize,
) {
    let Some(connection) = connection else {
        return;
    };
    let Some(edges) = connection.get("edges").and_then(|e| e.as_array()) else {
        return;
    };
    for edge in edges {
        if let Some(node) = edge.get("node") {
            if looks_like_opencti_node(node) {
                nodes.push(node);
            } else {
                *skipped += 1;
            }
        } else {
            *skipped += 1;
        }
    }
}

fn looks_like_opencti_node(obj: &serde_json::Value) -> bool {
    if !obj.is_object() {
        return false;
    }
    // OpenCTI observable
    if obj
        .get("observable_value")
        .and_then(|v| v.as_str())
        .is_some()
        || obj.get("value").and_then(|v| v.as_str()).is_some()
    {
        return obj.get("entity_type").is_some()
            || obj.get("type").is_some()
            || obj.get("x_opencti_main_observable_type").is_some();
    }
    // STIX indicator inside OpenCTI export
    if obj.get("type").and_then(|t| t.as_str()) == Some("indicator")
        && obj.get("pattern").and_then(|p| p.as_str()).is_some()
    {
        return true;
    }
    // OpenCTI indicator with pattern field
    if obj.get("pattern").and_then(|p| p.as_str()).is_some()
        && (obj.get("entity_type").and_then(|t| t.as_str()) == Some("Indicator")
            || obj.get("standard_id").is_some())
    {
        return true;
    }
    false
}

fn materialize_node(node: &serde_json::Value, source: &str, ttl_seconds: u64) -> NodeOutcome {
    // STIX indicator pattern path (native STIX or OpenCTI Indicator entity).
    if let Some(pattern) = node
        .get("pattern")
        .and_then(|p| p.as_str())
        .filter(|p| !p.is_empty())
        && (node.get("type").and_then(|t| t.as_str()) == Some("indicator")
            || node.get("entity_type").and_then(|t| t.as_str()) == Some("Indicator")
            || node.get("pattern_type").is_some())
    {
        let stix_node = if node.get("type").and_then(|t| t.as_str()) == Some("indicator") {
            node.clone()
        } else {
            serde_json::json!({
                "type": "indicator",
                "id": node.get("standard_id").cloned().unwrap_or(serde_json::json!("indicator--opencti")),
                "name": node.get("name").cloned().unwrap_or(serde_json::json!("opencti-indicator")),
                "pattern": pattern,
                "pattern_type": node.get("pattern_type").cloned().unwrap_or(serde_json::json!("stix")),
                "valid_from": "1970-01-01T00:00:00Z",
                "confidence": node.get("confidence")
                    .or_else(|| node.get("x_opencti_score"))
                    .cloned()
                    .unwrap_or(serde_json::json!(50)),
            })
        };
        match stix_import::stix_material_from_value(&stix_node, source, ttl_seconds) {
            Ok(material) if !material.threats.is_empty() || !material.dnsbl.is_empty() => {
                return NodeOutcome::Mapped {
                    threats: material.threats,
                    dnsbl: material.dnsbl,
                };
            }
            _ => return NodeOutcome::Skipped,
        }
    }

    let entity_type = node
        .get("entity_type")
        .or_else(|| node.get("x_opencti_main_observable_type"))
        .or_else(|| node.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .trim();
    let value = node
        .get("observable_value")
        .or_else(|| node.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if entity_type.is_empty() || value.is_empty() {
        return NodeOutcome::Skipped;
    }

    let severity = severity_from_opencti(node);
    let normalized_type = normalize_entity_type(entity_type);
    let mut threats = Vec::new();
    let mut dnsbl = Vec::new();
    let reason = format!(
        "opencti:{}",
        node.get("name")
            .and_then(|n| n.as_str())
            .or_else(|| node.get("standard_id").and_then(|s| s.as_str()))
            .unwrap_or(entity_type)
    );

    match normalized_type.as_str() {
        "ipv4-addr" | "ipv6-addr" | "ip" => {
            if !push_ip(
                value,
                source,
                ttl_seconds,
                severity,
                &reason,
                &mut threats,
                &mut dnsbl,
            ) {
                return NodeOutcome::Skipped;
            }
        }
        "domain-name" | "hostname" => {
            let domain = value.to_ascii_lowercase();
            if !is_plausible_domain(&domain) {
                return NodeOutcome::Skipped;
            }
            threats.push(ThreatIndicator {
                value: domain,
                indicator_type: "domain".to_string(),
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
        }
        "url" => {
            threats.push(ThreatIndicator {
                value: value.to_string(),
                indicator_type: "url".to_string(),
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
        }
        "email-addr" | "email" => {
            threats.push(ThreatIndicator {
                value: value.to_ascii_lowercase(),
                indicator_type: "email".to_string(),
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
        }
        "file" | "stixfile" | "artifact" => {
            // Prefer explicit hash fields when present.
            if let Some(hashes) = node.get("hashes").and_then(|h| h.as_object()) {
                let mut any = false;
                for (algo, hash_val) in hashes {
                    if let Some(hash) = hash_val.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        threats.push(ThreatIndicator {
                            value: hash.to_ascii_lowercase(),
                            indicator_type: algo.to_ascii_lowercase(),
                            severity: severity.clone(),
                            source: source.to_string(),
                            ttl_seconds,
                        });
                        any = true;
                    }
                }
                if !any {
                    return NodeOutcome::Skipped;
                }
            } else if looks_like_hash(value) {
                threats.push(ThreatIndicator {
                    value: value.to_ascii_lowercase(),
                    indicator_type: guess_hash_type(value),
                    severity,
                    source: source.to_string(),
                    ttl_seconds,
                });
            } else {
                return NodeOutcome::Skipped;
            }
        }
        "md5" | "sha1" | "sha256" | "sha512" => {
            threats.push(ThreatIndicator {
                value: value.to_ascii_lowercase(),
                indicator_type: normalized_type,
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
        }
        _ => return NodeOutcome::Skipped,
    }

    NodeOutcome::Mapped { threats, dnsbl }
}

fn normalize_entity_type(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

fn severity_from_opencti(node: &serde_json::Value) -> Severity {
    // OpenCTI score is typically 0-100.
    let score = node
        .get("x_opencti_score")
        .or_else(|| node.get("confidence"))
        .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
        .unwrap_or(50);
    match score {
        0..=24 => Severity::Low,
        25..=49 => Severity::Medium,
        50..=74 => Severity::High,
        _ => Severity::Critical,
    }
}

fn push_ip(
    raw: &str,
    source: &str,
    ttl_seconds: u64,
    severity: Severity,
    reason: &str,
    threats: &mut Vec<ThreatIndicator>,
    dnsbl: &mut Vec<DnsblEntry>,
) -> bool {
    let Ok(ip) = raw.parse::<IpAddr>() else {
        return false;
    };
    dnsbl.push(DnsblEntry {
        address: ip,
        code: "127.0.0.2".to_string(),
        reason: reason.to_string(),
        source: source.to_string(),
        ttl_seconds,
        prefix_len: None,
    });
    threats.push(ThreatIndicator {
        value: ip.to_string(),
        indicator_type: "client_ip".to_string(),
        severity,
        source: source.to_string(),
        ttl_seconds,
    });
    true
}

fn is_plausible_domain(host: &str) -> bool {
    if host.is_empty() || !host.contains('.') || host.starts_with('.') || host.contains("..") {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    host.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

fn looks_like_hash(value: &str) -> bool {
    let len = value.len();
    matches!(len, 32 | 40 | 64 | 128) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn guess_hash_type(value: &str) -> String {
    match value.len() {
        32 => "md5".to_string(),
        40 => "sha1".to_string(),
        64 => "sha256".to_string(),
        128 => "sha512".to_string(),
        _ => "hash".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn maps_graphql_observables() {
        let raw = r#"{
          "data": {
            "stixCyberObservables": {
              "edges": [
                {
                  "node": {
                    "entity_type": "IPv4-Addr",
                    "observable_value": "203.0.113.44",
                    "x_opencti_score": 90,
                    "standard_id": "ipv4-addr--1"
                  }
                },
                {
                  "node": {
                    "entity_type": "Domain-Name",
                    "observable_value": "evil.opencti.example",
                    "x_opencti_score": 60
                  }
                },
                {
                  "node": {
                    "entity_type": "Url",
                    "observable_value": "http://evil.opencti.example/login"
                  }
                },
                {
                  "node": {
                    "entity_type": "Text",
                    "observable_value": "noise"
                  }
                }
              ]
            }
          }
        }"#;
        let material = parse_opencti_document(raw, "opencti:test", 3600).unwrap();
        assert!(
            material
                .dnsbl
                .iter()
                .any(|d| d.address == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44)))
        );
        assert!(
            material
                .threats
                .iter()
                .any(|t| { t.indicator_type == "domain" && t.value == "evil.opencti.example" })
        );
        assert!(material.threats.iter().any(|t| t.indicator_type == "url"));
        assert!(material.skipped_objects >= 1);
    }

    #[test]
    fn maps_entities_list_and_stix_indicator() {
        let raw = r#"{
          "entities": [
            {
              "entity_type": "Indicator",
              "pattern": "[ipv4-addr:value = '198.51.100.77']",
              "pattern_type": "stix",
              "name": "c2"
            },
            {
              "entity_type": "StixFile",
              "observable_value": "aabbccddeeff00112233445566778899",
              "hashes": { "MD5": "aabbccddeeff00112233445566778899" }
            }
          ]
        }"#;
        let material = parse_opencti_document(raw, "opencti", 60).unwrap();
        assert!(
            material
                .dnsbl
                .iter()
                .any(|d| d.address == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)))
        );
        assert!(material.threats.iter().any(|t| t.indicator_type == "md5"));
    }

    #[test]
    fn rejects_empty_and_non_opencti() {
        assert!(parse_opencti_document("", "s", 60).is_err());
        assert!(parse_opencti_document(r#"{"foo":1}"#, "s", 60).is_err());
        assert!(parse_opencti_document(
            r#"{"data":{"stixCyberObservables":{"edges":[{"node":{"entity_type":"Text","observable_value":"x"}}]}}}"#,
            "s",
            60
        )
        .is_err());
    }

    #[test]
    fn rejects_implausible_domains() {
        let raw = r#"[{"entity_type":"Domain-Name","observable_value":"a"}]"#;
        assert!(parse_opencti_document(raw, "s", 60).is_err());
    }
}
