//! MISP event / attribute import adapter.
//!
//! Parses common MISP JSON exports (Event wrapper, REST response arrays,
//! attribute lists, Object-nested attributes) into gateway
//! [`ThreatIndicator`] / [`DnsblEntry`] rows. This is a proven threat-intel
//! platform boundary — not a hand-rolled detection engine. Live MISP REST
//! pull jobs remain a follow-up; operators POST MISP documents here.

use std::net::IpAddr;

use waf_ids_core::{DnsblEntry, Severity, ThreatIndicator};

/// Parsed MISP import ready for the existing threat-feed upsert path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MispImportMaterial {
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
    pub skipped_attributes: usize,
}

/// Extract indicators from a MISP JSON document.
pub fn misp_material_from_value(
    value: &serde_json::Value,
    source: &str,
    ttl_seconds: u64,
) -> Result<MispImportMaterial, String> {
    let mut threats = Vec::new();
    let mut dnsbl = Vec::new();
    let mut skipped_attributes = 0usize;

    let mut events: Vec<(&serde_json::Value, Severity)> = Vec::new();
    let mut loose_attributes: Vec<(&serde_json::Value, Severity)> = Vec::new();

    match value {
        // Classic export: { "Event": { ... } }
        obj if obj.get("Event").is_some() => {
            if let Some(event) = obj.get("Event") {
                events.push((event, severity_from_event(event)));
            }
        }
        // MISP REST list: { "response": [ { "Event": ... }, ... ] }
        obj if obj.get("response").and_then(|r| r.as_array()).is_some() => {
            let items = obj.get("response").and_then(|r| r.as_array()).unwrap();
            for item in items {
                if let Some(event) = item.get("Event") {
                    events.push((event, severity_from_event(event)));
                } else if item.get("Attribute").is_some() || item.get("info").is_some() {
                    events.push((item, severity_from_event(item)));
                } else if looks_like_attribute(item) {
                    loose_attributes.push((item, Severity::Medium));
                } else {
                    skipped_attributes += 1;
                }
            }
        }
        // Bare event object (has Attribute or Object arrays, or info+id)
        obj if is_event_shape(obj) => {
            events.push((obj, severity_from_event(obj)));
        }
        // Array of events / attributes / Event wrappers
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                return Err("MISP document contained an empty array".to_string());
            }
            for item in items {
                if let Some(event) = item.get("Event") {
                    events.push((event, severity_from_event(event)));
                } else if is_event_shape(item) {
                    events.push((item, severity_from_event(item)));
                } else if looks_like_attribute(item) {
                    loose_attributes.push((item, Severity::Medium));
                } else {
                    skipped_attributes += 1;
                }
            }
        }
        // Single attribute
        obj if looks_like_attribute(obj) => {
            loose_attributes.push((obj, Severity::Medium));
        }
        _ => {
            return Err(
                "MISP document must be an Event, Event wrapper, attribute, response list, or array"
                    .to_string(),
            );
        }
    }

    if events.is_empty() && loose_attributes.is_empty() {
        return Err("MISP document contained no events or attributes".to_string());
    }

    for (event, severity) in events {
        let event_label = event
            .get("info")
            .and_then(|i| i.as_str())
            .or_else(|| event.get("id").and_then(|i| i.as_str()))
            .unwrap_or("misp-event");

        for (attr, parent_active) in collect_event_attributes(event) {
            match materialize_attribute(
                attr,
                source,
                ttl_seconds,
                severity.clone(),
                event_label,
                parent_active,
            ) {
                AttributeOutcome::Mapped {
                    threats: t,
                    dnsbl: d,
                } => {
                    threats.extend(t);
                    dnsbl.extend(d);
                }
                AttributeOutcome::Skipped => skipped_attributes += 1,
            }
        }
    }

    for (attr, severity) in loose_attributes {
        match materialize_attribute(attr, source, ttl_seconds, severity, "misp-attribute", true) {
            AttributeOutcome::Mapped {
                threats: t,
                dnsbl: d,
            } => {
                threats.extend(t);
                dnsbl.extend(d);
            }
            AttributeOutcome::Skipped => skipped_attributes += 1,
        }
    }

    if threats.is_empty() && dnsbl.is_empty() {
        return Err(
            "no MISP attributes could be mapped (supported: ip-src/ip-dst, domain/hostname, url/uri, composites)"
                .to_string(),
        );
    }

    Ok(MispImportMaterial {
        threats,
        dnsbl,
        skipped_attributes,
    })
}

/// Parse a MISP JSON body string.
pub fn parse_misp_document(
    body: &str,
    source: &str,
    ttl_seconds: u64,
) -> Result<MispImportMaterial, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty MISP body".to_string());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|error| format!("invalid MISP JSON: {error}"))?;
    misp_material_from_value(&value, source, ttl_seconds)
}

enum AttributeOutcome {
    Mapped {
        threats: Vec<ThreatIndicator>,
        dnsbl: Vec<DnsblEntry>,
    },
    Skipped,
}

fn is_event_shape(obj: &serde_json::Value) -> bool {
    obj.get("Attribute").and_then(|a| a.as_array()).is_some()
        || obj.get("Object").and_then(|o| o.as_array()).is_some()
        || (obj.get("info").is_some() && (obj.get("id").is_some() || obj.get("uuid").is_some()))
}

fn looks_like_attribute(obj: &serde_json::Value) -> bool {
    obj.get("type").and_then(|t| t.as_str()).is_some()
        && obj.get("value").and_then(|v| v.as_str()).is_some()
}

fn severity_from_event(event: &serde_json::Value) -> Severity {
    // MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined
    match event
        .get("threat_level_id")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| v.as_u64())
        })
        .unwrap_or(2)
    {
        1 => Severity::Critical,
        2 => Severity::High,
        3 => Severity::Medium,
        _ => Severity::Low,
    }
}

fn active_by_deleted_marker(deleted: Option<&serde_json::Value>) -> bool {
    deleted
        .map(|value| match value {
            serde_json::Value::Bool(is_deleted) => !*is_deleted,
            serde_json::Value::String(value) => value == "0" || value.eq_ignore_ascii_case("false"),
            serde_json::Value::Number(value) => value.as_u64() == Some(0),
            _ => false,
        })
        .unwrap_or(true)
}

fn collect_event_attributes(event: &serde_json::Value) -> Vec<(&serde_json::Value, bool)> {
    let mut out = Vec::new();
    if let Some(attrs) = event.get("Attribute").and_then(|a| a.as_array()) {
        out.extend(attrs.iter().map(|attr| (attr, true)));
    }
    if let Some(objects) = event.get("Object").and_then(|o| o.as_array()) {
        for object in objects {
            let parent_active = active_by_deleted_marker(object.get("deleted"));
            if let Some(attrs) = object.get("Attribute").and_then(|a| a.as_array()) {
                out.extend(attrs.iter().map(|attr| (attr, parent_active)));
            }
        }
    }
    out
}

fn materialize_attribute(
    attr: &serde_json::Value,
    source: &str,
    ttl_seconds: u64,
    severity: Severity,
    event_label: &str,
    parent_active: bool,
) -> AttributeOutcome {
    // MISP's `to_ids` contract is affirmative evidence. Preserve the previously supported
    // scalar true spellings, but absent or malformed values cannot authorize enforcement.
    // See docs/doctoring/misp-to-ids-admission.md.
    let to_ids = attr
        .get("to_ids")
        .map(|v| match v {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(s) => s == "1" || s.eq_ignore_ascii_case("true"),
            serde_json::Value::Number(n) => n.as_u64() == Some(1),
            _ => false,
        })
        .unwrap_or(false);

    // MISP publishes deletion state independently at both object and attribute scope. A
    // nested attribute cannot override a withdrawn parent object. Omission remains active
    // for compatibility; any present unrecognized deletion state fails closed.
    let active = active_by_deleted_marker(attr.get("deleted"));
    if !parent_active || !to_ids || !active {
        return AttributeOutcome::Skipped;
    }

    let attr_type = attr
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let value = attr
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if attr_type.is_empty() || value.is_empty() {
        return AttributeOutcome::Skipped;
    }

    let comment = attr
        .get("comment")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(event_label);
    let reason = format!("misp:{comment}");

    let mut threats = Vec::new();
    let mut dnsbl = Vec::new();

    match attr_type.as_str() {
        "ip-src" | "ip-dst" | "ip" => {
            if push_ip(
                value,
                source,
                ttl_seconds,
                severity.clone(),
                &reason,
                &mut threats,
                &mut dnsbl,
            ) {
                AttributeOutcome::Mapped { threats, dnsbl }
            } else {
                AttributeOutcome::Skipped
            }
        }
        "ip-src|port" | "ip-dst|port" => {
            let ip_part = value.split('|').next().unwrap_or("").trim();
            if push_ip(
                ip_part,
                source,
                ttl_seconds,
                severity.clone(),
                &reason,
                &mut threats,
                &mut dnsbl,
            ) {
                AttributeOutcome::Mapped { threats, dnsbl }
            } else {
                AttributeOutcome::Skipped
            }
        }
        "domain" | "hostname" => {
            threats.push(ThreatIndicator {
                value: value.to_ascii_lowercase(),
                indicator_type: "domain".to_string(),
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
            AttributeOutcome::Mapped { threats, dnsbl }
        }
        "domain|ip" => {
            let mut parts = value.splitn(2, '|');
            let domain = parts.next().unwrap_or("").trim();
            let ip_part = parts.next().unwrap_or("").trim();
            if !domain.is_empty() {
                threats.push(ThreatIndicator {
                    value: domain.to_ascii_lowercase(),
                    indicator_type: "domain".to_string(),
                    severity: severity.clone(),
                    source: source.to_string(),
                    ttl_seconds,
                });
            }
            if !ip_part.is_empty() {
                let _ = push_ip(
                    ip_part,
                    source,
                    ttl_seconds,
                    severity,
                    &reason,
                    &mut threats,
                    &mut dnsbl,
                );
            }
            if threats.is_empty() && dnsbl.is_empty() {
                AttributeOutcome::Skipped
            } else {
                AttributeOutcome::Mapped { threats, dnsbl }
            }
        }
        "url" | "uri" | "link" => {
            threats.push(ThreatIndicator {
                value: value.to_string(),
                indicator_type: "url".to_string(),
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
            AttributeOutcome::Mapped { threats, dnsbl }
        }
        "md5" | "sha1" | "sha256" | "sha512" | "ssdeep" => {
            threats.push(ThreatIndicator {
                value: value.to_ascii_lowercase(),
                indicator_type: attr_type,
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
            AttributeOutcome::Mapped { threats, dnsbl }
        }
        "email-src" | "email-dst" | "email" | "email-src-display-name" => {
            threats.push(ThreatIndicator {
                value: value.to_ascii_lowercase(),
                indicator_type: "email".to_string(),
                severity,
                source: source.to_string(),
                ttl_seconds,
            });
            AttributeOutcome::Mapped { threats, dnsbl }
        }
        _ => AttributeOutcome::Skipped,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn maps_event_wrapper_ip_and_domain() {
        let raw = r#"{
          "Event": {
            "id": "42",
            "info": "phishing campaign",
            "threat_level_id": "1",
            "Attribute": [
              {
                "type": "ip-dst",
                "value": "203.0.113.77",
                "to_ids": true,
                "comment": "c2"
              },
              {
                "type": "domain",
                "value": "bad.example",
                "to_ids": "1"
              },
              {
                "type": "url",
                "value": "http://bad.example/login",
                "to_ids": true
              },
              {
                "type": "comment",
                "value": "noise",
                "to_ids": true
              },
              {
                "type": "ip-src",
                "value": "198.51.100.9",
                "to_ids": false
              }
            ],
            "Object": [
              {
                "name": "file",
                "Attribute": [
                  {
                    "type": "sha256",
                    "value": "AABBCC",
                    "to_ids": true
                  }
                ]
              }
            ]
          }
        }"#;
        let material = parse_misp_document(raw, "misp:test", 3600).unwrap();
        assert!(
            material
                .dnsbl
                .iter()
                .any(|d| d.address == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)))
        );
        assert!(
            material
                .threats
                .iter()
                .any(|t| t.indicator_type == "domain" && t.value == "bad.example")
        );
        assert!(
            material
                .threats
                .iter()
                .any(|t| t.indicator_type == "url" && t.value == "http://bad.example/login")
        );
        assert!(
            material
                .threats
                .iter()
                .any(|t| t.indicator_type == "sha256" && t.value == "aabbcc")
        );
        // to_ids=false IP skipped
        assert!(!material.threats.iter().any(|t| t.value == "198.51.100.9"));
        assert!(material.skipped_attributes >= 2);
    }

    #[test]
    fn maps_domain_ip_composite_and_ip_port() {
        let raw_array = r#"[
          {"type":"domain|ip","value":"evil.example|203.0.113.9","to_ids":true},
          {"type":"ip-dst|port","value":"203.0.113.10|443","to_ids":true}
        ]"#;
        let material = parse_misp_document(raw_array, "misp", 60).unwrap();
        assert!(
            material
                .threats
                .iter()
                .any(|t| t.indicator_type == "domain" && t.value == "evil.example")
        );
        assert!(
            material
                .dnsbl
                .iter()
                .any(|d| d.address == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
        assert!(
            material
                .dnsbl
                .iter()
                .any(|d| d.address == IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
    }

    #[test]
    fn rejects_empty_and_non_misp() {
        assert!(parse_misp_document("", "s", 60).is_err());
        assert!(parse_misp_document("{\"foo\":1}", "s", 60).is_err());
        assert!(parse_misp_document(
            r#"{"Event":{"info":"x","Attribute":[{"type":"comment","value":"n","to_ids":true}]}}"#,
            "s",
            60
        )
        .is_err());
    }
}
