//! Suricata EVE JSON ingest adapter.
//!
//! Maps proven Suricata IDS alert records into gateway [`SecurityEvent`]-shaped
//! fields. This is an integration boundary — not a hand-rolled detection engine.

use std::net::IpAddr;

/// One alert extracted from a Suricata EVE JSON record (event_type=alert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataIngestedAlert {
    pub client_ip: Option<IpAddr>,
    /// `block` or `monitor` (route-scoped enforcement language used by the gateway).
    pub action: String,
    pub reason: String,
    pub score: u16,
    pub path: String,
    /// Event occurrence time from EVE `timestamp` when parseable; otherwise `None`
    /// so the gateway can fall back to ingest time.
    pub timestamp_unix: Option<u64>,
}

/// Parse a single Suricata EVE JSON value into an ingested alert.
///
/// Non-alert event types and malformed records return `None` (skipped).
pub fn suricata_alert_from_value(value: &serde_json::Value) -> Option<SuricataIngestedAlert> {
    let event_type = value.get("event_type")?.as_str()?;
    if event_type != "alert" {
        return None;
    }
    let alert = value.get("alert")?;
    let signature = alert
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("suricata alert")
        .trim();
    if signature.is_empty() {
        return None;
    }
    let category = alert
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let reason = if category.is_empty() {
        format!("suricata: {signature}")
    } else {
        format!("suricata: {signature} [{category}]")
    };

    let severity = alert
        .get("severity")
        .and_then(|v| v.as_u64())
        .unwrap_or(3)
        .clamp(1, 3) as u8;
    // Suricata severities: 1 = high, 2 = medium, 3 = low.
    let score = match severity {
        1 => 80,
        2 => 50,
        _ => 25,
    };

    let alert_action = alert
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let action = if alert_action.contains("block") || alert_action == "dropped" || severity == 1 {
        "block".to_string()
    } else {
        "monitor".to_string()
    };

    let client_ip = value
        .get("src_ip")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<IpAddr>().ok());

    let path = value
        .pointer("/http/url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .pointer("/http/hostname")
                .and_then(|v| v.as_str())
                .map(|host| format!("suricata://{host}"))
        })
        .unwrap_or_else(|| {
            let dest = value
                .get("dest_ip")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let port = value
                .get("dest_port")
                .and_then(|v| v.as_u64())
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!("suricata://{dest}:{port}")
        });

    let timestamp_unix = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(parse_suricata_timestamp);

    Some(SuricataIngestedAlert {
        client_ip,
        action,
        reason,
        score,
        path,
        timestamp_unix,
    })
}

/// Parse common Suricata EVE timestamp forms to Unix seconds (UTC).
///
/// Accepts `YYYY-MM-DDTHH:MM:SS` with optional fractional seconds and a
/// trailing `Z`, `+0000`, or `+00:00` timezone. Other offsets are treated as UTC
/// (lab ingest); unparseable values return `None`.
pub fn parse_suricata_timestamp(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    if s.as_bytes().get(4) != Some(&b'-') {
        return None;
    }
    let month: u32 = s.get(5..7)?.parse().ok()?;
    if s.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let sep = s.as_bytes().get(10).copied()?;
    if sep != b'T' && sep != b' ' {
        return None;
    }
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    if s.as_bytes().get(13) != Some(&b':') {
        return None;
    }
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    if s.as_bytes().get(16) != Some(&b':') {
        return None;
    }
    let second: u32 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    days_from_civil(year, month, day).and_then(|days| {
        let secs = i64::from(days) * 86_400
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second);
        u64::try_from(secs).ok()
    })
}

/// Howard Hinnant civil-from-days inverse: days since Unix epoch for a UTC date.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i32> {
    let mut y = year;
    let m = month as i32;
    let d = day as i32;
    y -= i32::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u32;
    Some(era * 146_097 + doe as i32 - 719_468)
}

/// Result of parsing a Suricata EVE body (alerts kept; other EVE types skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataEveParseResult {
    pub alerts: Vec<SuricataIngestedAlert>,
    pub skipped_non_alerts: usize,
}

/// Parse an EVE body that may be a single object, a JSON array, or NDJSON lines.
/// Returns alerts in input order; non-alert lines/objects are counted as skipped.
pub fn parse_suricata_eve_body(body: &str) -> Result<SuricataEveParseResult, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("empty Suricata EVE body".to_string());
    }

    // Prefer a single JSON value (object or array) when the whole body parses.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(alerts_from_json_value(&value));
    }

    // Fall back to NDJSON (one EVE record per line — Suricata eve-log default).
    let mut alerts = Vec::new();
    let mut skipped_non_alerts = 0usize;
    let mut saw_json_line = false;
    for (idx, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                saw_json_line = true;
                if let Some(alert) = suricata_alert_from_value(&value) {
                    alerts.push(alert);
                } else {
                    skipped_non_alerts += 1;
                }
            }
            Err(error) => {
                return Err(format!(
                    "invalid Suricata EVE JSON on line {}: {error}",
                    idx + 1
                ));
            }
        }
    }
    if !saw_json_line {
        return Err("no Suricata EVE JSON records found".to_string());
    }
    Ok(SuricataEveParseResult {
        alerts,
        skipped_non_alerts,
    })
}

fn alerts_from_json_value(value: &serde_json::Value) -> SuricataEveParseResult {
    match value {
        serde_json::Value::Array(items) => {
            let mut alerts = Vec::new();
            let mut skipped_non_alerts = 0usize;
            for item in items {
                if let Some(alert) = suricata_alert_from_value(item) {
                    alerts.push(alert);
                } else {
                    skipped_non_alerts += 1;
                }
            }
            SuricataEveParseResult {
                alerts,
                skipped_non_alerts,
            }
        }
        other => {
            if let Some(alert) = suricata_alert_from_value(other) {
                SuricataEveParseResult {
                    alerts: vec![alert],
                    skipped_non_alerts: 0,
                }
            } else {
                SuricataEveParseResult {
                    alerts: vec![],
                    skipped_non_alerts: 1,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn maps_high_severity_http_alert_to_block() {
        let raw = r#"{
          "timestamp": "2024-06-15T12:34:56.123456+0000",
          "event_type": "alert",
          "src_ip": "203.0.113.10",
          "dest_ip": "198.51.100.1",
          "dest_port": 443,
          "alert": {
            "action": "allowed",
            "signature": "ET WEB_SERVER SQL Injection",
            "category": "Web Application Attack",
            "severity": 1
          },
          "http": { "url": "/search?q=1'+OR+1%3D1", "hostname": "app.example" }
        }"#;
        let alert = suricata_alert_from_value(&serde_json::from_str(raw).unwrap()).unwrap();
        assert_eq!(alert.action, "block");
        assert_eq!(alert.score, 80);
        assert_eq!(
            alert.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
        assert_eq!(alert.path, "/search?q=1'+OR+1%3D1");
        assert!(alert.reason.contains("SQL Injection"));
        assert!(alert.reason.contains("Web Application Attack"));
        // 2024-06-15T12:34:56Z
        assert_eq!(alert.timestamp_unix, Some(1_718_454_896));
    }

    #[test]
    fn parse_suricata_timestamp_handles_common_eve_forms() {
        assert_eq!(
            parse_suricata_timestamp("2024-06-15T12:34:56.123456+0000"),
            Some(1_718_454_896)
        );
        assert_eq!(
            parse_suricata_timestamp("2024-06-15T12:34:56Z"),
            Some(1_718_454_896)
        );
        assert!(parse_suricata_timestamp("not-a-timestamp").is_none());
    }

    #[test]
    fn parse_suricata_eve_body_never_panics_on_arbitrary_text() {
        for sample in [
            "",
            "{",
            "[]",
            "null",
            "{\"event_type\":\"alert\"}",
            "\u{0000}\u{ffff}💥",
            "{\"event_type\":\"alert\",\"alert\":{\"signature\":\"x\"}}\n{",
        ] {
            let _ = parse_suricata_eve_body(sample);
        }
    }

    #[test]
    fn skips_non_alert_event_types() {
        let raw = r#"{"event_type":"flow","src_ip":"203.0.113.10"}"#;
        assert!(suricata_alert_from_value(&serde_json::from_str(raw).unwrap()).is_none());
    }

    #[test]
    fn parses_ndjson_and_ignores_non_alerts() {
        let body = r#"
{"event_type":"stats"}
{"event_type":"alert","src_ip":"198.51.100.9","alert":{"signature":"ET SCAN Nmap","severity":2},"dest_ip":"10.0.0.1","dest_port":22}
"#;
        let parsed = parse_suricata_eve_body(body).unwrap();
        assert_eq!(parsed.alerts.len(), 1);
        assert_eq!(parsed.skipped_non_alerts, 1);
        assert_eq!(parsed.alerts[0].action, "monitor");
        assert_eq!(parsed.alerts[0].score, 50);
        assert!(parsed.alerts[0].path.contains("10.0.0.1:22"));
    }

    #[test]
    fn rejects_empty_body() {
        assert!(parse_suricata_eve_body("  \n").is_err());
    }
}
