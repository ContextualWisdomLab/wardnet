use crate::{DnsblEntry, Severity, ThreatIndicator};
use serde_json::Value;
use std::net::IpAddr;

const MAX_OFFICIAL_FEED_MATERIAL_ITEMS: usize = 50_000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedOfficialFeed {
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
    pub source_notice: Option<String>,
}

pub fn parse(
    parser: &str,
    source_id: &str,
    ttl_seconds: u64,
    body: &str,
) -> Result<ParsedOfficialFeed, String> {
    parse_with_limit(
        parser,
        source_id,
        ttl_seconds,
        body,
        MAX_OFFICIAL_FEED_MATERIAL_ITEMS,
    )
}

fn parse_with_limit(
    parser: &str,
    source_id: &str,
    ttl_seconds: u64,
    body: &str,
    max_material_items: usize,
) -> Result<ParsedOfficialFeed, String> {
    match parser {
        "spamhaus_drop_json" => parse_spamhaus(source_id, ttl_seconds, body, max_material_items),
        "urlhaus_recent_csv" => parse_urlhaus(source_id, ttl_seconds, body, max_material_items),
        "threatfox_json" => parse_threatfox(source_id, ttl_seconds, body, max_material_items),
        _ => Err(format!("unsupported official feed parser: {parser}")),
    }
}

fn parse_spamhaus(
    source_id: &str,
    ttl_seconds: u64,
    body: &str,
    max_material_items: usize,
) -> Result<ParsedOfficialFeed, String> {
    let mut parsed = ParsedOfficialFeed::default();
    for (line_number, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|error| {
            format!("invalid Spamhaus JSON on line {}: {error}", line_number + 1)
        })?;
        if value.get("type").is_some() {
            parsed.source_notice = value
                .get("copyright")
                .and_then(Value::as_str)
                .map(str::to_string);
            continue;
        }
        let cidr = value
            .get("cidr")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Spamhaus record {} is missing cidr", line_number + 1))?;
        let (address, prefix_len) = parse_cidr(cidr)?;
        let sblid = value.get("sblid").and_then(Value::as_str).unwrap_or("DROP");
        push_dnsbl(
            &mut parsed,
            source_id,
            max_material_items,
            DnsblEntry {
                address,
                prefix_len: Some(prefix_len),
                code: "127.0.0.2".to_string(),
                reason: format!("Spamhaus DROP {sblid}"),
                source: source_id.to_string(),
                ttl_seconds,
            },
        )?;
    }
    require_material(parsed, source_id)
}

fn parse_urlhaus(
    source_id: &str,
    ttl_seconds: u64,
    body: &str,
    max_material_items: usize,
) -> Result<ParsedOfficialFeed, String> {
    let mut parsed = ParsedOfficialFeed::default();
    let csv_body = body
        .lines()
        .scan(false, |seen_header, line| {
            let trimmed = line.trim_start();
            if !*seen_header {
                let header = trimmed
                    .strip_prefix('#')
                    .map(str::trim_start)
                    .filter(|candidate| candidate.starts_with("id,dateadded,url,"));
                if let Some(header) = header {
                    *seen_header = true;
                    return Some(Some(header));
                }
                return Some(None);
            }
            Some(Some(line))
        })
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_body.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| format!("invalid URLhaus CSV header: {error}"))?
        .clone();
    let url_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("url"))
        .ok_or_else(|| "URLhaus CSV is missing url header".to_string())?;
    let url_status_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("url_status"));
    for record in reader.records() {
        let record = record.map_err(|error| format!("invalid URLhaus CSV record: {error}"))?;
        if let Some(status_index) = url_status_index {
            let Some(status) = record.get(status_index) else {
                continue;
            };
            if !status.eq_ignore_ascii_case("online") {
                continue;
            }
        }
        let Some(url) = record.get(url_index).filter(|url| !url.is_empty()) else {
            continue;
        };
        push_threat(
            &mut parsed,
            source_id,
            max_material_items,
            threat(url, "url", source_id, ttl_seconds),
        )?;
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
        if let Some(host) = host {
            let ip_candidate = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(address) = ip_candidate.parse::<IpAddr>() {
                push_threat(
                    &mut parsed,
                    source_id,
                    max_material_items,
                    threat(&address.to_string(), "client_ip", source_id, ttl_seconds),
                )?;
                push_dnsbl(
                    &mut parsed,
                    source_id,
                    max_material_items,
                    DnsblEntry {
                        address,
                        prefix_len: None,
                        code: "127.0.0.2".to_string(),
                        reason: "URLhaus malware URL host".to_string(),
                        source: source_id.to_string(),
                        ttl_seconds,
                    },
                )?;
            } else {
                push_threat(
                    &mut parsed,
                    source_id,
                    max_material_items,
                    threat(&host, "domain", source_id, ttl_seconds),
                )?;
            }
        }
    }
    require_material(parsed, source_id)
}

fn parse_threatfox(
    source_id: &str,
    ttl_seconds: u64,
    body: &str,
    max_material_items: usize,
) -> Result<ParsedOfficialFeed, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|error| format!("invalid ThreatFox JSON: {error}"))?;
    if value.get("query_status").and_then(Value::as_str) != Some("ok") {
        return Err(format!(
            "ThreatFox query failed: {}",
            value
                .get("query_status")
                .and_then(Value::as_str)
                .unwrap_or("missing query_status")
        ));
    }
    let records = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "ThreatFox response is missing data".to_string())?;
    let mut parsed = ParsedOfficialFeed::default();
    for record in records {
        let Some(ioc) = record.get("ioc").and_then(Value::as_str) else {
            continue;
        };
        let ioc_type = record.get("ioc_type").and_then(Value::as_str).unwrap_or("");
        if ioc_type == "domain" {
            push_threat(
                &mut parsed,
                source_id,
                max_material_items,
                threat(ioc, "domain", source_id, ttl_seconds),
            )?;
        } else if ioc_type.starts_with("ip") {
            let Some(address) = threatfox_ip(ioc) else {
                continue;
            };
            push_threat(
                &mut parsed,
                source_id,
                max_material_items,
                threat(&address.to_string(), "client_ip", source_id, ttl_seconds),
            )?;
            push_dnsbl(
                &mut parsed,
                source_id,
                max_material_items,
                DnsblEntry {
                    address,
                    prefix_len: None,
                    code: "127.0.0.2".to_string(),
                    reason: format!("ThreatFox {ioc_type}: {ioc}"),
                    source: source_id.to_string(),
                    ttl_seconds,
                },
            )?;
        }
    }
    require_material(parsed, source_id)
}

fn push_threat(
    parsed: &mut ParsedOfficialFeed,
    source_id: &str,
    max_material_items: usize,
    indicator: ThreatIndicator,
) -> Result<(), String> {
    ensure_material_capacity(parsed, source_id, max_material_items)?;
    parsed.threats.push(indicator);
    Ok(())
}

fn push_dnsbl(
    parsed: &mut ParsedOfficialFeed,
    source_id: &str,
    max_material_items: usize,
    entry: DnsblEntry,
) -> Result<(), String> {
    ensure_material_capacity(parsed, source_id, max_material_items)?;
    parsed.dnsbl.push(entry);
    Ok(())
}

fn ensure_material_capacity(
    parsed: &ParsedOfficialFeed,
    source_id: &str,
    max_material_items: usize,
) -> Result<(), String> {
    if parsed.threats.len().saturating_add(parsed.dnsbl.len()) >= max_material_items {
        Err(format!(
            "official feed {source_id} exceeded material limit of {max_material_items} items"
        ))
    } else {
        Ok(())
    }
}

fn threat(value: &str, indicator_type: &str, source: &str, ttl_seconds: u64) -> ThreatIndicator {
    ThreatIndicator {
        value: value.to_string(),
        indicator_type: indicator_type.to_string(),
        severity: Severity::High,
        source: source.to_string(),
        ttl_seconds,
    }
}

fn require_material(
    parsed: ParsedOfficialFeed,
    source_id: &str,
) -> Result<ParsedOfficialFeed, String> {
    if parsed.threats.is_empty() && parsed.dnsbl.is_empty() {
        Err(format!(
            "official feed {source_id} contained no supported indicators"
        ))
    } else {
        Ok(parsed)
    }
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR: {value}"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid CIDR address: {value}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("invalid CIDR prefix: {value}"))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(format!("invalid CIDR prefix: {value}"));
    }
    Ok((address, prefix))
}

fn threatfox_ip(value: &str) -> Option<IpAddr> {
    value
        .parse()
        .ok()
        .or_else(|| {
            value
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|socket| socket.ip())
        })
        .or_else(|| value.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_official_feed_shapes_and_rejects_empty_material() {
        let spamhaus = parse(
            "spamhaus_drop_json",
            "spamhaus-drop-v4",
            7200,
            "{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL1\"}\n{\"type\":\"metadata\",\"copyright\":\"Copyright Spamhaus\"}\n",
        )
        .unwrap();
        assert_eq!(spamhaus.dnsbl[0].prefix_len, Some(24));
        assert_eq!(
            spamhaus.source_notice.as_deref(),
            Some("Copyright Spamhaus")
        );
        assert!(
            parse(
                "spamhaus_drop_json",
                "spamhaus-drop-v4",
                7200,
                "{not-json}\n"
            )
            .is_err(),
            "malformed upstream records fail closed before the LKG swap"
        );

        let urlhaus = parse(
            "urlhaus_recent_csv",
            "urlhaus-online",
            7200,
            "# attribution\n# id,dateadded,url,url_status,reporter\n1,2026-01-01,https://evil.example/a,online,\"analyst\n#team\"\n",
        )
        .unwrap();
        assert!(
            urlhaus
                .threats
                .iter()
                .any(|item| item.indicator_type == "domain")
        );
        let urlhaus_ipv6 = parse(
            "urlhaus_recent_csv",
            "urlhaus-online",
            7200,
            "# attribution\n# id,dateadded,url,url_status,reporter\n1,2026-01-01,https://[2001:db8::7]/a,online,analyst\n",
        )
        .unwrap();
        assert!(
            urlhaus_ipv6
                .threats
                .iter()
                .any(|item| item.indicator_type == "client_ip" && item.value == "2001:db8::7")
        );
        assert_eq!(urlhaus_ipv6.dnsbl[0].address.to_string(), "2001:db8::7");
        let urlhaus_mixed_status = parse(
            "urlhaus_recent_csv",
            "urlhaus-online",
            7200,
            "# attribution\n# id,dateadded,url,url_status,reporter\n1,2026-01-01,https://offline.example/a,offline,analyst\n2,2026-01-01,https://active.example/a,online,analyst\n",
        )
        .unwrap();
        assert!(
            urlhaus_mixed_status
                .threats
                .iter()
                .any(|item| item.value == "active.example")
        );
        assert!(urlhaus_mixed_status.threats.iter().all(|item| item.value
            != "https://offline.example/a"
            && item.value != "offline.example"));

        let threatfox = parse(
            "threatfox_json",
            "threatfox-recent",
            7200,
            r#"{"query_status":"ok","data":[{"ioc":"198.51.100.9:443","ioc_type":"ip:port"},{"ioc":"[2001:db8::9]:443","ioc_type":"ip:port"},{"ioc":"bad.example","ioc_type":"domain"}]}"#,
        )
        .unwrap();
        assert_eq!(threatfox.dnsbl[0].address.to_string(), "198.51.100.9");
        assert_eq!(threatfox.dnsbl[1].address.to_string(), "2001:db8::9");
        assert!(
            parse(
                "threatfox_json",
                "x",
                1,
                r#"{"query_status":"no_results","data":[]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn official_feed_parse_fails_closed_when_material_limit_is_exceeded() {
        let err = parse_with_limit(
            "urlhaus_recent_csv",
            "urlhaus-online",
            7200,
            "# attribution\n# id,dateadded,url,url_status,reporter\n1,2026-01-01,https://[2001:db8::7]/a,online,analyst\n2,2026-01-01,https://evil.example/a,online,analyst\n",
            3,
        )
        .unwrap_err();
        assert!(err.contains("exceeded material limit"));
    }
}
