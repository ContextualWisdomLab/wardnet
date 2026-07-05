use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const BLOCK_SCORE: u16 = 50;
pub const TARGET_SALE_VALUE_KRW: u64 = 2_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppData {
    pub routes: Vec<RouteConfig>,
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
    pub events: Vec<SecurityEvent>,
    pub next_event_id: u64,
    #[serde(default)]
    pub audit_logs: Vec<AuditLogEntry>,
    #[serde(default = "initial_audit_log_id")]
    pub next_audit_log_id: u64,
    #[serde(default = "CommercialProfile::seeded")]
    pub commercial: CommercialProfile,
    #[serde(default)]
    pub threat_feeds: Vec<ThreatFeedStatus>,
}

impl AppData {
    pub fn seeded() -> Self {
        Self {
            routes: vec![RouteConfig {
                id: "demo".to_string(),
                path_prefix: "/demo".to_string(),
                upstream: "mock://demo-upstream".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }],
            threats: vec![ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::High,
                source: "seed:owasp-crs-shape".to_string(),
                ttl_seconds: 86_400,
            }],
            dnsbl: vec![DnsblEntry {
                address: "203.0.113.10".parse().expect("seed IP address is valid"),
                code: "127.0.0.2".to_string(),
                reason: "seed malicious scanner".to_string(),
                source: "seed:dnsbl".to_string(),
                ttl_seconds: 300,
            }],
            events: Vec::new(),
            next_event_id: 1,
            audit_logs: Vec::new(),
            next_audit_log_id: 1,
            commercial: CommercialProfile::seeded(),
            threat_feeds: Vec::new(),
        }
    }
}

fn initial_audit_log_id() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Monitor,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductEdition {
    Community,
    Evaluation,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Unlicensed,
    Evaluation,
    Active,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: String,
    pub path_prefix: String,
    pub upstream: String,
    pub mode: EnforcementMode,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatIndicator {
    pub value: String,
    pub indicator_type: String,
    pub severity: Severity,
    pub source: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsblEntry {
    pub address: IpAddr,
    pub code: String,
    pub reason: String,
    pub source: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommercialProfile {
    pub tenant_id: String,
    pub deployment_id: String,
    pub edition: ProductEdition,
    pub license_status: LicenseStatus,
    pub license_id: Option<String>,
    pub licensee: Option<String>,
    pub licensed_until_unix: Option<u64>,
    pub licensed_node_count: Option<u32>,
    pub annual_contract_value_krw: Option<u64>,
    pub support_contact: String,
    pub features: Vec<String>,
}

impl CommercialProfile {
    pub fn seeded() -> Self {
        Self {
            tenant_id: "local-lab".to_string(),
            deployment_id: "standalone-dev".to_string(),
            edition: ProductEdition::Community,
            license_status: LicenseStatus::Unlicensed,
            license_id: None,
            licensee: None,
            licensed_until_unix: None,
            licensed_node_count: Some(1),
            annual_contract_value_krw: None,
            support_contact: "security@example.invalid".to_string(),
            features: vec![
                "rust-edge-gateway".to_string(),
                "dnsbl-zone-export".to_string(),
                "soc-kpi-api".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatFeedStatus {
    pub feed_id: String,
    pub source: String,
    pub last_updated_unix: u64,
    pub threat_count: usize,
    pub dnsbl_count: usize,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatFeedImport {
    pub feed_id: String,
    pub source: String,
    pub ttl_seconds: u64,
    pub threats: Vec<ThreatIndicator>,
    pub dnsbl: Vec<DnsblEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatFeedImportResult {
    pub feed_id: String,
    pub upserted_threats: usize,
    pub upserted_dnsbl: usize,
    pub last_updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEvent {
    pub id: u64,
    pub timestamp_unix: u64,
    pub client_ip: Option<IpAddr>,
    pub route_id: Option<String>,
    pub action: String,
    pub reason: String,
    pub score: u16,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub id: u64,
    pub timestamp_unix: u64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub resource_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewAuditLogEntry {
    pub timestamp_unix: u64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub resource_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocKpiSnapshot {
    pub route_count: usize,
    pub threat_indicator_count: usize,
    pub dnsbl_entry_count: usize,
    pub threat_feed_count: usize,
    pub fresh_threat_feed_count: usize,
    pub stale_threat_feed_count: usize,
    pub event_count: usize,
    pub blocked_event_count: usize,
    pub monitor_event_count: usize,
    pub audit_log_count: usize,
    pub gateway_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatFeedFreshness {
    pub feed_id: String,
    pub source: String,
    pub last_updated_unix: u64,
    pub threat_count: usize,
    pub dnsbl_count: usize,
    pub ttl_seconds: u64,
    pub expires_at_unix: u64,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessCheck {
    pub id: String,
    pub status: ReadinessStatus,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommercialReadiness {
    pub target_sale_value_krw: u64,
    pub ready_for_enterprise_sale: bool,
    pub readiness_level: String,
    pub blockers: Vec<String>,
    pub checks: Vec<ReadinessCheck>,
    pub deployment_assets: Vec<String>,
    pub buyer_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuyerEvidenceEndpoint {
    pub id: String,
    pub method: String,
    pub path: String,
    pub content_type: String,
    pub proves: String,
    pub required_for_sale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuyerEvidenceRuntimeCounts {
    pub route_count: usize,
    pub threat_indicator_count: usize,
    pub dnsbl_entry_count: usize,
    pub threat_feed_count: usize,
    pub fresh_threat_feed_count: usize,
    pub stale_threat_feed_count: usize,
    pub event_count: usize,
    pub audit_log_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuyerEvidenceManifest {
    pub generated_at_unix: u64,
    pub target_sale_value_krw: u64,
    pub ready_for_enterprise_sale: bool,
    pub readiness_level: String,
    pub blockers: Vec<String>,
    pub runtime_counts: BuyerEvidenceRuntimeCounts,
    pub required_endpoints: Vec<BuyerEvidenceEndpoint>,
    pub document_paths: Vec<String>,
    pub deployment_assets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredRequest {
    pub score: u16,
    pub reason: String,
}

pub fn validate_route(route: &RouteConfig) -> Result<(), &'static str> {
    if route.id.trim().is_empty() {
        return Err("route id is required");
    }
    if !route.path_prefix.starts_with('/') {
        return Err("route path_prefix must start with /");
    }
    if route.path_prefix.contains('?') || route.path_prefix.contains('#') {
        return Err("route path_prefix must not contain query or fragment characters");
    }
    if route.upstream.trim().is_empty() {
        return Err("route upstream is required");
    }
    if !route.upstream.starts_with("mock://")
        && !route.upstream.starts_with("http://")
        && !route.upstream.starts_with("https://")
    {
        return Err("route upstream must start with mock://, http://, or https://");
    }
    Ok(())
}

pub fn validate_threat(indicator: &ThreatIndicator) -> Result<(), &'static str> {
    if indicator.value.trim().is_empty() {
        return Err("threat indicator value is required");
    }
    if indicator.indicator_type.trim().is_empty() {
        return Err("threat indicator type is required");
    }
    if indicator.source.trim().is_empty() {
        return Err("threat indicator source is required");
    }
    if indicator.ttl_seconds == 0 {
        return Err("threat indicator ttl_seconds must be greater than 0");
    }
    Ok(())
}

pub fn validate_dnsbl(entry: &DnsblEntry) -> Result<(), &'static str> {
    if entry.reason.trim().is_empty() {
        return Err("DNSBL reason is required");
    }
    if entry.source.trim().is_empty() {
        return Err("DNSBL source is required");
    }
    if entry.ttl_seconds == 0 {
        return Err("DNSBL ttl_seconds must be greater than 0");
    }
    match IpAddr::from_str(&entry.code) {
        Ok(IpAddr::V4(address)) if address.octets()[0] == 127 => Ok(()),
        Ok(IpAddr::V4(_)) => Err("DNSBL response code must be in 127.0.0.0/8"),
        Ok(IpAddr::V6(_)) => Err("DNSBL response code must be an IPv4 loopback address"),
        Err(_) => Err("DNSBL response code must be an IP address"),
    }
}

pub fn validate_commercial_profile(profile: &CommercialProfile) -> Result<(), &'static str> {
    if profile.tenant_id.trim().is_empty() {
        return Err("commercial tenant_id is required");
    }
    if profile.deployment_id.trim().is_empty() {
        return Err("commercial deployment_id is required");
    }
    if profile.support_contact.trim().is_empty() {
        return Err("commercial support_contact is required");
    }
    if profile.features.is_empty() {
        return Err("commercial features must not be empty");
    }
    if profile.licensed_node_count == Some(0) {
        return Err("commercial licensed_node_count must be greater than 0");
    }
    if matches!(
        profile.license_status,
        LicenseStatus::Active | LicenseStatus::Evaluation
    ) && profile
        .license_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("commercial license_id is required for active or evaluation licenses");
    }
    if matches!(
        profile.license_status,
        LicenseStatus::Active | LicenseStatus::Evaluation
    ) && profile
        .licensee
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("commercial licensee is required for active or evaluation licenses");
    }
    Ok(())
}

pub fn validate_threat_feed_import(feed: &ThreatFeedImport) -> Result<(), &'static str> {
    if feed.feed_id.trim().is_empty() {
        return Err("threat feed_id is required");
    }
    if feed.source.trim().is_empty() {
        return Err("threat feed source is required");
    }
    if feed.ttl_seconds == 0 {
        return Err("threat feed ttl_seconds must be greater than 0");
    }
    if feed.threats.is_empty() && feed.dnsbl.is_empty() {
        return Err("threat feed must include at least one threat or DNSBL entry");
    }
    for threat in &feed.threats {
        validate_threat(threat)?;
    }
    for entry in &feed.dnsbl {
        validate_dnsbl(entry)?;
    }
    Ok(())
}

pub fn upsert_route(routes: &mut Vec<RouteConfig>, route: RouteConfig) -> RouteConfig {
    if let Some(existing) = routes.iter_mut().find(|item| item.id == route.id) {
        *existing = route.clone();
    } else {
        routes.push(route.clone());
    }
    route
}

pub fn upsert_threat(
    threats: &mut Vec<ThreatIndicator>,
    indicator: ThreatIndicator,
) -> ThreatIndicator {
    if let Some(existing) = threats.iter_mut().find(|item| {
        item.indicator_type == indicator.indicator_type
            && item.value == indicator.value
            && item.source == indicator.source
    }) {
        *existing = indicator.clone();
    } else {
        threats.push(indicator.clone());
    }
    indicator
}

pub fn upsert_dnsbl(entries: &mut Vec<DnsblEntry>, entry: DnsblEntry) -> DnsblEntry {
    if let Some(existing) = entries
        .iter_mut()
        .find(|item| item.address == entry.address)
    {
        *existing = entry.clone();
    } else {
        entries.push(entry.clone());
    }
    entry
}

pub fn upsert_threat_feed(
    feeds: &mut Vec<ThreatFeedStatus>,
    feed: ThreatFeedStatus,
) -> ThreatFeedStatus {
    if let Some(existing) = feeds.iter_mut().find(|item| item.feed_id == feed.feed_id) {
        *existing = feed.clone();
    } else {
        feeds.push(feed.clone());
    }
    feed
}

pub fn record_audit_log(data: &mut AppData, entry: NewAuditLogEntry) -> AuditLogEntry {
    let audit_log = AuditLogEntry {
        id: data.next_audit_log_id,
        timestamp_unix: entry.timestamp_unix,
        actor: entry.actor,
        action: entry.action,
        resource: entry.resource,
        resource_id: entry.resource_id,
        outcome: entry.outcome,
    };
    data.next_audit_log_id = data.next_audit_log_id.saturating_add(1);
    data.audit_logs.push(audit_log.clone());
    audit_log
}

pub fn select_route<'a>(routes: &'a [RouteConfig], path: &str) -> Option<&'a RouteConfig> {
    routes
        .iter()
        .filter(|route| route.enabled && path.starts_with(&route.path_prefix))
        .max_by_key(|route| route.path_prefix.len())
}

/// A built-in WAF attack-class signature, applied to every request without any
/// operator configuration. `pattern` is a lowercased token matched against the
/// normalized (path + percent-decoded query + body) haystack. These give the
/// gateway OWASP-shape coverage out of the box, alongside operator-configured
/// [`ThreatIndicator`]s.
pub struct BuiltinSignature {
    pub id: &'static str,
    pub class: &'static str,
    pub pattern: &'static str,
    pub severity: Severity,
}

/// The built-in signature set: curated, high-signal OWASP-shape tokens across
/// the most common web attack classes. Kept deliberately conservative to limit
/// false positives; operator [`ThreatIndicator`]s cover site-specific payloads.
pub fn builtin_signatures() -> &'static [BuiltinSignature] {
    const SIGS: &[BuiltinSignature] = &[
        // SQL injection
        BuiltinSignature {
            id: "sqli-union-select",
            class: "sqli",
            pattern: "union select",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "sqli-or-tautology",
            class: "sqli",
            pattern: "or 1=1",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "sqli-quoted-tautology",
            class: "sqli",
            pattern: "' or '",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "sqli-comment",
            class: "sqli",
            pattern: "'--",
            severity: Severity::Medium,
        },
        BuiltinSignature {
            id: "sqli-sleep",
            class: "sqli",
            pattern: "sleep(",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "sqli-benchmark",
            class: "sqli",
            pattern: "benchmark(",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "sqli-waitfor",
            class: "sqli",
            pattern: "waitfor delay",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "sqli-info-schema",
            class: "sqli",
            pattern: "information_schema",
            severity: Severity::Medium,
        },
        // Cross-site scripting
        BuiltinSignature {
            id: "xss-script-tag",
            class: "xss",
            pattern: "<script",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "xss-javascript-uri",
            class: "xss",
            pattern: "javascript:",
            severity: Severity::Medium,
        },
        BuiltinSignature {
            id: "xss-onerror",
            class: "xss",
            pattern: "onerror=",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "xss-onload",
            class: "xss",
            pattern: "onload=",
            severity: Severity::Medium,
        },
        BuiltinSignature {
            id: "xss-svg",
            class: "xss",
            pattern: "<svg",
            severity: Severity::Medium,
        },
        BuiltinSignature {
            id: "xss-cookie-theft",
            class: "xss",
            pattern: "document.cookie",
            severity: Severity::Medium,
        },
        // Path traversal / local file inclusion
        BuiltinSignature {
            id: "traversal-dotdot",
            class: "path-traversal",
            pattern: "../",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "traversal-dotdot-enc",
            class: "path-traversal",
            pattern: "..%2f",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "traversal-etc-passwd",
            class: "path-traversal",
            pattern: "/etc/passwd",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "traversal-win-ini",
            class: "path-traversal",
            pattern: "\\windows\\win.ini",
            severity: Severity::High,
        },
        // OS command injection
        BuiltinSignature {
            id: "cmdi-cat-etc",
            class: "command-injection",
            pattern: "; cat /",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "cmdi-subshell",
            class: "command-injection",
            pattern: "$(",
            severity: Severity::Medium,
        },
        BuiltinSignature {
            id: "cmdi-pipe-whoami",
            class: "command-injection",
            pattern: "|whoami",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "cmdi-bin-sh",
            class: "command-injection",
            pattern: "/bin/sh",
            severity: Severity::Medium,
        },
        // SSRF / cloud metadata
        BuiltinSignature {
            id: "ssrf-file-uri",
            class: "ssrf",
            pattern: "file://",
            severity: Severity::Medium,
        },
        BuiltinSignature {
            id: "ssrf-gopher",
            class: "ssrf",
            pattern: "gopher://",
            severity: Severity::High,
        },
        BuiltinSignature {
            id: "ssrf-cloud-metadata",
            class: "ssrf",
            pattern: "169.254.169.254",
            severity: Severity::High,
        },
        // JNDI / deserialization (Log4Shell-shape)
        BuiltinSignature {
            id: "jndi-injection",
            class: "deserialization",
            pattern: "${jndi:",
            severity: Severity::Critical,
        },
    ];
    SIGS
}

/// A lightweight behavioral anomaly heuristic (not ML): flags requests whose
/// decoded payload has an unusually high density of shell/markup metacharacters.
/// This is the first-tier "AI SOC" behavioral signal — intentionally conservative
/// so ordinary requests never trip it. Returns `(score_contribution, reason)`.
pub fn anomaly_signal(haystack: &str) -> Option<(u16, String)> {
    const META: &str = "<>'\"();|&$`";
    let suspicious = haystack.chars().filter(|c| META.contains(*c)).count();
    let len = haystack.chars().count().max(1);
    let ratio = suspicious as f64 / len as f64;
    if suspicious >= 6 && ratio >= 0.08 {
        Some((
            15,
            format!(
                "anomaly heuristic: {suspicious} metacharacters ({:.0}% density)",
                ratio * 100.0
            ),
        ))
    } else {
        None
    }
}

pub fn score_request(
    path: &str,
    query: Option<&str>,
    body: &str,
    client_ip: Option<IpAddr>,
    threats: &[ThreatIndicator],
    dnsbl: &[DnsblEntry],
) -> ScoredRequest {
    let decoded_query = query
        .map(|value| percent_decode_str(value).decode_utf8_lossy())
        .unwrap_or_default();
    let haystack = format!("{}?{} {}", path, decoded_query, body).to_lowercase();
    let mut score = 0;
    let mut reasons = Vec::new();

    // Built-in OWASP-shape signatures (no operator configuration required).
    for sig in builtin_signatures() {
        if haystack.contains(sig.pattern) {
            score += severity_score(&sig.severity);
            reasons.push(format!("builtin {} rule {}", sig.class, sig.id));
        }
    }

    // Operator-configured threat indicators.
    for indicator in threats {
        if haystack.contains(&indicator.value.to_lowercase()) {
            score += severity_score(&indicator.severity);
            reasons.push(format!(
                "{} indicator from {}",
                indicator.indicator_type, indicator.source
            ));
        }
    }

    // DNSBL client reputation.
    if let Some(ip) = client_ip
        && let Some(entry) = dnsbl.iter().find(|entry| entry.address == ip)
    {
        score += 100;
        reasons.push(format!(
            "DNSBL match {} from {}",
            entry.reason, entry.source
        ));
    }

    // Behavioral anomaly heuristic (first-tier AI SOC signal).
    if let Some((anomaly, reason)) = anomaly_signal(&haystack) {
        score += anomaly;
        reasons.push(reason);
    }

    ScoredRequest {
        score,
        reason: if reasons.is_empty() {
            "no matching indicator".to_string()
        } else {
            reasons.join("; ")
        },
    }
}

pub fn severity_score(severity: &Severity) -> u16 {
    match severity {
        Severity::Low => 10,
        Severity::Medium => 25,
        Severity::High => 50,
        Severity::Critical => 100,
    }
}

/// Fixed-window rate-limit arithmetic for one client key. Given the current
/// window state `(window_start, count)`, returns `(allowed, new_window_start,
/// new_count)`. `limit == 0` disables limiting (always allowed).
///
/// ponytail: fixed window — permits up to ~2x `limit` across a boundary; swap
/// for a sliding window if that burst matters.
pub fn rate_limit_step(
    now_unix: u64,
    window_start: u64,
    count: u32,
    limit: u32,
    window_secs: u64,
) -> (bool, u64, u32) {
    if limit == 0 {
        return (true, window_start, count);
    }
    if now_unix.saturating_sub(window_start) >= window_secs.max(1) {
        (true, now_unix, 1)
    } else if count < limit {
        (true, window_start, count + 1)
    } else {
        (false, window_start, count)
    }
}

pub fn enforce_event_limit(data: &mut AppData, limit: usize) {
    if data.events.len() > limit {
        let drain_count = data.events.len() - limit;
        data.events.drain(0..drain_count);
    }
}

pub fn threat_feed_freshness_snapshot(
    feeds: &[ThreatFeedStatus],
    now_unix: u64,
) -> Vec<ThreatFeedFreshness> {
    feeds
        .iter()
        .map(|feed| {
            let expires_at_unix = feed.last_updated_unix.saturating_add(feed.ttl_seconds);
            ThreatFeedFreshness {
                feed_id: feed.feed_id.clone(),
                source: feed.source.clone(),
                last_updated_unix: feed.last_updated_unix,
                threat_count: feed.threat_count,
                dnsbl_count: feed.dnsbl_count,
                ttl_seconds: feed.ttl_seconds,
                expires_at_unix,
                stale: expires_at_unix <= now_unix,
            }
        })
        .collect()
}

pub fn kpi_snapshot(data: &AppData) -> SocKpiSnapshot {
    kpi_snapshot_at(data, unix_now())
}

pub fn kpi_snapshot_at(data: &AppData, now_unix: u64) -> SocKpiSnapshot {
    let feed_freshness = threat_feed_freshness_snapshot(&data.threat_feeds, now_unix);
    SocKpiSnapshot {
        route_count: data.routes.len(),
        threat_indicator_count: data.threats.len(),
        dnsbl_entry_count: data.dnsbl.len(),
        threat_feed_count: data.threat_feeds.len(),
        fresh_threat_feed_count: feed_freshness.iter().filter(|feed| !feed.stale).count(),
        stale_threat_feed_count: feed_freshness.iter().filter(|feed| feed.stale).count(),
        event_count: data.events.len(),
        blocked_event_count: data
            .events
            .iter()
            .filter(|event| event.action == "blocked")
            .count(),
        monitor_event_count: data
            .events
            .iter()
            .filter(|event| event.action == "monitored")
            .count(),
        audit_log_count: data.audit_logs.len(),
        gateway_mode: "rust-first edge gateway program baseline".to_string(),
    }
}

pub fn commercial_readiness_snapshot(data: &AppData) -> CommercialReadiness {
    commercial_readiness_snapshot_at(data, unix_now())
}

pub fn commercial_readiness_snapshot_at(data: &AppData, now_unix: u64) -> CommercialReadiness {
    let license_ready = matches!(
        data.commercial.license_status,
        LicenseStatus::Active | LicenseStatus::Evaluation
    ) && data
        .commercial
        .license_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && data
            .commercial
            .licensee
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    let commercial_value_ready = data
        .commercial
        .annual_contract_value_krw
        .is_some_and(|value| value >= TARGET_SALE_VALUE_KRW);
    let threat_feed_ready = threat_feed_freshness_snapshot(&data.threat_feeds, now_unix)
        .iter()
        .any(|feed| !feed.stale && (feed.threat_count > 0 || feed.dnsbl_count > 0));
    let route_ready = data.routes.iter().any(|route| route.enabled);
    let dnsbl_ready = !data.dnsbl.is_empty();
    let support_evidence_ready = !data.events.is_empty();

    let checks = vec![
        readiness_check(
            "license",
            license_ready,
            "active/evaluation tenant license metadata is present",
        ),
        readiness_check(
            "contract_value",
            commercial_value_ready,
            "annual contract value meets the 2B KRW sale target",
        ),
        readiness_check(
            "threat_feed_updates",
            threat_feed_ready,
            "at least one imported threat feed is fresh within its TTL",
        ),
        readiness_check(
            "gateway_enforcement",
            route_ready,
            "at least one enabled gateway route is configured",
        ),
        readiness_check(
            "dnsbl_publication",
            dnsbl_ready,
            "DNSBL entries are available for zone export",
        ),
        readiness_check(
            "support_evidence",
            support_evidence_ready,
            "security event evidence is available for a support bundle",
        ),
    ];
    let blockers: Vec<String> = checks
        .iter()
        .filter(|check| check.status == ReadinessStatus::Fail)
        .map(|check| check.id.clone())
        .collect();
    let ready_for_enterprise_sale = blockers.is_empty();

    CommercialReadiness {
        target_sale_value_krw: TARGET_SALE_VALUE_KRW,
        ready_for_enterprise_sale,
        readiness_level: if ready_for_enterprise_sale {
            "sale_ready".to_string()
        } else {
            "implementation_required".to_string()
        },
        blockers,
        checks,
        deployment_assets: vec![
            "Dockerfile".to_string(),
            "deploy/docker-compose.yml".to_string(),
            "deploy/kubernetes/waf-ids-ai-soc.yaml".to_string(),
        ],
        buyer_evidence: vec![
            "docs/commercial/20b-krw-sale-readiness.md".to_string(),
            "docs/commercial/buyer-due-diligence.md".to_string(),
            "docs/security/threat-model.md".to_string(),
            "docs/security/compliance-mapping.md".to_string(),
        ],
    }
}

pub fn buyer_evidence_manifest(data: &AppData) -> BuyerEvidenceManifest {
    buyer_evidence_manifest_at(data, unix_now())
}

pub fn buyer_evidence_manifest_at(data: &AppData, now_unix: u64) -> BuyerEvidenceManifest {
    let readiness = commercial_readiness_snapshot_at(data, now_unix);
    let kpis = kpi_snapshot_at(data, now_unix);

    BuyerEvidenceManifest {
        generated_at_unix: now_unix,
        target_sale_value_krw: readiness.target_sale_value_krw,
        ready_for_enterprise_sale: readiness.ready_for_enterprise_sale,
        readiness_level: readiness.readiness_level,
        blockers: readiness.blockers,
        runtime_counts: BuyerEvidenceRuntimeCounts {
            route_count: kpis.route_count,
            threat_indicator_count: kpis.threat_indicator_count,
            dnsbl_entry_count: kpis.dnsbl_entry_count,
            threat_feed_count: kpis.threat_feed_count,
            fresh_threat_feed_count: kpis.fresh_threat_feed_count,
            stale_threat_feed_count: kpis.stale_threat_feed_count,
            event_count: kpis.event_count,
            audit_log_count: kpis.audit_log_count,
        },
        required_endpoints: buyer_evidence_endpoints(),
        document_paths: vec![
            "docs/commercial/20b-krw-sale-readiness.md".to_string(),
            "docs/commercial/buyer-due-diligence.md".to_string(),
            "docs/analytics/soc-kpis.md".to_string(),
            "docs/product-design/enterprise-operator-workflows.md".to_string(),
            "docs/figma/enterprise-product-architecture.md".to_string(),
            "docs/ponytail/2026-07-02-complexity-audit.md".to_string(),
        ],
        deployment_assets: readiness.deployment_assets,
    }
}

fn buyer_evidence_endpoints() -> Vec<BuyerEvidenceEndpoint> {
    vec![
        buyer_evidence_endpoint(
            "health",
            "GET",
            "/healthz",
            "application/json",
            "runtime health, persistence mode, DNSBL origin, and event retention limit",
            true,
        ),
        buyer_evidence_endpoint(
            "license",
            "GET",
            "/api/commercial/license",
            "application/json",
            "tenant, edition, license, support, node count, and contract metadata",
            true,
        ),
        buyer_evidence_endpoint(
            "readiness",
            "GET",
            "/api/commercial/readiness",
            "application/json",
            "2B KRW readiness checks and explicit blockers",
            true,
        ),
        buyer_evidence_endpoint(
            "evidence_manifest",
            "GET",
            "/api/commercial/evidence-manifest",
            "application/json",
            "buyer-verifiable evidence map for runtime APIs, docs, and deployment assets",
            true,
        ),
        buyer_evidence_endpoint(
            "feed_freshness",
            "GET",
            "/api/threat-feeds/freshness",
            "application/json",
            "fresh and stale threat-feed evidence from TTL and last update time",
            true,
        ),
        buyer_evidence_endpoint(
            "soc_event_export",
            "GET",
            "/api/events.ndjson",
            "application/x-ndjson",
            "one-security-event-per-line SOC/SIEM ingestion evidence",
            true,
        ),
        buyer_evidence_endpoint(
            "management_audit_logs",
            "GET",
            "/api/audit-logs",
            "application/json",
            "admin write history for buyer due-diligence without admin secrets",
            true,
        ),
        buyer_evidence_endpoint(
            "support_bundle",
            "GET",
            "/api/support-bundle",
            "application/json",
            "support and due-diligence handoff package without admin secrets",
            true,
        ),
        buyer_evidence_endpoint(
            "dnsbl_zone",
            "GET",
            "/dnsbl/zone",
            "text/plain",
            "RFC 5782-style DNSBL zone export for buyer lab DNS validation",
            true,
        ),
    ]
}

fn buyer_evidence_endpoint(
    id: &str,
    method: &str,
    path: &str,
    content_type: &str,
    proves: &str,
    required_for_sale: bool,
) -> BuyerEvidenceEndpoint {
    BuyerEvidenceEndpoint {
        id: id.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        content_type: content_type.to_string(),
        proves: proves.to_string(),
        required_for_sale,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn readiness_check(id: &str, passed: bool, evidence: &str) -> ReadinessCheck {
    ReadinessCheck {
        id: id.to_string(),
        status: if passed {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Fail
        },
        evidence: evidence.to_string(),
    }
}

pub fn export_dnsbl_zone(origin: &str, entries: &[DnsblEntry]) -> String {
    let mut out = format!("$ORIGIN {}.\n$TTL 300\n", origin.trim_end_matches('.'));
    for entry in entries {
        if let IpAddr::V4(address) = entry.address {
            let name = reverse_ipv4_for_dnsbl(address.octets());
            out.push_str(&format!("{} IN A {}\n", name, entry.code));
            out.push_str(&format!(
                "{} IN TXT \"{}\"\n",
                name,
                escape_txt(&format!("{} source={}", entry.reason, entry.source))
            ));
        }
    }
    out
}

pub fn reverse_ipv4_for_dnsbl(octets: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
}

fn escape_txt(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_audit_logs_with_monotonic_ids() {
        let mut data = AppData::seeded();

        let first = record_audit_log(
            &mut data,
            NewAuditLogEntry {
                timestamp_unix: 10,
                actor: "operator@example.com".to_string(),
                action: "upsert_route".to_string(),
                resource: "route".to_string(),
                resource_id: "edge".to_string(),
                outcome: "success".to_string(),
            },
        );
        let second = record_audit_log(
            &mut data,
            NewAuditLogEntry {
                timestamp_unix: 11,
                actor: "operator@example.com".to_string(),
                action: "update_license".to_string(),
                resource: "commercial_license".to_string(),
                resource_id: "cwlab-enterprise".to_string(),
                outcome: "success".to_string(),
            },
        );

        assert_eq!(first.id, 1);
        assert_eq!(second.id, 2);
        assert_eq!(data.audit_logs.len(), 2);
        assert_eq!(data.next_audit_log_id, 3);
        assert_eq!(data.audit_logs[0].resource_id, "edge");
    }
}
