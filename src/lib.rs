use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

const BLOCK_SCORE: u16 = 50;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppData>>,
    http: reqwest::Client,
    admin_token: Option<String>,
}

impl AppState {
    pub fn seeded(admin_token: Option<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AppData::seeded())),
            http: reqwest::Client::new(),
            admin_token,
        }
    }
}

#[derive(Debug)]
struct AppData {
    routes: Vec<RouteConfig>,
    threats: Vec<ThreatIndicator>,
    dnsbl: Vec<DnsblEntry>,
    events: Vec<SecurityEvent>,
    next_event_id: u64,
}

impl AppData {
    fn seeded() -> Self {
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
        }
    }
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
pub struct SocKpiSnapshot {
    pub route_count: usize,
    pub threat_indicator_count: usize,
    pub dnsbl_entry_count: usize,
    pub event_count: usize,
    pub blocked_event_count: usize,
    pub monitor_event_count: usize,
    pub gateway_mode: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/", get(admin_console))
        .route("/admin", get(admin_console))
        .route("/healthz", get(healthz))
        .route("/api/routes", get(list_routes).post(create_route))
        .route("/api/threats", get(list_threats).post(create_threat))
        .route("/api/dnsbl", get(list_dnsbl).post(create_dnsbl))
        .route("/api/events", get(list_events))
        .route("/api/kpis", get(kpis))
        .route("/dnsbl/zone", get(dnsbl_zone))
        .route("/gateway/{*path}", any(gateway))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn admin_console() -> Html<&'static str> {
    Html(ADMIN_HTML)
}

async fn list_routes(State(state): State<AppState>) -> Json<Vec<RouteConfig>> {
    Json(state.inner.read().await.routes.clone())
}

async fn create_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(route): Json<RouteConfig>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    if let Err(message) = validate_route(&route) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let mut data = state.inner.write().await;
    if let Some(existing) = data.routes.iter_mut().find(|item| item.id == route.id) {
        *existing = route.clone();
    } else {
        data.routes.push(route.clone());
    }
    (StatusCode::CREATED, Json(route)).into_response()
}

async fn list_threats(State(state): State<AppState>) -> Json<Vec<ThreatIndicator>> {
    Json(state.inner.read().await.threats.clone())
}

async fn create_threat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(indicator): Json<ThreatIndicator>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    if indicator.value.trim().is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "threat indicator value is required",
        );
    }

    state.inner.write().await.threats.push(indicator.clone());
    (StatusCode::CREATED, Json(indicator)).into_response()
}

async fn list_dnsbl(State(state): State<AppState>) -> Json<Vec<DnsblEntry>> {
    Json(state.inner.read().await.dnsbl.clone())
}

async fn create_dnsbl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(entry): Json<DnsblEntry>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    if IpAddr::from_str(&entry.code).is_err() {
        return error(
            StatusCode::BAD_REQUEST,
            "DNSBL response code must be an IP address",
        );
    }

    state.inner.write().await.dnsbl.push(entry.clone());
    (StatusCode::CREATED, Json(entry)).into_response()
}

async fn list_events(State(state): State<AppState>) -> Json<Vec<SecurityEvent>> {
    Json(state.inner.read().await.events.clone())
}

async fn kpis(State(state): State<AppState>) -> Json<SocKpiSnapshot> {
    let data = state.inner.read().await;
    Json(kpi_snapshot(&data))
}

async fn dnsbl_zone(State(state): State<AppState>) -> impl IntoResponse {
    let data = state.inner.read().await;
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        export_dnsbl_zone("dnsbl.local", &data.dnsbl),
    )
}

async fn gateway(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let gateway_path = uri
        .path()
        .strip_prefix("/gateway")
        .filter(|path| !path.is_empty())
        .unwrap_or("/");

    let (route, threats, dnsbl) = {
        let data = state.inner.read().await;
        let Some(route) = select_route(&data.routes, gateway_path) else {
            return error(
                StatusCode::NOT_FOUND,
                "no gateway route matched the request path",
            );
        };
        (route.clone(), data.threats.clone(), data.dnsbl.clone())
    };

    let client_ip = client_ip_from_headers(&headers);
    let body_text = String::from_utf8_lossy(&body);
    let scored = score_request(
        gateway_path,
        uri.query(),
        &body_text,
        client_ip,
        &threats,
        &dnsbl,
    );

    if route.mode == EnforcementMode::Block && scored.score >= BLOCK_SCORE {
        record_event(
            &state,
            client_ip,
            Some(route.id.clone()),
            "blocked",
            scored.reason.clone(),
            scored.score,
            gateway_path,
        )
        .await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "action": "blocked",
                "route_id": route.id,
                "score": scored.score,
                "reason": scored.reason
            })),
        )
            .into_response();
    }

    record_event(
        &state,
        client_ip,
        Some(route.id.clone()),
        "monitored",
        scored.reason.clone(),
        scored.score,
        gateway_path,
    )
    .await;

    if route.upstream.starts_with("mock://") {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "action": "monitored",
                "route_id": route.id,
                "method": method.as_str(),
                "path": gateway_path,
                "score": scored.score,
                "reason": scored.reason,
                "upstream": route.upstream
            })),
        )
            .into_response();
    }

    match proxy_request(&state, &route, &method, gateway_path, uri.query(), body).await {
        Ok(response) => response,
        Err(message) => error(StatusCode::BAD_GATEWAY, message),
    }
}

fn validate_route(route: &RouteConfig) -> Result<(), &'static str> {
    if route.id.trim().is_empty() {
        return Err("route id is required");
    }
    if !route.path_prefix.starts_with('/') {
        return Err("route path_prefix must start with /");
    }
    if route.upstream.trim().is_empty() {
        return Err("route upstream is required");
    }
    Ok(())
}

fn select_route<'a>(routes: &'a [RouteConfig], path: &str) -> Option<&'a RouteConfig> {
    routes
        .iter()
        .filter(|route| route.enabled && path.starts_with(&route.path_prefix))
        .max_by_key(|route| route.path_prefix.len())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoredRequest {
    pub score: u16,
    pub reason: String,
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

    for indicator in threats {
        if haystack.contains(&indicator.value.to_lowercase()) {
            score += severity_score(&indicator.severity);
            reasons.push(format!(
                "{} indicator from {}",
                indicator.indicator_type, indicator.source
            ));
        }
    }

    if let Some(ip) = client_ip
        && let Some(entry) = dnsbl.iter().find(|entry| entry.address == ip)
    {
        score += 100;
        reasons.push(format!(
            "DNSBL match {} from {}",
            entry.reason, entry.source
        ));
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

fn severity_score(severity: &Severity) -> u16 {
    match severity {
        Severity::Low => 10,
        Severity::Medium => 25,
        Severity::High => 50,
        Severity::Critical => 100,
    }
}

fn client_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
        })
        .and_then(|value| value.parse().ok())
}

async fn proxy_request(
    state: &AppState,
    route: &RouteConfig,
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: Bytes,
) -> Result<Response, String> {
    let target = upstream_target(route, path, query)?;
    let method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|error| format!("unsupported method: {error}"))?;
    let response = state
        .http
        .request(method, target)
        .body(body)
        .send()
        .await
        .map_err(|error| format!("upstream request failed: {error}"))?;
    let status = StatusCode::from_u16(response.status().as_u16())
        .map_err(|error| format!("invalid upstream status: {error}"))?;
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("upstream body read failed: {error}"))?;
    Ok((status, bytes).into_response())
}

pub fn upstream_target(
    route: &RouteConfig,
    path: &str,
    query: Option<&str>,
) -> Result<String, String> {
    if !route.upstream.starts_with("http://") && !route.upstream.starts_with("https://") {
        return Err("upstream must use http:// or https:// for proxy mode".to_string());
    }
    let suffix = path.strip_prefix(&route.path_prefix).unwrap_or(path);
    let suffix = if suffix.starts_with('/') {
        suffix.to_string()
    } else if suffix.is_empty() {
        "/".to_string()
    } else {
        format!("/{suffix}")
    };
    let mut target = format!("{}{}", route.upstream.trim_end_matches('/'), suffix);
    if let Some(query) = query.filter(|value| !value.is_empty()) {
        target.push('?');
        target.push_str(query);
    }
    Ok(target)
}

async fn record_event(
    state: &AppState,
    client_ip: Option<IpAddr>,
    route_id: Option<String>,
    action: &str,
    reason: String,
    score: u16,
    path: &str,
) {
    let mut data = state.inner.write().await;
    let id = data.next_event_id;
    data.next_event_id += 1;
    data.events.push(SecurityEvent {
        id,
        timestamp_unix: now_unix(),
        client_ip,
        route_id,
        action: action.to_string(),
        reason,
        score,
        path: path.to_string(),
    });
}

fn kpi_snapshot(data: &AppData) -> SocKpiSnapshot {
    SocKpiSnapshot {
        route_count: data.routes.len(),
        threat_indicator_count: data.threats.len(),
        dnsbl_entry_count: data.dnsbl.len(),
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
        gateway_mode: "rust-first edge gateway mvp".to_string(),
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

fn admin_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.admin_token.as_deref() else {
        return true;
    };
    headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|actual| actual == expected)
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const ADMIN_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WAF IDS AI SOC</title>
  <style>
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f8fa; color: #18202a; }
    header { padding: 20px 28px; background: #14213d; color: white; }
    main { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; padding: 20px; }
    section { background: white; border: 1px solid #d9dee7; border-radius: 8px; padding: 16px; min-height: 180px; }
    h1 { font-size: 20px; margin: 0; }
    h2 { font-size: 15px; margin: 0 0 10px; }
    pre { white-space: pre-wrap; word-break: break-word; font-size: 12px; line-height: 1.4; }
    .metric { font-size: 28px; font-weight: 700; }
  </style>
</head>
<body>
  <header><h1>ContextualWisdomLab WAF/IDS/AI SOC Gateway</h1></header>
  <main>
    <section><h2>Routes</h2><pre id="routes">Loading</pre></section>
    <section><h2>Threat Indicators</h2><pre id="threats">Loading</pre></section>
    <section><h2>DNSBL Entries</h2><pre id="dnsbl">Loading</pre></section>
    <section><h2>SOC KPIs</h2><div class="metric" id="blocked">0</div><pre id="kpis">Loading</pre></section>
    <section><h2>Recent Events</h2><pre id="events">Loading</pre></section>
    <section><h2>DNSBL Zone</h2><pre id="zone">Loading</pre></section>
  </main>
  <script>
    async function show(id, url) {
      const res = await fetch(url);
      const text = res.headers.get("content-type")?.includes("json")
        ? JSON.stringify(await res.json(), null, 2)
        : await res.text();
      document.getElementById(id).textContent = text;
      return text;
    }
    async function refresh() {
      await Promise.all([
        show("routes", "/api/routes"),
        show("threats", "/api/threats"),
        show("dnsbl", "/api/dnsbl"),
        show("events", "/api/events"),
        show("zone", "/dnsbl/zone"),
      ]);
      const kpiText = await show("kpis", "/api/kpis");
      document.getElementById("blocked").textContent = JSON.parse(kpiText).blocked_event_count;
    }
    refresh();
  </script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> RouteConfig {
        RouteConfig {
            id: "api".to_string(),
            path_prefix: "/api".to_string(),
            upstream: "https://origin.example".to_string(),
            mode: EnforcementMode::Block,
            enabled: true,
        }
    }

    #[test]
    fn reverses_ipv4_for_dnsbl_zone_names() {
        assert_eq!(reverse_ipv4_for_dnsbl([192, 0, 2, 10]), "10.2.0.192");
    }

    #[test]
    fn exports_rfc5782_style_zone_records() {
        let zone = export_dnsbl_zone(
            "dnsbl.example",
            &[DnsblEntry {
                address: "192.0.2.10".parse().unwrap(),
                code: "127.0.0.2".to_string(),
                reason: "scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            }],
        );

        assert!(zone.contains("$ORIGIN dnsbl.example."));
        assert!(zone.contains("10.2.0.192 IN A 127.0.0.2"));
        assert!(zone.contains("10.2.0.192 IN TXT \"scanner source=unit\""));
    }

    #[test]
    fn scores_threat_indicator_matches() {
        let score = score_request(
            "/login",
            Some("q=UNION%20SELECT%20password"),
            "",
            None,
            &[ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::High,
                source: "unit".to_string(),
                ttl_seconds: 60,
            }],
            &[],
        );

        assert_eq!(score.score, 50);
        assert!(score.reason.contains("sqli indicator"));
    }

    #[test]
    fn scores_dnsbl_client_matches() {
        let score = score_request(
            "/",
            None,
            "",
            Some("203.0.113.10".parse().unwrap()),
            &[],
            &[DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.2".to_string(),
                reason: "known scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            }],
        );

        assert_eq!(score.score, 100);
        assert!(score.reason.contains("DNSBL match"));
    }

    #[test]
    fn builds_upstream_target_from_route_prefix() {
        assert_eq!(
            upstream_target(&route(), "/api/v1/items", Some("limit=1")).unwrap(),
            "https://origin.example/v1/items?limit=1"
        );
    }

    #[test]
    fn selects_longest_enabled_route_prefix() {
        let routes = vec![
            route(),
            RouteConfig {
                id: "admin".to_string(),
                path_prefix: "/api/admin".to_string(),
                upstream: "mock://admin".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            },
        ];

        assert_eq!(
            select_route(&routes, "/api/admin/users").unwrap().id,
            "admin"
        );
    }
}
