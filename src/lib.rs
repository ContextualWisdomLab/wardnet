use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{any, get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    sync::{Mutex, RwLock},
};
use waf_ids_core::{
    AppData, BLOCK_SCORE, buyer_evidence_manifest_at, commercial_readiness_snapshot_at,
    enforce_event_limit, kpi_snapshot_at, rate_limit_step, record_audit_log, select_route,
    threat_feed_freshness_snapshot, upsert_dnsbl, upsert_route, upsert_threat, upsert_threat_feed,
    validate_commercial_profile, validate_dnsbl, validate_route, validate_threat,
    validate_threat_feed_import,
};
pub use waf_ids_core::{
    AuditLogEntry, BuyerEvidenceEndpoint, BuyerEvidenceManifest, BuyerEvidenceRuntimeCounts,
    CommercialProfile, CommercialReadiness, DnsblEntry, EnforcementMode, LicenseStatus,
    NewAuditLogEntry, ProductEdition, ReadinessCheck, ReadinessStatus, RouteConfig, ScoredRequest,
    SecurityEvent, Severity, SocKpiSnapshot, TARGET_SALE_VALUE_KRW, ThreatFeedFreshness,
    ThreatFeedImport, ThreatFeedImportResult, ThreatFeedStatus, ThreatIndicator, export_dnsbl_zone,
    reverse_ipv4_for_dnsbl, score_request,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppData>>,
    persist_lock: Arc<Mutex<()>>,
    http: reqwest::Client,
    admin_token: Option<String>,
    state_path: Option<PathBuf>,
    dnsbl_origin: String,
    event_limit: usize,
    // Ephemeral per-client-IP fixed-window counters (not persisted).
    // ponytail: unbounded map — add TTL eviction if client-IP cardinality grows.
    rate_limiter: Arc<Mutex<HashMap<IpAddr, (u64, u32)>>>,
    rate_limit: u32,
    rate_limit_window: u64,
}

impl AppState {
    pub fn seeded(admin_token: Option<String>) -> Self {
        Self::new(AppData::seeded(), AppConfig::memory(admin_token))
    }

    pub async fn load(config: AppConfig) -> Result<Self, String> {
        let mut data = match config.state_path.as_deref() {
            Some(path) => load_or_seed_state(path).await?,
            None => AppData::seeded(),
        };
        let event_limit = config.event_limit.max(1);
        enforce_event_limit(&mut data, event_limit);
        if let Some(path) = config.state_path.as_deref() {
            persist_state(path, &data).await?;
        }
        Ok(Self::new(data, config))
    }

    fn new(data: AppData, config: AppConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(data)),
            persist_lock: Arc::new(Mutex::new(())),
            http: reqwest::Client::new(),
            admin_token: config.admin_token,
            state_path: config.state_path,
            dnsbl_origin: normalized_origin(&config.dnsbl_origin),
            event_limit: config.event_limit.max(1),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: 0,
            rate_limit_window: 60,
        }
    }

    /// Enable per-client-IP rate limiting: at most `limit` gateway requests per
    /// `window_secs`. `limit == 0` disables it (the default). Builder-style so
    /// callers keep using [`AppConfig`] unchanged.
    pub fn with_rate_limit(mut self, limit: u32, window_secs: u64) -> Self {
        self.rate_limit = limit;
        self.rate_limit_window = window_secs.max(1);
        self
    }

    /// Records one gateway request for `client_ip` and returns `true` if it is
    /// within the configured rate limit. Unknown IPs share one bucket.
    async fn allow_request(&self, client_ip: Option<IpAddr>) -> bool {
        if self.rate_limit == 0 {
            return true;
        }
        let key = client_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let now = now_unix();
        let mut map = self.rate_limiter.lock().await;
        let (window_start, count) = map.get(&key).copied().unwrap_or((now, 0));
        let (allowed, new_start, new_count) = rate_limit_step(
            now,
            window_start,
            count,
            self.rate_limit,
            self.rate_limit_window,
        );
        map.insert(key, (new_start, new_count));
        allowed
    }

    async fn mutate_and_persist<T>(
        &self,
        mutate: impl FnOnce(&mut AppData) -> T,
    ) -> Result<T, String> {
        let _guard = self.persist_lock.lock().await;
        let (result, snapshot, previous) = {
            let mut data = self.inner.write().await;
            let previous = data.clone();
            let result = mutate(&mut data);
            (result, data.clone(), previous)
        };
        if let Err(error) = self.persist_snapshot(&snapshot).await {
            let mut data = self.inner.write().await;
            *data = previous;
            return Err(error);
        }
        Ok(result)
    }

    async fn persist_snapshot(&self, data: &AppData) -> Result<(), String> {
        let Some(path) = self.state_path.as_deref() else {
            return Ok(());
        };
        persist_state(path, data).await
    }

    fn health_status(&self) -> HealthStatus {
        HealthStatus {
            status: "ok".to_string(),
            persistence: if self.state_path.is_some() {
                "file".to_string()
            } else {
                "memory".to_string()
            },
            dnsbl_origin: self.dnsbl_origin.clone(),
            event_limit: self.event_limit,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub admin_token: Option<String>,
    pub state_path: Option<PathBuf>,
    pub dnsbl_origin: String,
    pub event_limit: usize,
}

impl AppConfig {
    pub const DEFAULT_DNSBL_ORIGIN: &'static str = "dnsbl.local";
    pub const DEFAULT_EVENT_LIMIT: usize = 1_000;

    pub fn memory(admin_token: Option<String>) -> Self {
        Self {
            admin_token,
            state_path: None,
            dnsbl_origin: Self::DEFAULT_DNSBL_ORIGIN.to_string(),
            event_limit: Self::DEFAULT_EVENT_LIMIT,
        }
    }
}

async fn load_or_seed_state(path: &Path) -> Result<AppData, String> {
    match fs::read_to_string(path).await {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|error| format!("state file {} is not valid JSON: {error}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let data = AppData::seeded();
            persist_state(path, &data).await?;
            Ok(data)
        }
        Err(error) => Err(format!(
            "failed to read state file {}: {error}",
            path.display()
        )),
    }
}

async fn persist_state(path: &Path, data: &AppData) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).await.map_err(|error| {
            format!(
                "failed to create state directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let json =
        serde_json::to_vec_pretty(data).expect("AppData contains only JSON-serializable fields");
    let temp_path = temporary_state_path(path);
    fs::write(&temp_path, json).await.map_err(|error| {
        format!(
            "failed to write temporary state file {}: {error}",
            temp_path.display()
        )
    })?;
    if let Err(error) = fs::rename(&temp_path, path).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(format!(
            "failed to replace state file {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

fn temporary_state_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_file_name(format!(".{file_name}.tmp-{}-{unique}", std::process::id()))
}

fn normalized_origin(origin: &str) -> String {
    let trimmed = origin.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        AppConfig::DEFAULT_DNSBL_ORIGIN.to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupportBundle {
    pub generated_at_unix: u64,
    pub health: HealthStatus,
    pub kpis: SocKpiSnapshot,
    pub commercial: CommercialProfile,
    pub readiness: CommercialReadiness,
    pub evidence_manifest: BuyerEvidenceManifest,
    pub threat_feed_freshness: Vec<ThreatFeedFreshness>,
    pub route_count: usize,
    pub threat_indicator_count: usize,
    pub dnsbl_entry_count: usize,
    pub threat_feed_count: usize,
    pub event_count: usize,
    pub audit_log_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthStatus {
    pub status: String,
    pub persistence: String,
    pub dnsbl_origin: String,
    pub event_limit: usize,
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
        .route("/api/audit-logs", get(list_audit_logs))
        .route("/api/events.ndjson", get(events_ndjson))
        .route("/api/kpis", get(kpis))
        .route(
            "/api/commercial/license",
            get(get_commercial_license).post(update_commercial_license),
        )
        .route("/api/commercial/readiness", get(commercial_readiness))
        .route(
            "/api/commercial/evidence-manifest",
            get(commercial_evidence_manifest),
        )
        .route("/api/threat-feeds", get(list_threat_feeds))
        .route("/api/threat-feeds/freshness", get(threat_feed_freshness))
        .route("/api/threat-feeds/import", post(import_threat_feed))
        .route("/api/support-bundle", get(support_bundle))
        .route("/dnsbl/zone", get(dnsbl_zone))
        .route("/gateway/{*path}", any(gateway))
        .with_state(state)
}

pub fn export_events_ndjson(events: &[SecurityEvent]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for event in events {
        out.push_str(&serde_json::to_string(event)?);
        out.push('\n');
    }
    Ok(out)
}

async fn healthz(State(state): State<AppState>) -> Json<HealthStatus> {
    Json(state.health_status())
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

    let actor = audit_actor(&headers);
    match state
        .mutate_and_persist(|data| {
            let saved = upsert_route(&mut data.routes, route.clone());
            record_successful_audit_log(data, actor, "upsert_route", "route", saved.id.clone());
            saved
        })
        .await
    {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
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
    if let Err(message) = validate_threat(&indicator) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let actor = audit_actor(&headers);
    match state
        .mutate_and_persist(|data| {
            let saved = upsert_threat(&mut data.threats, indicator.clone());
            record_successful_audit_log(
                data,
                actor,
                "upsert_threat",
                "threat_indicator",
                threat_resource_id(&saved),
            );
            saved
        })
        .await
    {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
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
    if let Err(message) = validate_dnsbl(&entry) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let actor = audit_actor(&headers);
    match state
        .mutate_and_persist(|data| {
            let saved = upsert_dnsbl(&mut data.dnsbl, entry.clone());
            record_successful_audit_log(
                data,
                actor,
                "upsert_dnsbl",
                "dnsbl_entry",
                saved.address.to_string(),
            );
            saved
        })
        .await
    {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

async fn list_events(State(state): State<AppState>) -> Json<Vec<SecurityEvent>> {
    Json(state.inner.read().await.events.clone())
}

async fn list_audit_logs(State(state): State<AppState>) -> Json<Vec<AuditLogEntry>> {
    Json(state.inner.read().await.audit_logs.clone())
}

async fn kpis(State(state): State<AppState>) -> Json<SocKpiSnapshot> {
    let data = state.inner.read().await;
    Json(kpi_snapshot_at(&data, now_unix()))
}

async fn get_commercial_license(State(state): State<AppState>) -> Json<CommercialProfile> {
    Json(state.inner.read().await.commercial.clone())
}

async fn update_commercial_license(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(profile): Json<CommercialProfile>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    if let Err(message) = validate_commercial_profile(&profile) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let actor = audit_actor(&headers);
    match state
        .mutate_and_persist(|data| {
            data.commercial = profile.clone();
            record_successful_audit_log(
                data,
                actor,
                "update_commercial_license",
                "commercial_license",
                profile.tenant_id.clone(),
            );
            profile
        })
        .await
    {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

async fn commercial_readiness(State(state): State<AppState>) -> Json<CommercialReadiness> {
    let data = state.inner.read().await;
    Json(commercial_readiness_snapshot_at(&data, now_unix()))
}

async fn commercial_evidence_manifest(
    State(state): State<AppState>,
) -> Json<BuyerEvidenceManifest> {
    let data = state.inner.read().await;
    Json(buyer_evidence_manifest_at(&data, now_unix()))
}

async fn list_threat_feeds(State(state): State<AppState>) -> Json<Vec<ThreatFeedStatus>> {
    Json(state.inner.read().await.threat_feeds.clone())
}

async fn threat_feed_freshness(State(state): State<AppState>) -> Json<Vec<ThreatFeedFreshness>> {
    let data = state.inner.read().await;
    Json(threat_feed_freshness_snapshot(
        &data.threat_feeds,
        now_unix(),
    ))
}

async fn import_threat_feed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(feed): Json<ThreatFeedImport>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    if let Err(message) = validate_threat_feed_import(&feed) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let imported_at = now_unix();
    let actor = audit_actor(&headers);
    match state
        .mutate_and_persist(|data| {
            for threat in feed.threats.iter().cloned() {
                upsert_threat(&mut data.threats, threat);
            }
            for entry in feed.dnsbl.iter().cloned() {
                upsert_dnsbl(&mut data.dnsbl, entry);
            }
            upsert_threat_feed(
                &mut data.threat_feeds,
                ThreatFeedStatus {
                    feed_id: feed.feed_id.clone(),
                    source: feed.source.clone(),
                    last_updated_unix: imported_at,
                    threat_count: feed.threats.len(),
                    dnsbl_count: feed.dnsbl.len(),
                    ttl_seconds: feed.ttl_seconds,
                },
            );
            let result = ThreatFeedImportResult {
                feed_id: feed.feed_id.clone(),
                upserted_threats: feed.threats.len(),
                upserted_dnsbl: feed.dnsbl.len(),
                last_updated_unix: imported_at,
            };
            record_successful_audit_log(
                data,
                actor,
                "import_threat_feed",
                "threat_feed",
                result.feed_id.clone(),
            );
            result
        })
        .await
    {
        Ok(result) => (StatusCode::CREATED, Json(result)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

async fn support_bundle(State(state): State<AppState>) -> Json<SupportBundle> {
    let data = state.inner.read().await;
    let generated_at_unix = now_unix();
    Json(SupportBundle {
        generated_at_unix,
        health: state.health_status(),
        kpis: kpi_snapshot_at(&data, generated_at_unix),
        commercial: data.commercial.clone(),
        readiness: commercial_readiness_snapshot_at(&data, generated_at_unix),
        evidence_manifest: buyer_evidence_manifest_at(&data, generated_at_unix),
        threat_feed_freshness: threat_feed_freshness_snapshot(
            &data.threat_feeds,
            generated_at_unix,
        ),
        route_count: data.routes.len(),
        threat_indicator_count: data.threats.len(),
        dnsbl_entry_count: data.dnsbl.len(),
        threat_feed_count: data.threat_feeds.len(),
        event_count: data.events.len(),
        audit_log_count: data.audit_logs.len(),
    })
}

async fn events_ndjson(State(state): State<AppState>) -> Response {
    let data = state.inner.read().await;
    events_ndjson_response(export_events_ndjson(&data.events))
}

fn events_ndjson_response(export: Result<String, serde_json::Error>) -> Response {
    match export {
        Ok(body) => (
            StatusCode::OK,
            [("content-type", "application/x-ndjson; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(err) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize security events: {err}"),
        ),
    }
}

async fn dnsbl_zone(State(state): State<AppState>) -> impl IntoResponse {
    let data = state.inner.read().await;
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        export_dnsbl_zone(&state.dnsbl_origin, &data.dnsbl),
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

    // Rate limiting runs before scoring/proxying so floods are shed cheaply.
    if !state.allow_request(client_ip).await {
        record_event(
            &state,
            client_ip,
            Some(route.id.clone()),
            "rate_limited",
            format!(
                "rate limit exceeded ({} requests per {}s)",
                state.rate_limit, state.rate_limit_window
            ),
            0,
            gateway_path,
        )
        .await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "action": "rate_limited",
                "route_id": route.id,
                "limit": state.rate_limit,
                "window_seconds": state.rate_limit_window
            })),
        )
            .into_response();
    }

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
        .expect("axum HTTP methods are valid reqwest HTTP methods");
    let response = state
        .http
        .request(method, target)
        .body(body)
        .send()
        .await
        .map_err(|error| format!("upstream request failed: {error}"))?;
    let status = StatusCode::from_u16(response.status().as_u16())
        .expect("reqwest upstream status codes are valid axum status codes");
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
    let action = action.to_string();
    let path = path.to_string();
    let event_limit = state.event_limit;
    if let Err(error) = state
        .mutate_and_persist(|data| {
            let id = data.next_event_id;
            data.next_event_id += 1;
            data.events.push(SecurityEvent {
                id,
                timestamp_unix: now_unix(),
                client_ip,
                route_id,
                action,
                reason,
                score,
                path,
            });
            enforce_event_limit(data, event_limit);
        })
        .await
    {
        eprintln!("failed to persist security event: {error}");
    }
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

fn audit_actor(headers: &HeaderMap) -> String {
    headers
        .get("x-admin-actor")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("admin-token")
        .to_string()
}

fn record_successful_audit_log(
    data: &mut AppData,
    actor: String,
    action: &str,
    resource: &str,
    resource_id: String,
) -> AuditLogEntry {
    record_audit_log(
        data,
        NewAuditLogEntry {
            timestamp_unix: now_unix(),
            actor,
            action: action.to_string(),
            resource: resource.to_string(),
            resource_id,
            outcome: "success".to_string(),
        },
    )
}

fn threat_resource_id(indicator: &ThreatIndicator) -> String {
    format!(
        "{}:{}:{}",
        indicator.indicator_type, indicator.value, indicator.source
    )
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
    <section><h2>Commercial Readiness</h2><pre id="readiness">Loading</pre></section>
    <section><h2>Evidence Manifest</h2><pre id="manifest">Loading</pre></section>
    <section><h2>License</h2><pre id="license">Loading</pre></section>
    <section><h2>Threat Feeds</h2><pre id="feeds">Loading</pre></section>
    <section><h2>Feed Freshness</h2><pre id="freshness">Loading</pre></section>
    <section><h2>Recent Events</h2><pre id="events">Loading</pre></section>
    <section><h2>Audit Logs</h2><pre id="auditLogs">Loading</pre></section>
    <section><h2>SOC Event Export</h2><pre id="eventExport">Loading</pre></section>
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
        show("readiness", "/api/commercial/readiness"),
        show("manifest", "/api/commercial/evidence-manifest"),
        show("license", "/api/commercial/license"),
        show("feeds", "/api/threat-feeds"),
        show("freshness", "/api/threat-feeds/freshness"),
        show("events", "/api/events"),
        show("auditLogs", "/api/audit-logs"),
        show("eventExport", "/api/events.ndjson"),
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
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request},
    };
    use serde::de::DeserializeOwned;
    use std::{
        future::IntoFuture,
        io::{Read, Write},
        net::TcpListener as StdTcpListener,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    fn route() -> RouteConfig {
        RouteConfig {
            id: "api".to_string(),
            path_prefix: "/api".to_string(),
            upstream: "https://origin.example".to_string(),
            mode: EnforcementMode::Block,
            enabled: true,
        }
    }

    fn enterprise_profile() -> CommercialProfile {
        CommercialProfile {
            tenant_id: "cwlab-enterprise".to_string(),
            deployment_id: "prod-seoul-edge".to_string(),
            edition: ProductEdition::Enterprise,
            license_status: LicenseStatus::Active,
            license_id: Some("LIC-2B-KRW-0001".to_string()),
            licensee: Some("Contextual Wisdom Enterprise Buyer".to_string()),
            licensed_until_unix: Some(1_829_088_000),
            licensed_node_count: Some(12),
            annual_contract_value_krw: Some(TARGET_SALE_VALUE_KRW),
            support_contact: "soc-support@example.com".to_string(),
            features: vec![
                "rust-edge-gateway".to_string(),
                "tenant-license-readiness".to_string(),
                "threat-feed-import".to_string(),
                "dnsbl-zone-export".to_string(),
            ],
        }
    }

    fn threat_feed_import() -> ThreatFeedImport {
        ThreatFeedImport {
            feed_id: "misp-seoul".to_string(),
            source: "misp://soc.example".to_string(),
            ttl_seconds: 600,
            threats: vec![ThreatIndicator {
                value: "credential_dump".to_string(),
                indicator_type: "malware".to_string(),
                severity: Severity::Critical,
                source: "misp-seoul".to_string(),
                ttl_seconds: 600,
            }],
            dnsbl: vec![DnsblEntry {
                address: "198.51.100.23".parse().unwrap(),
                code: "127.0.0.4".to_string(),
                reason: "feed scanner".to_string(),
                source: "misp-seoul".to_string(),
                ttl_seconds: 600,
            }],
        }
    }

    async fn app_request(app: &Router, request: Request<Body>) -> Response {
        app.clone().oneshot(request).await.unwrap()
    }

    fn empty_request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn json_request<T: Serialize>(
        method: Method,
        uri: &str,
        token: Option<&str>,
        payload: &T,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-admin-token", token);
        }
        builder
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    fn gateway_get_from_ip(uri: &str, ip: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn rate_limit_step_enforces_fixed_window() {
        // limit 0 disables limiting entirely.
        assert_eq!(rate_limit_step(100, 0, 999, 0, 60), (true, 0, 999));
        // First request in a fresh window is allowed and counted.
        assert_eq!(rate_limit_step(100, 100, 0, 2, 60), (true, 100, 1));
        // Second allowed; third (at the limit) rejected without advancing count.
        assert_eq!(rate_limit_step(100, 100, 1, 2, 60), (true, 100, 2));
        assert_eq!(rate_limit_step(100, 100, 2, 2, 60), (false, 100, 2));
        // Once the window elapses the counter resets.
        assert_eq!(rate_limit_step(160, 100, 2, 2, 60), (true, 160, 1));
    }

    #[tokio::test]
    async fn gateway_rate_limits_per_client_ip() {
        let app = build_app(AppState::seeded(None).with_rate_limit(2, 60));

        // Two requests from one IP pass; the third exceeds the budget.
        for i in 0..2 {
            let resp = app_request(&app, gateway_get_from_ip("/gateway/demo", "203.0.113.9")).await;
            assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
        }
        let blocked = app_request(&app, gateway_get_from_ip("/gateway/demo", "203.0.113.9")).await;
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different client IP keeps its own independent budget.
        let other = app_request(&app, gateway_get_from_ip("/gateway/demo", "198.51.100.7")).await;
        assert_eq!(other.status(), StatusCode::OK);
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn json_body<T: DeserializeOwned>(response: Response) -> T {
        serde_json::from_str(&body_text(response).await).unwrap()
    }

    #[test]
    fn reverses_ipv4_for_dnsbl_zone_names() {
        assert_eq!(reverse_ipv4_for_dnsbl([192, 0, 2, 10]), "10.2.0.192");
    }

    #[test]
    fn exports_rfc5782_style_zone_records() {
        let zone = export_dnsbl_zone(
            "dnsbl.example",
            &[
                DnsblEntry {
                    address: "192.0.2.10".parse().unwrap(),
                    code: "127.0.0.2".to_string(),
                    reason: "scanner".to_string(),
                    source: "unit".to_string(),
                    ttl_seconds: 300,
                },
                DnsblEntry {
                    address: "2001:db8::10".parse().unwrap(),
                    code: "127.0.0.2".to_string(),
                    reason: "ipv6 skip".to_string(),
                    source: "unit".to_string(),
                    ttl_seconds: 300,
                },
            ],
        );

        assert!(zone.contains("$ORIGIN dnsbl.example."));
        assert!(zone.contains("10.2.0.192 IN A 127.0.0.2"));
        assert!(zone.contains("10.2.0.192 IN TXT \"scanner source=unit\""));
        assert!(!zone.contains("ipv6 skip"));
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
        assert_eq!(
            upstream_target(&route(), "/api", None).unwrap(),
            "https://origin.example/"
        );
        assert_eq!(
            upstream_target(&route(), "relative", None).unwrap(),
            "https://origin.example/relative"
        );
        assert_eq!(
            upstream_target(
                &RouteConfig {
                    upstream: "mock://origin".to_string(),
                    ..route()
                },
                "/api",
                None,
            )
            .unwrap_err(),
            "upstream must use http:// or https:// for proxy mode"
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

    #[tokio::test]
    async fn admin_api_gateway_and_dnsbl_surfaces_work_together() {
        let path = temp_state_path("api");
        let state = AppState::load(AppConfig {
            admin_token: Some("secret".to_string()),
            state_path: Some(path.clone()),
            dnsbl_origin: "dnsbl.example.".to_string(),
            event_limit: 10,
        })
        .await
        .unwrap();
        let app = build_app(state);

        let response = app_request(&app, empty_request(Method::GET, "/admin")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("WAF/IDS/AI SOC Gateway"));

        let health: HealthStatus =
            json_body(app_request(&app, empty_request(Method::GET, "/healthz")).await).await;
        assert_eq!(health.persistence, "file");
        assert_eq!(health.dnsbl_origin, "dnsbl.example");

        let block_route = RouteConfig {
            id: "secure".to_string(),
            path_prefix: "/secure".to_string(),
            upstream: "mock://secure".to_string(),
            mode: EnforcementMode::Block,
            enabled: true,
        };
        let response = app_request(
            &app,
            json_request(Method::POST, "/api/routes", None, &block_route),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/routes",
                Some("secret"),
                &RouteConfig {
                    path_prefix: "secure".to_string(),
                    ..block_route.clone()
                },
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let saved_route: RouteConfig = json_body(
            app_request(
                &app,
                json_request(Method::POST, "/api/routes", Some("secret"), &block_route),
            )
            .await,
        )
        .await;
        assert_eq!(saved_route.id, "secure");

        let updated_route: RouteConfig = json_body(
            app_request(
                &app,
                json_request(
                    Method::POST,
                    "/api/routes",
                    Some("secret"),
                    &RouteConfig {
                        upstream: "mock://secure-v2".to_string(),
                        ..block_route.clone()
                    },
                ),
            )
            .await,
        )
        .await;
        assert_eq!(updated_route.upstream, "mock://secure-v2");

        let threat = ThreatIndicator {
            value: "drop table".to_string(),
            indicator_type: "sqli".to_string(),
            severity: Severity::Critical,
            source: "unit".to_string(),
            ttl_seconds: 60,
        };
        let response = app_request(
            &app,
            json_request(Method::POST, "/api/threats", None, &threat),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/threats",
                Some("secret"),
                &ThreatIndicator {
                    value: " ".to_string(),
                    ..threat.clone()
                },
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let saved_threat: ThreatIndicator = json_body(
            app_request(
                &app,
                json_request(Method::POST, "/api/threats", Some("secret"), &threat),
            )
            .await,
        )
        .await;
        assert_eq!(saved_threat.value, "drop table");

        let dnsbl = DnsblEntry {
            address: "198.51.100.7".parse().unwrap(),
            code: "127.0.0.9".to_string(),
            reason: "botnet".to_string(),
            source: "unit".to_string(),
            ttl_seconds: 300,
        };
        let response =
            app_request(&app, json_request(Method::POST, "/api/dnsbl", None, &dnsbl)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/dnsbl",
                Some("secret"),
                &DnsblEntry {
                    code: "not-ip".to_string(),
                    ..dnsbl.clone()
                },
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let saved_dnsbl: DnsblEntry = json_body(
            app_request(
                &app,
                json_request(Method::POST, "/api/dnsbl", Some("secret"), &dnsbl),
            )
            .await,
        )
        .await;
        assert_eq!(saved_dnsbl.code, "127.0.0.9");

        let gateway_request = Request::builder()
            .method(Method::POST)
            .uri("/gateway/secure/login?q=DROP%20TABLE")
            .header("x-forwarded-for", "198.51.100.7, 10.0.0.1")
            .body(Body::from("payload"))
            .unwrap();
        let response = app_request(&app, gateway_request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(body_text(response).await.contains("\"action\":\"blocked\""));

        let routes: Vec<RouteConfig> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/routes")).await).await;
        assert!(routes.iter().any(|route| route.id == "secure"));

        let threats: Vec<ThreatIndicator> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/threats")).await).await;
        assert!(threats.iter().any(|item| item.value == "drop table"));

        let dnsbl_entries: Vec<DnsblEntry> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/dnsbl")).await).await;
        assert!(
            dnsbl_entries
                .iter()
                .any(|entry| entry.address == "198.51.100.7".parse::<IpAddr>().unwrap())
        );

        let events: Vec<SecurityEvent> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/events")).await).await;
        assert_eq!(events.last().unwrap().action, "blocked");
        assert_eq!(
            events.last().unwrap().client_ip,
            Some("198.51.100.7".parse().unwrap())
        );
        let events_export =
            body_text(app_request(&app, empty_request(Method::GET, "/api/events.ndjson")).await)
                .await;
        assert!(events_export.contains(r#""action":"blocked""#));
        assert!(events_export.ends_with('\n'));

        let kpis: SocKpiSnapshot =
            json_body(app_request(&app, empty_request(Method::GET, "/api/kpis")).await).await;
        assert_eq!(kpis.blocked_event_count, 1);
        assert_eq!(kpis.threat_feed_count, 0);
        assert_eq!(kpis.fresh_threat_feed_count, 0);
        assert_eq!(kpis.stale_threat_feed_count, 0);

        let zone =
            body_text(app_request(&app, empty_request(Method::GET, "/dnsbl/zone")).await).await;
        assert!(zone.contains("$ORIGIN dnsbl.example."));
        assert!(zone.contains("7.100.51.198 IN A 127.0.0.9"));

        let _ = fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn audit_logs_record_successful_admin_writes_without_tokens() {
        let path = temp_state_path("audit");
        let state = AppState::load(AppConfig {
            admin_token: Some("secret".to_string()),
            state_path: Some(path.clone()),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await
        .unwrap();
        let app = build_app(state);
        let route = RouteConfig {
            id: "audit-route".to_string(),
            path_prefix: "/audit".to_string(),
            upstream: "mock://audit".to_string(),
            mode: EnforcementMode::Monitor,
            enabled: true,
        };

        let unauthorized = app_request(
            &app,
            json_request(Method::POST, "/api/routes", None, &route),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/routes")
                    .header("content-type", "application/json")
                    .header("x-admin-token", "secret")
                    .header("x-admin-actor", "operator@example.com")
                    .body(Body::from(serde_json::to_vec(&route).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let logs: Vec<AuditLogEntry> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/audit-logs")).await).await;
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].actor, "operator@example.com");
        assert_eq!(logs[0].action, "upsert_route");
        assert_eq!(logs[0].resource, "route");
        assert_eq!(logs[0].resource_id, "audit-route");
        assert_eq!(logs[0].outcome, "success");
        assert!(!serde_json::to_string(&logs).unwrap().contains("secret"));

        let persisted: AppData =
            serde_json::from_str(&fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(persisted.audit_logs.len(), 1);
        let persisted_json = serde_json::to_string(&persisted.audit_logs).unwrap();
        assert!(!persisted_json.contains("secret"));
        let _ = fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn commercial_license_feed_readiness_and_bundle_surfaces_work() {
        let path = temp_state_path("commercial");
        let state = AppState::load(AppConfig {
            admin_token: Some("secret".to_string()),
            state_path: Some(path.clone()),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await
        .unwrap();
        let app = build_app(state);

        let initial_readiness: CommercialReadiness = json_body(
            app_request(
                &app,
                empty_request(Method::GET, "/api/commercial/readiness"),
            )
            .await,
        )
        .await;
        assert!(!initial_readiness.ready_for_enterprise_sale);
        assert_eq!(initial_readiness.readiness_level, "implementation_required");
        assert!(
            initial_readiness
                .blockers
                .iter()
                .any(|item| item == "license")
        );

        let initial_license: CommercialProfile = json_body(
            app_request(&app, empty_request(Method::GET, "/api/commercial/license")).await,
        )
        .await;
        assert_eq!(initial_license.license_status, LicenseStatus::Unlicensed);

        let profile = enterprise_profile();
        let unauthorized = app_request(
            &app,
            json_request(Method::POST, "/api/commercial/license", None, &profile),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let bad_profile = CommercialProfile {
            features: Vec::new(),
            ..profile.clone()
        };
        let invalid = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/commercial/license",
                Some("secret"),
                &bad_profile,
            ),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let saved_profile: CommercialProfile = json_body(
            app_request(
                &app,
                json_request(
                    Method::POST,
                    "/api/commercial/license",
                    Some("secret"),
                    &profile,
                ),
            )
            .await,
        )
        .await;
        assert_eq!(saved_profile.annual_contract_value_krw, Some(2_000_000_000));

        let feed = threat_feed_import();
        let unauthorized_feed = app_request(
            &app,
            json_request(Method::POST, "/api/threat-feeds/import", None, &feed),
        )
        .await;
        assert_eq!(unauthorized_feed.status(), StatusCode::UNAUTHORIZED);

        let empty_feed = ThreatFeedImport {
            threats: Vec::new(),
            dnsbl: Vec::new(),
            ..feed.clone()
        };
        let invalid_feed = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/threat-feeds/import",
                Some("secret"),
                &empty_feed,
            ),
        )
        .await;
        assert_eq!(invalid_feed.status(), StatusCode::BAD_REQUEST);

        let import_result: ThreatFeedImportResult = json_body(
            app_request(
                &app,
                json_request(
                    Method::POST,
                    "/api/threat-feeds/import",
                    Some("secret"),
                    &feed,
                ),
            )
            .await,
        )
        .await;
        assert_eq!(import_result.feed_id, "misp-seoul");
        assert_eq!(import_result.upserted_threats, 1);
        assert_eq!(import_result.upserted_dnsbl, 1);

        let gateway_response = app_request(
            &app,
            empty_request(Method::GET, "/gateway/demo?q=union%20select"),
        )
        .await;
        assert_eq!(gateway_response.status(), StatusCode::OK);

        let feeds: Vec<ThreatFeedStatus> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/threat-feeds")).await)
                .await;
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds[0].feed_id, "misp-seoul");
        let freshness: Vec<ThreatFeedFreshness> = json_body(
            app_request(
                &app,
                empty_request(Method::GET, "/api/threat-feeds/freshness"),
            )
            .await,
        )
        .await;
        assert_eq!(freshness.len(), 1);
        assert_eq!(freshness[0].feed_id, "misp-seoul");
        assert!(!freshness[0].stale);

        let final_readiness: CommercialReadiness = json_body(
            app_request(
                &app,
                empty_request(Method::GET, "/api/commercial/readiness"),
            )
            .await,
        )
        .await;
        assert!(final_readiness.ready_for_enterprise_sale);
        assert_eq!(final_readiness.readiness_level, "sale_ready");
        assert!(final_readiness.blockers.is_empty());
        assert!(
            final_readiness
                .deployment_assets
                .iter()
                .any(|path| path == "Dockerfile")
        );

        let manifest: BuyerEvidenceManifest = json_body(
            app_request(
                &app,
                empty_request(Method::GET, "/api/commercial/evidence-manifest"),
            )
            .await,
        )
        .await;
        assert!(manifest.ready_for_enterprise_sale);
        assert_eq!(manifest.target_sale_value_krw, TARGET_SALE_VALUE_KRW);
        assert_eq!(manifest.runtime_counts.threat_feed_count, 1);
        assert_eq!(manifest.runtime_counts.fresh_threat_feed_count, 1);
        assert!(
            manifest
                .required_endpoints
                .iter()
                .any(|endpoint| endpoint.path == "/api/events.ndjson"
                    && endpoint.content_type == "application/x-ndjson"
                    && endpoint.required_for_sale)
        );
        assert!(
            manifest
                .required_endpoints
                .iter()
                .any(|endpoint| endpoint.path == "/api/audit-logs" && endpoint.required_for_sale)
        );
        assert!(
            manifest
                .document_paths
                .iter()
                .any(|path| path == "docs/figma/enterprise-product-architecture.md")
        );

        let support: SupportBundle =
            json_body(app_request(&app, empty_request(Method::GET, "/api/support-bundle")).await)
                .await;
        assert!(support.generated_at_unix > 0);
        assert!(support.readiness.ready_for_enterprise_sale);
        assert!(support.evidence_manifest.ready_for_enterprise_sale);
        assert!(
            support
                .evidence_manifest
                .required_endpoints
                .iter()
                .any(|endpoint| endpoint.path == "/api/commercial/evidence-manifest")
        );
        assert_eq!(
            support.commercial.license_id,
            Some("LIC-2B-KRW-0001".to_string())
        );
        assert_eq!(support.threat_feed_count, 1);
        assert_eq!(support.kpis.fresh_threat_feed_count, 1);
        assert_eq!(support.kpis.stale_threat_feed_count, 0);
        assert!(support.audit_log_count >= 2);
        assert_eq!(support.threat_feed_freshness.len(), 1);
        assert!(!support.threat_feed_freshness[0].stale);
        assert!(support.event_count >= 1);

        let persisted: AppData =
            serde_json::from_str(&fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(persisted.commercial.license_status, LicenseStatus::Active);
        assert_eq!(persisted.threat_feeds.len(), 1);
        let _ = fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn gateway_covers_monitor_proxy_not_found_and_bad_gateway_paths() {
        let upstream_app = Router::new().route(
            "/v1/items",
            any(|| async { (StatusCode::ACCEPTED, "proxied") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(axum::serve(listener, upstream_app).into_future());

        let unused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused_addr = unused_listener.local_addr().unwrap();
        drop(unused_listener);

        let raw_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let raw_addr = raw_listener.local_addr().unwrap();
        let raw_task = thread::spawn(move || {
            let (mut stream, _) = raw_listener.accept().unwrap();
            let mut buffer = [0; 512];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
                .unwrap();
        });

        let state = AppState::new(
            AppData {
                routes: vec![
                    RouteConfig {
                        id: "mock".to_string(),
                        path_prefix: "/mock".to_string(),
                        upstream: "mock://mock".to_string(),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                    },
                    RouteConfig {
                        id: "proxy".to_string(),
                        path_prefix: "/proxy".to_string(),
                        upstream: format!("http://{upstream_addr}"),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                    },
                    RouteConfig {
                        id: "down".to_string(),
                        path_prefix: "/down".to_string(),
                        upstream: format!("http://{unused_addr}"),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                    },
                    RouteConfig {
                        id: "truncated".to_string(),
                        path_prefix: "/truncated".to_string(),
                        upstream: format!("http://{raw_addr}"),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                    },
                ],
                threats: Vec::new(),
                dnsbl: Vec::new(),
                events: Vec::new(),
                next_event_id: 1,
                audit_logs: Vec::new(),
                next_audit_log_id: 1,
                commercial: CommercialProfile::seeded(),
                threat_feeds: Vec::new(),
            },
            AppConfig {
                admin_token: None,
                state_path: None,
                dnsbl_origin: "dnsbl.local".to_string(),
                event_limit: 20,
            },
        );
        let app = build_app(state);

        let no_route = app_request(&app, empty_request(Method::GET, "/gateway/none")).await;
        assert_eq!(no_route.status(), StatusCode::NOT_FOUND);

        let mock_request = Request::builder()
            .method(Method::GET)
            .uri("/gateway/mock")
            .header("x-real-ip", "198.51.100.8")
            .body(Body::empty())
            .unwrap();
        let mock_response = app_request(&app, mock_request).await;
        assert_eq!(mock_response.status(), StatusCode::OK);
        assert!(
            body_text(mock_response)
                .await
                .contains("no matching indicator")
        );

        let proxy_response = app_request(
            &app,
            empty_request(Method::GET, "/gateway/proxy/v1/items?ok=1"),
        )
        .await;
        assert_eq!(proxy_response.status(), StatusCode::ACCEPTED);
        assert_eq!(body_text(proxy_response).await, "proxied");

        let down_response = app_request(&app, empty_request(Method::GET, "/gateway/down")).await;
        assert_eq!(down_response.status(), StatusCode::BAD_GATEWAY);

        let truncated_response =
            app_request(&app, empty_request(Method::GET, "/gateway/truncated")).await;
        assert_eq!(truncated_response.status(), StatusCode::BAD_GATEWAY);
        raw_task.join().unwrap();

        upstream_task.abort();
    }

    #[tokio::test]
    async fn proxy_request_rejects_non_http_upstreams_before_sending() {
        let state = AppState::seeded(None);
        let result = proxy_request(
            &state,
            &RouteConfig {
                id: "mock".to_string(),
                path_prefix: "/mock".to_string(),
                upstream: "mock://mock".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            },
            &Method::GET,
            "/mock",
            None,
            Bytes::new(),
        )
        .await;
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("upstream must use http://"));
    }

    fn temp_state_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "waf-ids-ai-soc-{name}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn loads_missing_state_file_from_seed_and_persists_it() {
        let path = temp_state_path("seed");
        let state = AppState::load(AppConfig {
            admin_token: None,
            state_path: Some(path.clone()),
            dnsbl_origin: "dnsbl.example.".to_string(),
            event_limit: 10,
        })
        .await
        .unwrap();

        let data = state.inner.read().await;
        assert_eq!(data.routes[0].id, "demo");
        drop(data);

        let persisted = fs::read_to_string(&path).await.unwrap();
        assert!(persisted.contains("\"next_event_id\": 1"));
        assert!(persisted.contains("\"demo\""));
        let _ = fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn persists_management_upserts_to_state_file() {
        let path = temp_state_path("upsert");
        let state = AppState::load(AppConfig {
            admin_token: Some("secret".to_string()),
            state_path: Some(path.clone()),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await
        .unwrap();

        state
            .mutate_and_persist(|data| {
                upsert_route(
                    &mut data.routes,
                    RouteConfig {
                        id: "api".to_string(),
                        path_prefix: "/api".to_string(),
                        upstream: "mock://api".to_string(),
                        mode: EnforcementMode::Block,
                        enabled: true,
                    },
                );
            })
            .await
            .unwrap();

        let loaded: AppData =
            serde_json::from_str(&fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(
            loaded
                .routes
                .iter()
                .filter(|route| route.id == "api")
                .count(),
            1
        );
        assert_eq!(
            loaded
                .routes
                .iter()
                .find(|route| route.id == "api")
                .unwrap()
                .mode,
            EnforcementMode::Block
        );
        let _ = fs::remove_file(path).await;
    }

    #[test]
    fn upserts_threats_and_dnsbl_entries_by_stable_keys() {
        let mut threats = vec![ThreatIndicator {
            value: "union select".to_string(),
            indicator_type: "sqli".to_string(),
            severity: Severity::High,
            source: "unit".to_string(),
            ttl_seconds: 60,
        }];

        upsert_threat(
            &mut threats,
            ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::Critical,
                source: "unit".to_string(),
                ttl_seconds: 120,
            },
        );

        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].severity, Severity::Critical);
        assert_eq!(threats[0].ttl_seconds, 120);

        let mut dnsbl = vec![DnsblEntry {
            address: "203.0.113.10".parse().unwrap(),
            code: "127.0.0.2".to_string(),
            reason: "scanner".to_string(),
            source: "unit".to_string(),
            ttl_seconds: 300,
        }];

        upsert_dnsbl(
            &mut dnsbl,
            DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.3".to_string(),
                reason: "botnet".to_string(),
                source: "feed".to_string(),
                ttl_seconds: 600,
            },
        );

        assert_eq!(dnsbl.len(), 1);
        assert_eq!(dnsbl[0].code, "127.0.0.3");
        assert_eq!(dnsbl[0].reason, "botnet");

        let mut feeds = vec![ThreatFeedStatus {
            feed_id: "feed-a".to_string(),
            source: "misp://old".to_string(),
            last_updated_unix: 1,
            threat_count: 1,
            dnsbl_count: 0,
            ttl_seconds: 60,
        }];

        upsert_threat_feed(
            &mut feeds,
            ThreatFeedStatus {
                feed_id: "feed-a".to_string(),
                source: "misp://new".to_string(),
                last_updated_unix: 2,
                threat_count: 2,
                dnsbl_count: 1,
                ttl_seconds: 120,
            },
        );
        upsert_threat_feed(
            &mut feeds,
            ThreatFeedStatus {
                feed_id: "feed-b".to_string(),
                source: "taxii://new".to_string(),
                last_updated_unix: 3,
                threat_count: 1,
                dnsbl_count: 1,
                ttl_seconds: 300,
            },
        );

        assert_eq!(feeds.len(), 2);
        assert_eq!(feeds[0].source, "misp://new");
        assert_eq!(feeds[1].feed_id, "feed-b");
    }

    #[test]
    fn rejects_incomplete_management_records() {
        assert_eq!(
            validate_route(&RouteConfig {
                id: " ".to_string(),
                path_prefix: "/api".to_string(),
                upstream: "mock://api".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }),
            Err("route id is required")
        );
        assert_eq!(
            validate_route(&RouteConfig {
                id: "bad-path".to_string(),
                path_prefix: "api".to_string(),
                upstream: "mock://api".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }),
            Err("route path_prefix must start with /")
        );
        assert_eq!(
            validate_route(&RouteConfig {
                id: "bad-query".to_string(),
                path_prefix: "/api?debug=true".to_string(),
                upstream: "mock://api".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }),
            Err("route path_prefix must not contain query or fragment characters")
        );
        assert_eq!(
            validate_route(&RouteConfig {
                id: "bad-fragment".to_string(),
                path_prefix: "/api#frag".to_string(),
                upstream: "mock://api".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }),
            Err("route path_prefix must not contain query or fragment characters")
        );
        assert_eq!(
            validate_route(&RouteConfig {
                id: "no-upstream".to_string(),
                path_prefix: "/api".to_string(),
                upstream: " ".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }),
            Err("route upstream is required")
        );
        assert_eq!(
            validate_threat(&ThreatIndicator {
                value: " ".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::High,
                source: "unit".to_string(),
                ttl_seconds: 60,
            }),
            Err("threat indicator value is required")
        );
        assert_eq!(
            validate_threat(&ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: " ".to_string(),
                severity: Severity::High,
                source: "unit".to_string(),
                ttl_seconds: 60,
            }),
            Err("threat indicator type is required")
        );
        assert_eq!(
            validate_threat(&ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::High,
                source: " ".to_string(),
                ttl_seconds: 60,
            }),
            Err("threat indicator source is required")
        );
        assert_eq!(
            validate_threat(&ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::High,
                source: "unit".to_string(),
                ttl_seconds: 0,
            }),
            Err("threat indicator ttl_seconds must be greater than 0")
        );
        assert_eq!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.2".to_string(),
                reason: " ".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            }),
            Err("DNSBL reason is required")
        );
        assert_eq!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.2".to_string(),
                reason: "scanner".to_string(),
                source: " ".to_string(),
                ttl_seconds: 300,
            }),
            Err("DNSBL source is required")
        );
        assert_eq!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.2".to_string(),
                reason: "scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 0,
            }),
            Err("DNSBL ttl_seconds must be greater than 0")
        );
        assert_eq!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "192.0.2.1".to_string(),
                reason: "scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            }),
            Err("DNSBL response code must be in 127.0.0.0/8")
        );
        assert_eq!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "::1".to_string(),
                reason: "scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            }),
            Err("DNSBL response code must be an IPv4 loopback address")
        );
        assert_eq!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "not-ip".to_string(),
                reason: "scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            }),
            Err("DNSBL response code must be an IP address")
        );
        assert_eq!(
            validate_route(&RouteConfig {
                id: "bad".to_string(),
                path_prefix: "/api".to_string(),
                upstream: "ftp://origin".to_string(),
                mode: EnforcementMode::Monitor,
                enabled: true,
            }),
            Err("route upstream must start with mock://, http://, or https://")
        );
        assert!(validate_route(&route()).is_ok());
        assert!(
            validate_threat(&ThreatIndicator {
                value: "union select".to_string(),
                indicator_type: "sqli".to_string(),
                severity: Severity::High,
                source: "unit".to_string(),
                ttl_seconds: 60,
            })
            .is_ok()
        );
        assert!(
            validate_dnsbl(&DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.2".to_string(),
                reason: "scanner".to_string(),
                source: "unit".to_string(),
                ttl_seconds: 300,
            })
            .is_ok()
        );
    }

    #[test]
    fn validates_commercial_profiles_and_threat_feed_imports() {
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                tenant_id: " ".to_string(),
                ..enterprise_profile()
            }),
            Err("commercial tenant_id is required")
        );
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                deployment_id: " ".to_string(),
                ..enterprise_profile()
            }),
            Err("commercial deployment_id is required")
        );
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                support_contact: " ".to_string(),
                ..enterprise_profile()
            }),
            Err("commercial support_contact is required")
        );
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                features: Vec::new(),
                ..enterprise_profile()
            }),
            Err("commercial features must not be empty")
        );
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                licensed_node_count: Some(0),
                ..enterprise_profile()
            }),
            Err("commercial licensed_node_count must be greater than 0")
        );
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                license_id: Some(" ".to_string()),
                ..enterprise_profile()
            }),
            Err("commercial license_id is required for active or evaluation licenses")
        );
        assert_eq!(
            validate_commercial_profile(&CommercialProfile {
                licensee: None,
                ..enterprise_profile()
            }),
            Err("commercial licensee is required for active or evaluation licenses")
        );
        assert!(validate_commercial_profile(&enterprise_profile()).is_ok());
        assert!(
            validate_commercial_profile(&CommercialProfile {
                license_status: LicenseStatus::Expired,
                license_id: None,
                licensee: None,
                ..CommercialProfile::seeded()
            })
            .is_ok()
        );

        assert_eq!(
            validate_threat_feed_import(&ThreatFeedImport {
                feed_id: " ".to_string(),
                ..threat_feed_import()
            }),
            Err("threat feed_id is required")
        );
        assert_eq!(
            validate_threat_feed_import(&ThreatFeedImport {
                source: " ".to_string(),
                ..threat_feed_import()
            }),
            Err("threat feed source is required")
        );
        assert_eq!(
            validate_threat_feed_import(&ThreatFeedImport {
                ttl_seconds: 0,
                ..threat_feed_import()
            }),
            Err("threat feed ttl_seconds must be greater than 0")
        );
        assert_eq!(
            validate_threat_feed_import(&ThreatFeedImport {
                threats: Vec::new(),
                dnsbl: Vec::new(),
                ..threat_feed_import()
            }),
            Err("threat feed must include at least one threat or DNSBL entry")
        );
        assert_eq!(
            validate_threat_feed_import(&ThreatFeedImport {
                threats: vec![ThreatIndicator {
                    value: " ".to_string(),
                    indicator_type: "malware".to_string(),
                    severity: Severity::Critical,
                    source: "unit".to_string(),
                    ttl_seconds: 60,
                }],
                ..threat_feed_import()
            }),
            Err("threat indicator value is required")
        );
        assert_eq!(
            validate_threat_feed_import(&ThreatFeedImport {
                dnsbl: vec![DnsblEntry {
                    address: "203.0.113.10".parse().unwrap(),
                    code: "not-ip".to_string(),
                    reason: "scanner".to_string(),
                    source: "unit".to_string(),
                    ttl_seconds: 300,
                }],
                ..threat_feed_import()
            }),
            Err("DNSBL response code must be an IP address")
        );
        assert!(validate_threat_feed_import(&threat_feed_import()).is_ok());
    }

    #[test]
    fn legacy_state_json_defaults_commercial_fields() {
        let legacy = r#"{
          "routes": [],
          "threats": [],
          "dnsbl": [],
          "events": [],
          "next_event_id": 7
        }"#;
        let loaded: AppData = serde_json::from_str(legacy).unwrap();
        assert_eq!(loaded.next_event_id, 7);
        assert_eq!(loaded.commercial.tenant_id, "local-lab");
        assert_eq!(loaded.commercial.license_status, LicenseStatus::Unlicensed);
        assert!(loaded.threat_feeds.is_empty());
    }

    #[test]
    fn readiness_rejects_blank_license_and_accepts_dnsbl_only_feeds() {
        let mut data = AppData::seeded();
        data.threats.clear();
        data.commercial = CommercialProfile {
            license_id: Some(" ".to_string()),
            ..enterprise_profile()
        };
        data.threat_feeds = vec![ThreatFeedStatus {
            feed_id: "dnsbl-only".to_string(),
            source: "misp://dnsbl".to_string(),
            last_updated_unix: 1,
            threat_count: 0,
            dnsbl_count: 1,
            ttl_seconds: 600,
        }];
        data.events.push(SecurityEvent {
            id: 1,
            timestamp_unix: 1,
            client_ip: None,
            route_id: Some("demo".to_string()),
            action: "monitored".to_string(),
            reason: "unit".to_string(),
            score: 0,
            path: "/demo".to_string(),
        });

        let blocked = commercial_readiness_snapshot_at(&data, 1);
        assert!(!blocked.ready_for_enterprise_sale);
        assert!(blocked.blockers.iter().any(|item| item == "license"));

        data.commercial.license_id = Some("LIC-2B-KRW-0001".to_string());
        let ready = commercial_readiness_snapshot_at(&data, 1);
        assert!(ready.ready_for_enterprise_sale);

        let stale = commercial_readiness_snapshot_at(&data, 601);
        assert!(!stale.ready_for_enterprise_sale);
        assert!(
            stale
                .blockers
                .iter()
                .any(|item| item == "threat_feed_updates")
        );
        let freshness = threat_feed_freshness_snapshot(&data.threat_feeds, 601);
        assert!(freshness[0].stale);
        assert_eq!(freshness[0].expires_at_unix, 601);

        let wrapper_kpis = waf_ids_core::kpi_snapshot(&data);
        assert_eq!(wrapper_kpis.route_count, data.routes.len());
        let wrapper_readiness = waf_ids_core::commercial_readiness_snapshot(&data);
        assert_eq!(
            wrapper_readiness.target_sale_value_krw,
            TARGET_SALE_VALUE_KRW
        );
        let wrapper_manifest = waf_ids_core::buyer_evidence_manifest(&data);
        assert_eq!(
            wrapper_manifest.target_sale_value_krw,
            TARGET_SALE_VALUE_KRW
        );

        let manifest = waf_ids_core::buyer_evidence_manifest_at(&data, 1);
        assert!(manifest.ready_for_enterprise_sale);
        assert_eq!(manifest.runtime_counts.dnsbl_entry_count, data.dnsbl.len());
        assert!(
            manifest
                .required_endpoints
                .iter()
                .any(|endpoint| endpoint.id == "dnsbl_zone" && endpoint.required_for_sale)
        );

        let stale_manifest = waf_ids_core::buyer_evidence_manifest_at(&data, 601);
        assert!(!stale_manifest.ready_for_enterprise_sale);
        assert!(
            stale_manifest
                .blockers
                .iter()
                .any(|item| item == "threat_feed_updates")
        );
    }

    #[test]
    fn exports_security_events_as_ndjson() {
        let events = vec![SecurityEvent {
            id: 1,
            timestamp_unix: 10,
            client_ip: Some("198.51.100.7".parse().unwrap()),
            route_id: Some("demo".to_string()),
            action: "blocked".to_string(),
            reason: "unit".to_string(),
            score: 100,
            path: "/demo".to_string(),
        }];

        let export = export_events_ndjson(&events).unwrap();
        assert_eq!(export.lines().count(), 1);
        assert!(export.ends_with('\n'));
        assert!(export.contains(r#""action":"blocked""#));
    }

    #[tokio::test]
    async fn events_ndjson_serialization_errors_are_operator_visible() {
        let response =
            events_ndjson_response(Err(serde_json::Error::io(std::io::Error::other("boom"))));

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body_text(response).await.contains("failed to serialize"));
    }

    #[tokio::test]
    async fn defaults_scoring_and_state_error_paths_are_explicit() {
        let seeded = AppState::seeded(None);
        assert_eq!(seeded.health_status().persistence, "memory");

        let loaded = AppState::load(AppConfig::memory(None)).await.unwrap();
        assert_eq!(loaded.health_status().dnsbl_origin, "dnsbl.local");

        let minimum = AppState::load(AppConfig {
            admin_token: None,
            state_path: None,
            dnsbl_origin: " . ".to_string(),
            event_limit: 0,
        })
        .await
        .unwrap();
        assert_eq!(minimum.health_status().dnsbl_origin, "dnsbl.local");
        assert_eq!(minimum.health_status().event_limit, 1);

        let score = score_request(
            "/login",
            None,
            "alpha beta",
            None,
            &[
                ThreatIndicator {
                    value: "alpha".to_string(),
                    indicator_type: "low".to_string(),
                    severity: Severity::Low,
                    source: "unit".to_string(),
                    ttl_seconds: 60,
                },
                ThreatIndicator {
                    value: "beta".to_string(),
                    indicator_type: "medium".to_string(),
                    severity: Severity::Medium,
                    source: "unit".to_string(),
                    ttl_seconds: 60,
                },
            ],
            &[],
        );
        assert_eq!(score.score, 35);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip_from_headers(&headers), None);

        let valid_path = temp_state_path("valid-load");
        fs::write(
            &valid_path,
            serde_json::to_vec_pretty(&AppData::seeded()).unwrap(),
        )
        .await
        .unwrap();
        let valid_state = AppState::load(AppConfig {
            admin_token: None,
            state_path: Some(valid_path.clone()),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await
        .unwrap();
        assert_eq!(valid_state.inner.read().await.routes[0].id, "demo");
        let _ = fs::remove_file(valid_path).await;

        let local_path = PathBuf::from(format!(
            "waf-ids-state-unit-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        persist_state(&local_path, &AppData::seeded())
            .await
            .unwrap();
        let _ = fs::remove_file(local_path).await;

        let invalid_path = temp_state_path("invalid-json");
        fs::write(&invalid_path, "{").await.unwrap();
        let result = AppState::load(AppConfig {
            admin_token: None,
            state_path: Some(invalid_path.clone()),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await;
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.contains("not valid JSON"));
        let _ = fs::remove_file(invalid_path).await;

        let dir_path = temp_state_path("state-dir");
        fs::create_dir_all(&dir_path).await.unwrap();
        let error = load_or_seed_state(&dir_path).await.unwrap_err();
        assert!(error.contains("failed to read state file"));
        let _ = fs::remove_dir_all(&dir_path).await;

        let parent_file = temp_state_path("parent-file");
        fs::write(&parent_file, "not a directory").await.unwrap();
        let nested_path = parent_file.join("state.json");
        let error = persist_state(&nested_path, &AppData::seeded())
            .await
            .unwrap_err();
        assert!(error.contains("failed to create state directory"));
        let _ = fs::remove_file(parent_file).await;

        let write_dir = temp_state_path("write-dir");
        fs::create_dir_all(&write_dir).await.unwrap();
        let error = persist_state(&write_dir, &AppData::seeded())
            .await
            .unwrap_err();
        assert!(error.contains("failed to replace state file"));
        let _ = fs::remove_dir_all(write_dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn load_surfaces_state_rewrite_failures() {
        use std::os::unix::fs::PermissionsExt;

        let read_only_parent = temp_state_path("read-only-parent");
        fs::create_dir_all(&read_only_parent).await.unwrap();
        let read_only_file = read_only_parent.join("state.json");
        fs::write(
            &read_only_file,
            serde_json::to_vec_pretty(&AppData::seeded()).unwrap(),
        )
        .await
        .unwrap();
        std::fs::set_permissions(&read_only_parent, std::fs::Permissions::from_mode(0o500))
            .unwrap();
        let result = AppState::load(AppConfig {
            admin_token: None,
            state_path: Some(read_only_file.clone()),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await;
        assert!(
            result
                .err()
                .unwrap()
                .contains("failed to write temporary state file")
        );
        std::fs::set_permissions(&read_only_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let _ = fs::remove_dir_all(read_only_parent).await;

        let read_only_dir = temp_state_path("read-only-dir");
        fs::create_dir_all(&read_only_dir).await.unwrap();
        std::fs::set_permissions(&read_only_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = AppState::load(AppConfig {
            admin_token: None,
            state_path: Some(read_only_dir.join("state.json")),
            dnsbl_origin: "dnsbl.example".to_string(),
            event_limit: 10,
        })
        .await;
        assert!(
            result
                .err()
                .unwrap()
                .contains("failed to write temporary state file")
        );
        std::fs::set_permissions(&read_only_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(read_only_dir).await;
    }

    #[tokio::test]
    async fn persistence_failures_return_operator_visible_errors() {
        let failing_path = temp_state_path("persist-dir");
        fs::create_dir_all(&failing_path).await.unwrap();
        let state = AppState::new(
            AppData {
                routes: vec![RouteConfig {
                    id: "mock".to_string(),
                    path_prefix: "/mock".to_string(),
                    upstream: "mock://mock".to_string(),
                    mode: EnforcementMode::Monitor,
                    enabled: true,
                }],
                threats: Vec::new(),
                dnsbl: Vec::new(),
                events: Vec::new(),
                next_event_id: 1,
                audit_logs: Vec::new(),
                next_audit_log_id: 1,
                commercial: CommercialProfile::seeded(),
                threat_feeds: Vec::new(),
            },
            AppConfig {
                admin_token: None,
                state_path: Some(failing_path.clone()),
                dnsbl_origin: "dnsbl.local".to_string(),
                event_limit: 10,
            },
        );
        let app = build_app(state);

        let route_response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/routes",
                None,
                &RouteConfig {
                    id: "new".to_string(),
                    path_prefix: "/new".to_string(),
                    upstream: "mock://new".to_string(),
                    mode: EnforcementMode::Monitor,
                    enabled: true,
                },
            ),
        )
        .await;
        assert_eq!(route_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let routes: Vec<RouteConfig> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/routes")).await).await;
        assert!(!routes.iter().any(|route| route.id == "new"));

        let threat_response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/threats",
                None,
                &ThreatIndicator {
                    value: "union select".to_string(),
                    indicator_type: "sqli".to_string(),
                    severity: Severity::High,
                    source: "unit".to_string(),
                    ttl_seconds: 60,
                },
            ),
        )
        .await;
        assert_eq!(threat_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let threats: Vec<ThreatIndicator> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/threats")).await).await;
        assert!(threats.is_empty());

        let dnsbl_response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/dnsbl",
                None,
                &DnsblEntry {
                    address: "203.0.113.10".parse().unwrap(),
                    code: "127.0.0.2".to_string(),
                    reason: "scanner".to_string(),
                    source: "unit".to_string(),
                    ttl_seconds: 300,
                },
            ),
        )
        .await;
        assert_eq!(dnsbl_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let dnsbl: Vec<DnsblEntry> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/dnsbl")).await).await;
        assert!(dnsbl.is_empty());

        let license_response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/commercial/license",
                None,
                &enterprise_profile(),
            ),
        )
        .await;
        assert_eq!(license_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let license: CommercialProfile = json_body(
            app_request(&app, empty_request(Method::GET, "/api/commercial/license")).await,
        )
        .await;
        assert_eq!(license.license_status, LicenseStatus::Unlicensed);

        let feed_response = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/threat-feeds/import",
                None,
                &threat_feed_import(),
            ),
        )
        .await;
        assert_eq!(feed_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let feeds: Vec<ThreatFeedStatus> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/threat-feeds")).await)
                .await;
        assert!(feeds.is_empty());

        let gateway_response = app_request(&app, empty_request(Method::GET, "/gateway/mock")).await;
        assert_eq!(gateway_response.status(), StatusCode::OK);
        let events: Vec<SecurityEvent> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/events")).await).await;
        assert!(events.is_empty());
        let _ = fs::remove_dir_all(failing_path).await;
    }

    #[tokio::test]
    async fn event_retention_keeps_latest_events_and_next_id() {
        let state = AppState::new(
            AppData::seeded(),
            AppConfig {
                admin_token: None,
                state_path: None,
                dnsbl_origin: "dnsbl.example".to_string(),
                event_limit: 2,
            },
        );

        record_event(
            &state,
            None,
            None,
            "monitored",
            "one".to_string(),
            0,
            "/one",
        )
        .await;
        record_event(
            &state,
            None,
            None,
            "monitored",
            "two".to_string(),
            0,
            "/two",
        )
        .await;
        record_event(
            &state,
            None,
            None,
            "blocked",
            "three".to_string(),
            100,
            "/three",
        )
        .await;

        let data = state.inner.read().await;
        assert_eq!(data.events.len(), 2);
        assert_eq!(data.events[0].id, 2);
        assert_eq!(data.events[1].id, 3);
        assert_eq!(data.next_event_id, 4);
    }

    #[test]
    fn health_reports_runtime_configuration() {
        let state = AppState::new(
            AppData::seeded(),
            AppConfig {
                admin_token: None,
                state_path: Some(PathBuf::from("state.json")),
                dnsbl_origin: "dnsbl.example.".to_string(),
                event_limit: 25,
            },
        );

        assert_eq!(
            state.health_status(),
            HealthStatus {
                status: "ok".to_string(),
                persistence: "file".to_string(),
                dnsbl_origin: "dnsbl.example".to_string(),
                event_limit: 25,
            }
        );
    }
}
