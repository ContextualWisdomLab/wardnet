use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as PathParam, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{any, get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
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
    enforce_event_limit, kpi_snapshot_at, prometheus_exposition, rate_limit_step, record_audit_log,
    select_route, signature_catalog, threat_feed_freshness_snapshot, upsert_dnsbl, upsert_route,
    upsert_threat, upsert_threat_feed, validate_commercial_profile, validate_dnsbl, validate_route,
    validate_threat, validate_threat_feed_import,
};
pub use waf_ids_core::{
    AuditLogEntry, BuyerEvidenceEndpoint, BuyerEvidenceManifest, BuyerEvidenceRuntimeCounts,
    CommercialProfile, CommercialReadiness, DnsblEntry, EnforcementMode, LicenseStatus,
    NewAuditLogEntry, ProductEdition, ReadinessCheck, ReadinessStatus, RouteConfig, ScoredRequest,
    SecurityEvent, Severity, SignatureInfo, SocKpiSnapshot, TARGET_SALE_VALUE_KRW,
    ThreatFeedFreshness, ThreatFeedImport, ThreatFeedImportResult, ThreatFeedStatus,
    ThreatIndicator, export_dnsbl_zone, ip_in_network, reverse_ipv4_for_dnsbl, score_request,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppData>>,
    persist_lock: Arc<Mutex<()>>,
    http: reqwest::Client,
    admin_token: Option<String>,
    // RBAC: multiple admin tokens each mapped to an actor name for audit trails.
    // Empty falls back to the single `admin_token`. Never logged as the actor.
    admin_tokens: HashMap<String, String>,
    state_path: Option<PathBuf>,
    dnsbl_origin: String,
    event_limit: usize,
    // Ephemeral per-client-IP fixed-window counters (not persisted).
    // ponytail: unbounded map — add TTL eviction if client-IP cardinality grows.
    rate_limiter: Arc<Mutex<HashMap<IpAddr, (u64, u32)>>>,
    rate_limit: u32,
    rate_limit_window: u64,
    // Max accepted request body size in bytes; oversized requests get 413.
    max_body_bytes: usize,
    // Optional Clearfolio document-viewer integration. `None` unless configured.
    clearfolio: Option<ClearfolioConfig>,
    // Optional LLM SOC-analysis backend (OpenAI-compatible, e.g. the
    // contextual-orchestrator gateway). `None` unless configured.
    soc_llm: Option<SocLlmConfig>,
}

/// Configuration for the optional LLM-backed SOC analysis. Points at an
/// OpenAI-compatible `/v1/chat/completions` endpoint (the contextual-orchestrator
/// gateway fronts the org OpenAI key). Absent unless `SOC_LLM_BASE_URL` is set.
#[derive(Debug, Clone)]
pub struct SocLlmConfig {
    pub base_url: String,
    pub token: String,
    pub model: String,
}

/// Configuration for the optional Clearfolio document-viewer integration.
/// Absent unless `CLEARFOLIO_BASE_URL` is set. Tenant headers default to the
/// buyer-demo profile (unsigned).
// ponytail: unsigned tenant headers only; add HMAC claim signing
// (`X-Clearfolio-Claims-Signature`) when pointing at an HMAC-enforcing deployment.
#[derive(Debug, Clone)]
pub struct ClearfolioConfig {
    pub base_url: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub permissions: String,
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
            admin_tokens: HashMap::new(),
            state_path: config.state_path,
            dnsbl_origin: normalized_origin(&config.dnsbl_origin),
            event_limit: config.event_limit.max(1),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: 0,
            rate_limit_window: 60,
            max_body_bytes: 1_048_576,
            clearfolio: None,
            soc_llm: None,
        }
    }

    /// Set the maximum accepted request body size in bytes; larger requests are
    /// rejected with 413 before the handler runs. Builder-style.
    pub fn with_max_body_size(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Enable the Clearfolio document-viewer integration. `None` disables it
    /// (the default), so the admin console hides the viewer surface.
    pub fn with_clearfolio(mut self, config: Option<ClearfolioConfig>) -> Self {
        self.clearfolio = config;
        self
    }

    /// Enable LLM-backed SOC analysis via an OpenAI-compatible endpoint. `None`
    /// disables it (the default), hiding the analysis surface in the console.
    pub fn with_soc_llm(mut self, config: Option<SocLlmConfig>) -> Self {
        self.soc_llm = config;
        self
    }

    /// Enable per-client-IP rate limiting: at most `limit` gateway requests per
    /// `window_secs`. `limit == 0` disables it (the default). Builder-style so
    /// callers keep using [`AppConfig`] unchanged.
    pub fn with_rate_limit(mut self, limit: u32, window_secs: u64) -> Self {
        self.rate_limit = limit;
        self.rate_limit_window = window_secs.max(1);
        self
    }

    /// Configure RBAC admin tokens (token -> actor name). A non-empty map takes
    /// precedence over the single `admin_token`. Builder-style.
    pub fn with_admin_tokens(mut self, tokens: HashMap<String, String>) -> Self {
        self.admin_tokens = tokens;
        self
    }

    /// The actor name mapped to the request's `X-Admin-Token`, if that token is a
    /// configured RBAC token.
    fn actor_for_token(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("x-admin-token")
            .and_then(|value| value.to_str().ok())
            .and_then(|token| self.admin_tokens.get(token).cloned())
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

const PHISHING_DATABASE_DEFAULT_FEED_ID: &str = "phishing-database-active";
const PHISHING_DATABASE_DEFAULT_SOURCE: &str =
    "https://github.com/Phishing-Database/Phishing.Database";
const PHISHING_DATABASE_DEFAULT_DOMAIN_URL: &str = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
const PHISHING_DATABASE_DEFAULT_IP_URL: &str = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-IPs-ACTIVE.txt";
const PHISHING_DATABASE_DEFAULT_TTL_SECONDS: u64 = 3_600;
const PHISHING_DATABASE_DEFAULT_DOMAIN_LIMIT: usize = 5_000;
const PHISHING_DATABASE_DEFAULT_IP_LIMIT: usize = 5_000;
const PHISHING_DATABASE_DNSBL_CODE: &str = "127.0.0.66";
const PHISHING_DATABASE_DNSBL_REASON: &str = "phishing.database active IP";
const PHISHING_DATABASE_FETCH_TIMEOUT_SECS: u64 = 15;
const PHISHING_DATABASE_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

fn phishing_database_default_feed_id() -> String {
    PHISHING_DATABASE_DEFAULT_FEED_ID.to_string()
}

fn phishing_database_default_source() -> String {
    PHISHING_DATABASE_DEFAULT_SOURCE.to_string()
}

fn phishing_database_default_domain_url() -> String {
    PHISHING_DATABASE_DEFAULT_DOMAIN_URL.to_string()
}

fn phishing_database_default_ip_url() -> String {
    PHISHING_DATABASE_DEFAULT_IP_URL.to_string()
}

fn phishing_database_default_ttl_seconds() -> u64 {
    PHISHING_DATABASE_DEFAULT_TTL_SECONDS
}

fn phishing_database_default_domain_limit() -> usize {
    PHISHING_DATABASE_DEFAULT_DOMAIN_LIMIT
}

fn phishing_database_default_ip_limit() -> usize {
    PHISHING_DATABASE_DEFAULT_IP_LIMIT
}

fn phishing_database_default_severity() -> Severity {
    Severity::High
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn build_app(state: AppState) -> Router {
    let max_body_bytes = state.max_body_bytes;
    Router::new()
        .route("/", get(admin_console))
        .route("/admin", get(admin_console))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/version", get(version))
        .route("/api/routes", get(list_routes).post(create_route))
        .route("/api/threats", get(list_threats).post(create_threat))
        .route("/api/dnsbl", get(list_dnsbl).post(create_dnsbl))
        .route("/api/events", get(list_events))
        .route("/api/audit-logs", get(list_audit_logs))
        .route("/api/events.ndjson", get(events_ndjson))
        .route("/api/kpis", get(kpis))
        .route("/api/signatures", get(list_signatures))
        .route("/api/evaluate", post(evaluate_request))
        .route("/metrics", get(metrics))
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
        .route(
            "/api/threat-feeds/import/phishing-database",
            post(import_phishing_database_feed),
        )
        .route("/api/clearfolio/config", get(clearfolio_config))
        .route("/api/clearfolio/documents/{kind}", post(clearfolio_submit))
        .route("/api/clearfolio/jobs/{job_id}", get(clearfolio_status))
        .route("/api/soc/llm-config", get(soc_llm_config))
        .route("/api/soc/analyze", post(soc_analyze))
        .route("/api/support-bundle", get(support_bundle))
        .route("/dnsbl/zone", get(dnsbl_zone))
        .route("/gateway/{*path}", any(gateway))
        .layer(DefaultBodyLimit::max(max_body_bytes))
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

// ---- Clearfolio document-viewer integration -------------------------------
// The admin console can hand live SOC evidence to the Clearfolio viewer:
// submit the document (plain text) to Clearfolio's async convert API, then embed
// the resulting `/viewer/{docId}` iframe. Submit + status are thin single-call
// proxies; the browser polls status and drives the iframe (no server-side loop).

fn clearfolio_submit_url(base: &str) -> String {
    format!("{}/api/v1/convert/jobs", base.trim_end_matches('/'))
}

fn clearfolio_status_url(base: &str, job_id: &str) -> String {
    format!(
        "{}/api/v1/convert/jobs/{job_id}",
        base.trim_end_matches('/')
    )
}

fn clearfolio_tenant_headers(config: &ClearfolioConfig) -> [(&'static str, &str); 3] {
    [
        ("X-Clearfolio-Tenant-Id", config.tenant_id.as_str()),
        ("X-Clearfolio-Subject-Id", config.subject_id.as_str()),
        ("X-Clearfolio-Permissions", config.permissions.as_str()),
    ]
}

/// Renders a waf-ids document to plain-text bytes for Clearfolio ingest.
/// Clearfolio only blocks `hwp`/`hwpx`, so text uploads convert normally.
/// Returns `(filename, bytes)` or `None` for an unknown kind.
fn clearfolio_document(kind: &str, data: &AppData) -> Option<(String, Vec<u8>)> {
    let (name, text) = match kind {
        "evidence-manifest" => (
            "evidence-manifest.txt",
            serde_json::to_string_pretty(&buyer_evidence_manifest_at(data, now_unix()))
                .expect("evidence manifest is JSON-serializable"),
        ),
        "soc-export" => (
            "soc-export.txt",
            export_events_ndjson(&data.events).expect("security events are JSON-serializable"),
        ),
        _ => return None,
    };
    Some((name.to_string(), text.into_bytes()))
}

async fn clearfolio_relay_json(response: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(response.status().as_u16())
        .expect("clearfolio status codes are valid HTTP status codes");
    let body = response.bytes().await.unwrap_or_default();
    (status, [("content-type", "application/json")], body).into_response()
}

#[derive(Serialize)]
struct ClearfolioConfigView {
    enabled: bool,
    base_url: Option<String>,
    kinds: [&'static str; 2],
}

/// Reports whether the Clearfolio viewer is configured and its base URL, so the
/// admin console can build viewer iframes. The base URL is not a secret.
async fn clearfolio_config(State(state): State<AppState>) -> Json<ClearfolioConfigView> {
    let base_url = state.clearfolio.as_ref().map(|c| c.base_url.clone());
    Json(ClearfolioConfigView {
        enabled: base_url.is_some(),
        base_url,
        kinds: ["evidence-manifest", "soc-export"],
    })
}

/// Submits a live waf-ids document to Clearfolio for conversion and relays the
/// async job envelope (`jobId`, `status`, `statusUrl`) back to the console.
async fn clearfolio_submit(
    State(state): State<AppState>,
    PathParam(kind): PathParam<String>,
    headers: HeaderMap,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    let Some(config) = state.clearfolio.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Clearfolio integration is not configured",
        );
    };
    let document = {
        let data = state.inner.read().await;
        clearfolio_document(&kind, &data)
    };
    let Some((filename, bytes)) = document else {
        return error(
            StatusCode::NOT_FOUND,
            format!("unknown document kind: {kind}"),
        );
    };
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename)
        .mime_str("text/plain")
        .expect("text/plain is a valid MIME type");
    let form = reqwest::multipart::Form::new().part("file", part);
    let mut request = state
        .http
        .post(clearfolio_submit_url(&config.base_url))
        .multipart(form);
    for (name, value) in clearfolio_tenant_headers(&config) {
        request = request.header(name, value);
    }
    match request.send().await {
        Ok(response) => clearfolio_relay_json(response).await,
        Err(err) => error(
            StatusCode::BAD_GATEWAY,
            format!("clearfolio request failed: {err}"),
        ),
    }
}

/// Proxies one Clearfolio job-status read (tenant headers applied server-side),
/// so the browser can poll conversion progress without holding the credentials.
async fn clearfolio_status(
    State(state): State<AppState>,
    PathParam(job_id): PathParam<String>,
    headers: HeaderMap,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    let Some(config) = state.clearfolio.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Clearfolio integration is not configured",
        );
    };
    let mut request = state
        .http
        .get(clearfolio_status_url(&config.base_url, &job_id));
    for (name, value) in clearfolio_tenant_headers(&config) {
        request = request.header(name, value);
    }
    match request.send().await {
        Ok(response) => clearfolio_relay_json(response).await,
        Err(err) => error(
            StatusCode::BAD_GATEWAY,
            format!("clearfolio request failed: {err}"),
        ),
    }
}

// ---- LLM-backed SOC analysis ----------------------------------------------
// Hands a recorded security event to an OpenAI-compatible chat endpoint (the
// contextual-orchestrator gateway) for analyst-style triage. Single call; the
// request/response shaping is pure and unit-tested, the HTTP glue is thin.

/// Builds an OpenAI `/v1/chat/completions` request body that asks for concise
/// SOC triage of one security event.
fn soc_llm_chat_body(model: &str, event: &SecurityEvent) -> serde_json::Value {
    let client_ip = event
        .client_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let user = format!(
        "WAF/IDS security event:\n- action: {}\n- reason: {}\n- score: {}\n- path: {}\n- client_ip: {}\n- timestamp_unix: {}",
        event.action, event.reason, event.score, event.path, client_ip, event.timestamp_unix
    );
    serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a senior SOC analyst. For the WAF/IDS event, state the likely attack class, a severity judgement, and one recommended action. Answer in under 120 words."
            },
            { "role": "user", "content": user }
        ]
    })
}

/// Extracts the assistant message text from an OpenAI-compatible chat response.
fn soc_llm_extract_content(body: &serde_json::Value) -> Option<String> {
    body.get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()
        .map(|text| text.to_string())
}

#[derive(Serialize)]
struct SocLlmConfigView {
    enabled: bool,
    model: Option<String>,
}

/// Reports whether LLM SOC analysis is configured (and which model), so the
/// admin console can show or hide the analysis surface.
async fn soc_llm_config(State(state): State<AppState>) -> Json<SocLlmConfigView> {
    let model = state.soc_llm.as_ref().map(|c| c.model.clone());
    Json(SocLlmConfigView {
        enabled: model.is_some(),
        model,
    })
}

#[derive(Deserialize)]
struct SocAnalyzeRequest {
    event_id: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PhishingDatabaseImportRequest {
    #[serde(default = "phishing_database_default_feed_id")]
    feed_id: String,
    #[serde(default = "phishing_database_default_source")]
    source: String,
    #[serde(default = "phishing_database_default_domain_url")]
    domain_url: String,
    #[serde(default = "phishing_database_default_ip_url")]
    ip_url: String,
    #[serde(default = "phishing_database_default_ttl_seconds")]
    ttl_seconds: u64,
    #[serde(default = "phishing_database_default_domain_limit")]
    domain_limit: usize,
    #[serde(default = "phishing_database_default_ip_limit")]
    ip_limit: usize,
    #[serde(default = "phishing_database_default_severity")]
    severity: Severity,
    #[serde(default = "default_true")]
    import_domains: bool,
    #[serde(default = "default_true")]
    import_ips: bool,
}

#[derive(Serialize)]
struct SocAnalyzeResponse {
    event_id: u64,
    model: String,
    analysis: String,
}

/// Analyzes one recorded security event with the configured LLM and returns the
/// analyst summary. Admin-authorized; the event is looked up by id.
async fn soc_analyze(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SocAnalyzeRequest>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    let Some(config) = state.soc_llm.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "LLM SOC analysis is not configured",
        );
    };
    let event = {
        let data = state.inner.read().await;
        data.events
            .iter()
            .find(|event| event.id == request.event_id)
            .cloned()
    };
    let Some(event) = event else {
        return error(
            StatusCode::NOT_FOUND,
            format!("unknown event id: {}", request.event_id),
        );
    };
    let body = soc_llm_chat_body(&config.model, &event);
    let endpoint = format!(
        "{}/v1/chat/completions",
        config.base_url.trim_end_matches('/')
    );
    let response = state
        .http
        .post(endpoint)
        .bearer_auth(&config.token)
        .json(&body)
        .send()
        .await;
    match response {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(json) => match soc_llm_extract_content(&json) {
                Some(analysis) => Json(SocAnalyzeResponse {
                    event_id: event.id,
                    model: config.model,
                    analysis,
                })
                .into_response(),
                None => error(
                    StatusCode::BAD_GATEWAY,
                    "llm response missing choices[0].message.content",
                ),
            },
            Err(err) => error(
                StatusCode::BAD_GATEWAY,
                format!("llm response read failed: {err}"),
            ),
        },
        Err(err) => error(
            StatusCode::BAD_GATEWAY,
            format!("llm request failed: {err}"),
        ),
    }
}

async fn healthz(State(state): State<AppState>) -> Json<HealthStatus> {
    Json(state.health_status())
}

/// Build/version metadata for deployment verification.
async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Kubernetes readiness probe: distinct from `/healthz` (liveness), it reports
/// whether the gateway is configured to serve — i.e. has an enabled route.
async fn readyz(State(state): State<AppState>) -> Response {
    let routes_enabled = {
        let data = state.inner.read().await;
        data.routes.iter().filter(|route| route.enabled).count()
    };
    let ready = routes_enabled > 0;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "ready": ready,
            "routes_enabled": routes_enabled,
        })),
    )
        .into_response()
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

    let actor = audit_actor(&state, &headers);
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

    let actor = audit_actor(&state, &headers);
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

    let actor = audit_actor(&state, &headers);
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

#[derive(Deserialize)]
struct EventQuery {
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Lists security events, optionally filtered by `action` and capped to the most
/// recent `limit` (chronological order preserved) for SOC triage.
async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventQuery>,
) -> Json<Vec<SecurityEvent>> {
    let data = state.inner.read().await;
    let mut events: Vec<SecurityEvent> = match &query.action {
        Some(action) => data
            .events
            .iter()
            .filter(|event| &event.action == action)
            .cloned()
            .collect(),
        None => data.events.clone(),
    };
    if let Some(limit) = query.limit {
        let start = events.len().saturating_sub(limit);
        events.drain(..start);
    }
    Json(events)
}

async fn list_audit_logs(State(state): State<AppState>) -> Json<Vec<AuditLogEntry>> {
    Json(state.inner.read().await.audit_logs.clone())
}

async fn kpis(State(state): State<AppState>) -> Json<SocKpiSnapshot> {
    let data = state.inner.read().await;
    Json(kpi_snapshot_at(&data, now_unix()))
}

async fn list_signatures() -> Json<Vec<SignatureInfo>> {
    Json(signature_catalog())
}

#[derive(Deserialize)]
struct EvaluateRequest {
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    client_ip: Option<IpAddr>,
}

#[derive(Serialize)]
struct EvaluateResponse {
    score: u16,
    reason: String,
    would_block: bool,
}

/// Scores a synthetic request against the current detection state without
/// proxying it, so operators can test payloads and tune rules offline.
async fn evaluate_request(
    State(state): State<AppState>,
    Json(request): Json<EvaluateRequest>,
) -> Json<EvaluateResponse> {
    let data = state.inner.read().await;
    let scored = score_request(
        &request.path,
        request.query.as_deref(),
        request.body.as_deref().unwrap_or(""),
        request.client_ip,
        &data.threats,
        &data.dnsbl,
    );
    Json(EvaluateResponse {
        would_block: scored.score >= BLOCK_SCORE,
        score: scored.score,
        reason: scored.reason,
    })
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = {
        let data = state.inner.read().await;
        prometheus_exposition(&kpi_snapshot_at(&data, now_unix()))
    };
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
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

    let actor = audit_actor(&state, &headers);
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

    let actor = audit_actor(&state, &headers);
    match apply_threat_feed_import(&state, actor, "import_threat_feed", feed).await {
        Ok(result) => (StatusCode::CREATED, Json(result)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

async fn import_phishing_database_feed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PhishingDatabaseImportRequest>,
) -> Response {
    if !admin_authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    if let Err(message) = validate_phishing_database_import_request(&request) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let domain_fetch = async {
        if request.import_domains {
            fetch_text_feed(&state, &request.domain_url).await
        } else {
            Ok(String::new())
        }
    };
    let ip_fetch = async {
        if request.import_ips {
            fetch_text_feed(&state, &request.ip_url).await
        } else {
            Ok(String::new())
        }
    };
    let (domain_result, ip_result) = tokio::join!(domain_fetch, ip_fetch);
    let domains_text = match domain_result {
        Ok(text) => text,
        Err(message) => return error(StatusCode::BAD_GATEWAY, message),
    };
    let ips_text = match ip_result {
        Ok(text) => text,
        Err(message) => return error(StatusCode::BAD_GATEWAY, message),
    };

    let source_tag = request.feed_id.clone();
    let threats = if request.import_domains {
        parse_phishing_domains(&domains_text, request.domain_limit)
            .into_iter()
            .map(|domain| ThreatIndicator {
                value: domain,
                indicator_type: "phishing_domain".to_string(),
                severity: request.severity.clone(),
                source: source_tag.clone(),
                ttl_seconds: request.ttl_seconds,
            })
            .collect()
    } else {
        Vec::new()
    };
    let dnsbl = if request.import_ips {
        parse_phishing_ips(&ips_text, request.ip_limit)
            .into_iter()
            .map(|address| DnsblEntry {
                address,
                code: PHISHING_DATABASE_DNSBL_CODE.to_string(),
                reason: PHISHING_DATABASE_DNSBL_REASON.to_string(),
                source: source_tag.clone(),
                ttl_seconds: request.ttl_seconds,
                prefix_len: None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let feed = ThreatFeedImport {
        feed_id: request.feed_id,
        source: request.source,
        ttl_seconds: request.ttl_seconds,
        threats,
        dnsbl,
    };
    if let Err(message) = validate_threat_feed_import(&feed) {
        return error(
            StatusCode::BAD_GATEWAY,
            format!("invalid fetched feed data: {message}"),
        );
    }

    let actor = audit_actor(&state, &headers);
    match apply_threat_feed_import(&state, actor, "import_phishing_database_feed", feed).await {
        Ok(result) => (StatusCode::CREATED, Json(result)).into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

fn validate_phishing_database_import_request(
    request: &PhishingDatabaseImportRequest,
) -> Result<(), &'static str> {
    if request.feed_id.trim().is_empty() {
        return Err("feed_id is required");
    }
    if request.source.trim().is_empty() {
        return Err("source is required");
    }
    if request.ttl_seconds == 0 {
        return Err("ttl_seconds must be greater than zero");
    }
    if !request.import_domains && !request.import_ips {
        return Err("at least one of import_domains or import_ips must be true");
    }
    if request.import_domains {
        if request.domain_limit == 0 {
            return Err("domain_limit must be greater than zero when import_domains is enabled");
        }
        validate_http_url(&request.domain_url)?;
    }
    if request.import_ips {
        if request.ip_limit == 0 {
            return Err("ip_limit must be greater than zero when import_ips is enabled");
        }
        validate_http_url(&request.ip_url)?;
    }
    Ok(())
}

fn validate_http_url(value: &str) -> Result<(), &'static str> {
    let parsed = reqwest::Url::parse(value).map_err(|_| "feed URL must be an absolute URL")?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => Err("feed URL scheme must be http or https"),
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

    if route.mode == EnforcementMode::Block
        && scored.score >= route.block_threshold.unwrap_or(BLOCK_SCORE)
    {
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
            let event = SecurityEvent {
                id,
                timestamp_unix: now_unix(),
                client_ip,
                route_id,
                action,
                reason,
                score,
                path,
            };
            // Structured stdout log line for SIEM / log-collector ingestion.
            // ponytail: one println per recorded event — fine at gateway volumes;
            // add async batching if event throughput ever becomes a bottleneck.
            println!("{}", security_event_log_line(&event));
            data.events.push(event);
            enforce_event_limit(data, event_limit);
        })
        .await
    {
        eprintln!("failed to persist security event: {error}");
    }
}

/// Serializes a [`SecurityEvent`] as a single-line JSON record for structured
/// stdout logging (SIEM / log-collector ingestion).
fn security_event_log_line(event: &SecurityEvent) -> String {
    serde_json::to_string(event).expect("SecurityEvent is JSON-serializable")
}

fn admin_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let presented = headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok());
    // RBAC tokens take precedence when configured.
    if !state.admin_tokens.is_empty() {
        return presented.is_some_and(|token| state.admin_tokens.contains_key(token));
    }
    // Fallback: single shared token (None means auth is disabled).
    let Some(expected) = state.admin_token.as_deref() else {
        return true;
    };
    presented.is_some_and(|actual| actual == expected)
}

fn audit_actor(state: &AppState, headers: &HeaderMap) -> String {
    // Prefer the actor bound to the presented RBAC token, then an explicit
    // actor header, then a generic label. The token itself is never logged.
    if let Some(actor) = state.actor_for_token(headers) {
        return actor;
    }
    headers
        .get("x-admin-actor")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("admin-token")
        .to_string()
}

/// Parses an `ADMIN_TOKENS` string into a token -> actor map. Format is
/// comma-separated `token` or `token:actor` items; an item without an explicit
/// actor is labelled `admin`. Blank items and blank tokens are ignored.
pub fn parse_admin_tokens(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|item| {
            let (token, actor) = match item.split_once(':') {
                Some((token, actor)) => (token.trim(), actor.trim()),
                None => (item.trim(), ""),
            };
            if token.is_empty() {
                return None;
            }
            let actor = if actor.is_empty() { "admin" } else { actor };
            Some((token.to_string(), actor.to_string()))
        })
        .collect()
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

async fn apply_threat_feed_import(
    state: &AppState,
    actor: String,
    action: &'static str,
    feed: ThreatFeedImport,
) -> Result<ThreatFeedImportResult, String> {
    let imported_at = now_unix();
    state
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
            record_successful_audit_log(data, actor, action, "threat_feed", result.feed_id.clone());
            result
        })
        .await
}

async fn fetch_text_feed(state: &AppState, url: &str) -> Result<String, String> {
    validate_http_url(url).map_err(|message| format!("invalid feed URL {url}: {message}"))?;
    let response = state
        .http
        .get(url)
        .timeout(std::time::Duration::from_secs(
            PHISHING_DATABASE_FETCH_TIMEOUT_SECS,
        ))
        .send()
        .await
        .map_err(|error| format!("failed to fetch feed {url}: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("feed {url} returned HTTP {status}"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("failed to read feed body from {url}: {error}"))?;
    if bytes.len() > PHISHING_DATABASE_MAX_BODY_BYTES {
        return Err(format!(
            "feed {url} body too large: {} bytes (limit: {})",
            bytes.len(),
            PHISHING_DATABASE_MAX_BODY_BYTES
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("feed {url} is not valid UTF-8 text: {error}"))
}

fn parse_phishing_domains(feed: &str, limit: usize) -> Vec<String> {
    let mut values = Vec::new();
    let mut unique = HashSet::new();
    for line in feed.lines() {
        let Some(domain) = normalize_phishing_domain(line) else {
            continue;
        };
        if unique.insert(domain.clone()) {
            values.push(domain);
            if values.len() >= limit {
                break;
            }
        }
    }
    values
}

fn normalize_phishing_domain(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    let host = host_port
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.');
    if host.is_empty() || !host.contains('.') || host.starts_with('.') || host.contains("..") {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn parse_phishing_ips(feed: &str, limit: usize) -> Vec<IpAddr> {
    let mut values = Vec::new();
    let mut unique = HashSet::new();
    for line in feed.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Ok(address) = trimmed.parse::<IpAddr>() else {
            continue;
        };
        if unique.insert(address) {
            values.push(address);
            if values.len() >= limit {
                break;
            }
        }
    }
    values
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

const ADMIN_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAF IDS AI SOC — Console</title>
<style>
:root{
  --brand:#14213d;--canvas:#f7f8fa;--surface:#ffffff;--border:#d9dee7;
  --ink:#18202a;--sub:#667085;--on-brand:#ffffff;
  --pass:#1a7f37;--fail:#b3261e;--warn:#9a6700;
  --pass-bg:#e6f4ea;--fail-bg:#fce8e6;--warn-bg:#fff4e5;--brand-bg:#eef1f6;
  --radius:8px;--fs-h1:20px;--fs-h2:15px;--fs-body:14px;--fs-cap:12px;--fs-metric:28px;
}
:root[data-theme=hc]{
  --brand:#000000;--canvas:#ffffff;--surface:#ffffff;--border:#000000;
  --ink:#000000;--sub:#1c1c1c;--on-brand:#ffffff;
  --pass:#0a5c22;--fail:#8a1c14;--warn:#5a3d00;
  --pass-bg:#ffffff;--fail-bg:#ffffff;--warn-bg:#ffffff;--brand-bg:#ffffff;
}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--canvas);color:var(--ink);font-size:var(--fs-body);line-height:1.5}
a.skip{position:absolute;left:-9999px;top:0;background:var(--brand);color:var(--on-brand);padding:10px 16px;z-index:30;border-radius:0 0 6px 0}
a.skip:focus{left:0}
header.app{display:flex;align-items:center;gap:16px;padding:16px 24px;background:var(--brand);color:var(--on-brand)}
header.app h1{font-size:var(--fs-h1);margin:0;font-weight:600;flex:1}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.hdr-input{min-height:44px;border-radius:6px;border:1px solid rgba(255,255,255,.5);background:rgba(255,255,255,.12);color:var(--on-brand);padding:0 12px;font:inherit;width:200px}
.hdr-input::placeholder{color:rgba(255,255,255,.75)}
:root[data-theme=hc] .hdr-input{background:#fff;color:var(--ink);border-color:var(--on-brand)}
button{font:inherit;min-height:44px;padding:0 16px;border-radius:6px;border:1px solid transparent;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid #4c8dff;outline-offset:2px}
.btn-primary{background:var(--brand);color:var(--on-brand);border-color:var(--brand)}
.btn-ghost{background:transparent;color:var(--on-brand);border-color:rgba(255,255,255,.45)}
:root[data-theme=hc] .btn-ghost{border-color:var(--on-brand)}
.btn-secondary{background:var(--surface);color:var(--ink);border-color:var(--border)}
button[aria-pressed=true]{background:var(--on-brand);color:var(--brand)}
main{padding:20px;max-width:1600px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:20px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px}
.tile .label{font-size:var(--fs-cap);color:var(--sub);text-transform:uppercase;letter-spacing:.04em}
.tile .metric{font-size:var(--fs-metric);font-weight:700;margin-top:4px;word-break:break-word}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;align-items:start}
section.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px}
section.card h2{font-size:var(--fs-h2);margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}
caption{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--sub);font-weight:600;font-size:var(--fs-cap);text-transform:uppercase;letter-spacing:.03em}
tbody tr:last-child td{border-bottom:none}
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid;white-space:nowrap}
.badge.mono{font-family:ui-monospace,SFMono-Regular,monospace}
.b-brand{background:var(--brand-bg);color:var(--brand);border-color:var(--brand)}
.b-pass{background:var(--pass-bg);color:var(--pass);border-color:var(--pass)}
.b-fail{background:var(--fail-bg);color:var(--fail);border-color:var(--fail)}
.b-warn{background:var(--warn-bg);color:var(--warn);border-color:var(--warn)}
.b-neutral{background:var(--canvas);color:var(--sub);border-color:var(--border)}
dl.def{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0}
dl.def dt{color:var(--sub);font-size:13px}
dl.def dd{margin:0;font-weight:600;text-align:right;font-size:13px;word-break:break-all}
pre.raw{white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.4;font-family:ui-monospace,SFMono-Regular,monospace;background:var(--canvas);border:1px solid var(--border);border-radius:6px;padding:10px;max-height:220px;overflow:auto;margin:0}
details{margin-top:12px;border-top:1px solid var(--border);padding-top:8px}
summary{cursor:pointer;min-height:44px;display:flex;align-items:center;color:var(--brand);font-size:13px;font-weight:600}
form.stack{display:flex;flex-direction:column;gap:10px;margin-top:8px}
label.field{display:flex;flex-direction:column;gap:4px;font-size:13px;color:var(--sub)}
input,select{font:inherit;min-height:44px;padding:0 12px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--ink)}
.field-help{font-size:12px;color:var(--sub)}
.check{flex-direction:row;align-items:center;gap:8px}
.check input{min-height:auto;width:20px;height:20px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.muted{color:var(--sub);font-size:13px}
.empty{color:var(--sub);font-size:13px;padding:8px 0}
.err{color:var(--fail);font-size:13px;padding:8px 0}
#toast{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:40}
.toast{background:var(--surface);border:1px solid var(--border);border-left-width:4px;border-radius:8px;padding:12px 16px;box-shadow:0 6px 20px rgba(20,33,61,.14);max-width:360px;font-size:13px}
.toast.ok{border-left-color:var(--pass)}
.toast.bad{border-left-color:var(--fail)}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="app">
  <h1>ContextualWisdomLab WAF/IDS/AI SOC Gateway</h1>
  <div class="toolbar">
    <input id="adminToken" class="hdr-input" type="password" placeholder="Admin token (if set)" autocomplete="off" aria-label="Admin token for write operations">
    <button class="btn-ghost" id="hcToggle" aria-pressed="false">High contrast</button>
    <button class="btn-ghost" id="refreshBtn">Refresh</button>
  </div>
</header>
<main id="main">
  <div class="kpis" id="kpis" aria-live="polite"><div class="tile"><div class="label">Loading</div><div class="metric">…</div></div></div>
  <div class="grid">
    <section class="card"><h2>Routes</h2><div id="routesBody" class="muted">Loading…</div>
      <details><summary>+ Add route</summary>
        <form class="stack" id="routeForm" data-url="/api/routes" data-ok="Route">
          <label class="field">Path prefix<input name="path_prefix" placeholder="/demo" required pattern="/.*"><span class="field-help">must start with /</span></label>
          <label class="field">Upstream<input name="upstream" placeholder="mock://demo-upstream" required><span class="field-help">mock:// | http:// | https://</span></label>
          <label class="field">Enforcement mode<select name="mode"><option value="monitor">Monitor</option><option value="block">Block</option></select></label>
          <label class="field check"><input type="checkbox" name="enabled" checked> Enabled</label>
          <div class="row"><button type="submit" class="btn-primary">Save route</button><button type="reset" class="btn-secondary">Reset</button></div>
        </form>
      </details>
    </section>
    <section class="card"><h2>Threat indicators</h2><div id="threatsBody" class="muted">Loading…</div>
      <details><summary>+ Add threat indicator</summary>
        <form class="stack" id="threatForm" data-url="/api/threats" data-ok="Threat indicator">
          <label class="field">Value<input name="value" placeholder="union select" required></label>
          <label class="field">Type<input name="indicator_type" placeholder="sqli" required></label>
          <label class="field">Severity<select name="severity"><option value="low">Low</option><option value="medium">Medium</option><option value="high" selected>High</option><option value="critical">Critical</option></select></label>
          <label class="field">Source<input name="source" placeholder="seed:owasp-crs-shape" required></label>
          <label class="field">TTL (seconds)<input name="ttl_seconds" type="number" min="1" value="86400" required></label>
          <div class="row"><button type="submit" class="btn-primary">Save indicator</button><button type="reset" class="btn-secondary">Reset</button></div>
        </form>
      </details>
    </section>
    <section class="card"><h2>DNSBL entries</h2><div id="dnsblBody" class="muted">Loading…</div>
      <details><summary>+ Add DNSBL entry</summary>
        <form class="stack" id="dnsblForm" data-url="/api/dnsbl" data-ok="DNSBL entry">
          <label class="field">Address<input name="address" placeholder="203.0.113.10" required><span class="field-help">IP address</span></label>
          <label class="field">Response code<input name="code" placeholder="127.0.0.2" required><span class="field-help">must be in 127.0.0.0/8</span></label>
          <label class="field">Reason<input name="reason" placeholder="seed malicious scanner" required></label>
          <label class="field">Source<input name="source" placeholder="seed:dnsbl" required></label>
          <label class="field">TTL (seconds)<input name="ttl_seconds" type="number" min="1" value="300" required></label>
          <div class="row"><button type="submit" class="btn-primary">Save entry</button><button type="reset" class="btn-secondary">Reset</button></div>
        </form>
      </details>
    </section>
    <section class="card"><h2>Commercial readiness</h2><div id="readinessBody" class="muted">Loading…</div></section>
    <section class="card"><h2>License</h2><div id="licenseBody" class="muted">Loading…</div>
      <details><summary>+ Update license</summary>
        <form class="stack" id="licenseForm" data-url="/api/commercial/license" data-ok="License">
          <label class="field">Tenant ID<input name="tenant_id" placeholder="local-lab" required></label>
          <label class="field">Deployment ID<input name="deployment_id" placeholder="standalone-dev" required></label>
          <label class="field">Edition<select name="edition"><option value="community">Community</option><option value="evaluation">Evaluation</option><option value="enterprise">Enterprise</option></select></label>
          <label class="field">License status<select name="license_status"><option value="unlicensed">Unlicensed</option><option value="evaluation">Evaluation</option><option value="active">Active</option><option value="expired">Expired</option></select></label>
          <label class="field">Support contact<input name="support_contact" placeholder="security@example.invalid" required></label>
          <label class="field">Features<input name="features" placeholder="rust-edge-gateway, dnsbl-zone-export" required><span class="field-help">comma-separated, at least one</span></label>
          <label class="field">Licensee<input name="licensee" placeholder="required for active / evaluation"></label>
          <label class="field">License ID<input name="license_id" placeholder="required for active / evaluation"></label>
          <div class="row"><button type="submit" class="btn-primary">Save license</button><button type="reset" class="btn-secondary">Reset</button></div>
        </form>
      </details>
    </section>
    <section class="card"><h2>Threat feeds</h2><div id="feedsBody" class="muted">Loading…</div></section>
    <section class="card"><h2>Recent events</h2><div id="eventsBody" class="muted">Loading…</div></section>
    <section class="card" id="socLlmCard" hidden><h2>AI SOC analysis (LLM)</h2>
      <p class="muted">Triage a recorded security event with the configured LLM (contextual-orchestrator).</p>
      <div class="row">
        <input id="socEventId" class="hdr-input" type="number" min="1" placeholder="Event id" aria-label="Security event id to analyze">
        <button type="button" id="socAnalyzeBtn" class="btn-secondary">Analyze event</button>
      </div>
      <pre class="raw" id="socAnalysis" style="margin-top:8px;white-space:pre-wrap"></pre>
    </section>
    <section class="card"><h2>Audit log</h2><div id="auditBody" class="muted">Loading…</div></section>
    <section class="card"><h2>Evidence manifest</h2><pre class="raw" id="manifest">Loading…</pre></section>
    <section class="card"><h2>SOC event export (ndjson)</h2><pre class="raw" id="export">Loading…</pre></section>
    <section class="card" id="viewerCard" hidden><h2>Document viewer (Clearfolio)</h2>
      <p class="muted">Render live SOC evidence in the Clearfolio document viewer.</p>
      <div class="row">
        <button type="button" class="btn-secondary" data-doc="evidence-manifest">Open evidence manifest</button>
        <button type="button" class="btn-secondary" data-doc="soc-export">Open SOC export</button>
      </div>
      <div id="viewerStatus" class="muted" style="margin-top:8px"></div>
      <iframe id="viewerFrame" title="Clearfolio document viewer" hidden style="width:100%;height:70vh;border:1px solid var(--border);border-radius:var(--radius);margin-top:8px"></iframe>
    </section>
    <section class="card"><h2>DNSBL zone</h2><pre class="raw" id="zone">Loading…</pre></section>
  </div>
</main>
<div id="toast" aria-live="assertive"></div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cap=s=>{s=String(s||'');return s.charAt(0).toUpperCase()+s.slice(1);};
async function getJSON(u){const r=await fetch(u);if(!r.ok){let m=r.statusText;try{m=(await r.json()).error||m;}catch(e){}throw new Error(m);}return r.json();}
async function getText(u){const r=await fetch(u);return r.text();}
function badge(t,cls){return '<span class="badge '+cls+'">'+esc(t)+'</span>';}
function sevBadge(s){const m={low:'b-neutral',medium:'b-warn',high:'b-fail',critical:'b-fail'};return badge(cap(s),m[String(s).toLowerCase()]||'b-neutral');}
function modeBadge(m){return badge(cap(m),String(m).toLowerCase()==='block'?'b-fail':'b-brand');}
function stateBadge(v){return v?badge('Enabled','b-pass'):badge('Disabled','b-neutral');}
function statusBadge(s){const m={pass:'b-pass',fail:'b-fail',active:'b-pass',evaluation:'b-warn',unlicensed:'b-neutral',expired:'b-fail'};return badge(cap(s),m[String(s).toLowerCase()]||'b-neutral');}
function mono(t){return '<span class="badge mono b-neutral">'+esc(t)+'</span>';}
function table(capt,cols,rows){
  if(!rows.length)return '<p class="empty">No entries.</p>';
  return '<table><caption>'+esc(capt)+'</caption><thead><tr>'+cols.map(c=>'<th scope="col">'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+
    rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
}
function toast(msg,ok){const d=document.createElement('div');d.className='toast '+(ok?'ok':'bad');d.textContent=msg;$('toast').appendChild(d);setTimeout(()=>d.remove(),4500);}
async function guard(id,fn){try{await fn();}catch(e){$(id).innerHTML='<p class="err">Error: '+esc(e.message)+'</p>';}}
async function loadKpis(){const k=await getJSON('/api/kpis');
  const t=[['Routes',k.route_count],['Threat indicators',k.threat_indicator_count],['DNSBL entries',k.dnsbl_entry_count],['Blocked events',k.blocked_event_count],['Monitor events',k.monitor_event_count],['Gateway mode',cap(k.gateway_mode)]];
  $('kpis').innerHTML=t.map(([l,v])=>'<div class="tile"><div class="label">'+esc(l)+'</div><div class="metric">'+esc(v)+'</div></div>').join('');}
async function loadRoutes(){const d=await getJSON('/api/routes');
  $('routesBody').innerHTML=table('Configured routes',['Path prefix','Upstream','Mode','State'],d.map(r=>[esc(r.path_prefix),esc(r.upstream),modeBadge(r.mode),stateBadge(r.enabled)]));}
async function loadThreats(){const d=await getJSON('/api/threats');
  $('threatsBody').innerHTML=table('Threat indicators',['Value','Type','Severity','Source','TTL'],d.map(t=>[mono(t.value),esc(t.indicator_type),sevBadge(t.severity),esc(t.source),esc(t.ttl_seconds)+'s']));}
async function loadDnsbl(){const d=await getJSON('/api/dnsbl');
  $('dnsblBody').innerHTML=table('DNSBL entries',['Address','Code','Reason','Source','TTL'],d.map(x=>[esc(x.address),mono(x.code),esc(x.reason),esc(x.source),esc(x.ttl_seconds)+'s']));}
async function loadLicense(){const c=await getJSON('/api/commercial/license');
  $('licenseBody').innerHTML='<dl class="def">'+
    [['tenant_id',esc(c.tenant_id)],['deployment_id',esc(c.deployment_id)],['edition',badge(cap(c.edition),'b-brand')],['license_status',statusBadge(c.license_status)],['licensee',esc(c.licensee??'—')],['support_contact',esc(c.support_contact)],['ACV (KRW)',c.annual_contract_value_krw!=null?esc(c.annual_contract_value_krw):'—']]
    .map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+v+'</dd>').join('')+'</dl>';}
async function loadReadiness(){const r=await getJSON('/api/commercial/readiness');
  const head='<div class="row" style="margin-bottom:10px">'+badge(r.ready_for_enterprise_sale?'Ready':'Not ready',r.ready_for_enterprise_sale?'b-pass':'b-warn')+'<span class="muted">'+esc(r.readiness_level)+'</span></div>';
  const checks=(r.checks||[]).map(c=>'<div class="row" style="margin:6px 0">'+statusBadge(c.status)+'<span class="muted">'+esc(c.id)+' — '+esc(c.evidence)+'</span></div>').join('');
  $('readinessBody').innerHTML=head+checks;}
async function loadFeeds(){const f=await getJSON('/api/threat-feeds/freshness');
  $('feedsBody').innerHTML=table('Threat feeds',['Feed','Source','Threats','DNSBL','Freshness'],f.map(x=>[esc(x.feed_id),esc(x.source),esc(x.threat_count),esc(x.dnsbl_count),x.stale?badge('Stale','b-fail'):badge('Fresh','b-pass')]));}
async function loadEvents(){const e=await getJSON('/api/events');
  $('eventsBody').innerHTML=table('Recent events',['ID','Client IP','Action','Score','Path'],e.slice(0,25).map(x=>[esc(x.id),esc(x.client_ip??'—'),esc(x.action),esc(x.score),esc(x.path)]));}
async function loadAudit(){const a=await getJSON('/api/audit-logs');
  $('auditBody').innerHTML=table('Audit log',['Actor','Action','Resource','Resource ID','Outcome'],a.slice(0,25).map(x=>[esc(x.actor),esc(x.action),esc(x.resource),esc(x.resource_id),esc(x.outcome)]));}
async function loadRaw(id,url,json){try{const t=json?JSON.stringify(await getJSON(url),null,2):await getText(url);$(id).textContent=t&&t.trim()?t:'(empty)';}catch(e){$(id).textContent='Error: '+e.message;}}
async function refresh(){await Promise.allSettled([
  guard('kpis',loadKpis),guard('routesBody',loadRoutes),guard('threatsBody',loadThreats),guard('dnsblBody',loadDnsbl),
  guard('licenseBody',loadLicense),guard('readinessBody',loadReadiness),guard('feedsBody',loadFeeds),
  guard('eventsBody',loadEvents),guard('auditBody',loadAudit),
  loadRaw('manifest','/api/commercial/evidence-manifest',true),loadRaw('export','/api/events.ndjson',false),loadRaw('zone','/dnsbl/zone',false)]);}
function wireCreate(formId,buildBody,onOk){const f=$(formId);if(!f)return;
  f.addEventListener('submit',async ev=>{ev.preventDefault();let body;try{body=buildBody(new FormData(f));}catch(e){toast(e.message,false);return;}
    const token=($('adminToken').value||'').trim();const h={'content-type':'application/json'};if(token)h['x-admin-token']=token;
    try{const r=await fetch(f.dataset.url,{method:'POST',headers:h,body:JSON.stringify(body)});
      if(!r.ok){let m=r.statusText;try{m=(await r.json()).error||m;}catch(e){}throw new Error(m);}
      toast(f.dataset.ok+' saved',true);f.reset();onOk();
    }catch(e){toast('Save failed: '+e.message,false);}});}
const num=v=>{const n=parseInt(v,10);return Number.isFinite(n)?n:0;};
wireCreate('routeForm',fd=>{const pp=(fd.get('path_prefix')||'').trim();return {id:pp.replace(/^\//,'').replace(/[^a-zA-Z0-9_-]/g,'-')||'route',path_prefix:pp,upstream:(fd.get('upstream')||'').trim(),mode:fd.get('mode'),enabled:fd.get('enabled')==='on'};},()=>{guard('routesBody',loadRoutes);guard('kpis',loadKpis);});
wireCreate('threatForm',fd=>({value:(fd.get('value')||'').trim(),indicator_type:(fd.get('indicator_type')||'').trim(),severity:fd.get('severity'),source:(fd.get('source')||'').trim(),ttl_seconds:num(fd.get('ttl_seconds'))}),()=>{guard('threatsBody',loadThreats);guard('kpis',loadKpis);});
wireCreate('dnsblForm',fd=>({address:(fd.get('address')||'').trim(),code:(fd.get('code')||'').trim(),reason:(fd.get('reason')||'').trim(),source:(fd.get('source')||'').trim(),ttl_seconds:num(fd.get('ttl_seconds'))}),()=>{guard('dnsblBody',loadDnsbl);guard('kpis',loadKpis);loadRaw('zone','/dnsbl/zone',false);});
wireCreate('licenseForm',fd=>{const feats=(fd.get('features')||'').split(',').map(s=>s.trim()).filter(Boolean);const b={tenant_id:(fd.get('tenant_id')||'').trim(),deployment_id:(fd.get('deployment_id')||'').trim(),edition:fd.get('edition'),license_status:fd.get('license_status'),support_contact:(fd.get('support_contact')||'').trim(),features:feats};const lic=(fd.get('licensee')||'').trim();if(lic)b.licensee=lic;const lid=(fd.get('license_id')||'').trim();if(lid)b.license_id=lid;return b;},()=>{guard('licenseBody',loadLicense);guard('readinessBody',loadReadiness);});
const root=document.documentElement;
if(localStorage.getItem('waf-theme')==='hc')root.dataset.theme='hc';
function syncHc(){$('hcToggle').setAttribute('aria-pressed',root.dataset.theme==='hc'?'true':'false');}
syncHc();
$('hcToggle').addEventListener('click',()=>{const on=root.dataset.theme==='hc';if(on){delete root.dataset.theme;}else{root.dataset.theme='hc';}localStorage.setItem('waf-theme',on?'':'hc');syncHc();});
$('refreshBtn').addEventListener('click',refresh);
function cfHeaders(){const t=($('adminToken').value||'').trim();return t?{'x-admin-token':t}:{};}
async function pollClearfolio(id){
  for(let i=0;i<40;i++){
    const r=await fetch('/api/clearfolio/jobs/'+encodeURIComponent(id),{headers:cfHeaders()});
    if(r.ok){const j=await r.json();const s=String(j.status||'').toUpperCase();const doc=j.docId||j.doc_id;
      if(s==='SUCCEEDED'||doc)return doc||id;
      if(s==='FAILED'||j.deadLettered)throw new Error('conversion failed');}
    await new Promise(res=>setTimeout(res,1500));}
  throw new Error('conversion timed out');}
async function openClearfolioDoc(kind,base){
  const st=$('viewerStatus'),frame=$('viewerFrame');frame.hidden=true;st.textContent='Submitting conversion…';
  try{
    const sr=await fetch('/api/clearfolio/documents/'+encodeURIComponent(kind),{method:'POST',headers:cfHeaders()});
    if(!sr.ok)throw new Error((await sr.json().catch(()=>({}))).error||sr.statusText);
    const job=await sr.json();const id=job.jobId||job.job_id;if(!id)throw new Error('no job id returned');
    st.textContent='Converting… (job '+id+')';
    const doc=await pollClearfolio(id);
    frame.src=base.replace(/\/+$/,'')+'/viewer/'+encodeURIComponent(doc);frame.hidden=false;st.textContent='Document ready.';
  }catch(e){st.innerHTML='<span class="err">Viewer error: '+esc(e.message)+'</span>';}}
async function initClearfolio(){
  let cfg;try{cfg=await getJSON('/api/clearfolio/config');}catch(e){return;}
  if(!cfg||!cfg.enabled||!cfg.base_url)return;
  const card=$('viewerCard');if(!card)return;card.hidden=false;
  card.querySelectorAll('button[data-doc]').forEach(b=>b.addEventListener('click',()=>openClearfolioDoc(b.dataset.doc,cfg.base_url)));}
async function analyzeSocEvent(){
  const out=$('socAnalysis');const id=parseInt(($('socEventId').value||'').trim(),10);
  if(!Number.isFinite(id)||id<1){out.innerHTML='<span class="err">Enter a valid event id.</span>';return;}
  out.textContent='Analyzing…';
  try{
    const r=await fetch('/api/soc/analyze',{method:'POST',headers:{'content-type':'application/json',...cfHeaders()},body:JSON.stringify({event_id:id})});
    if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||r.statusText);
    const j=await r.json();out.textContent=j.analysis||'(no analysis)';
  }catch(e){out.innerHTML='<span class="err">Analysis error: '+esc(e.message)+'</span>';}}
async function initSocLlm(){
  let cfg;try{cfg=await getJSON('/api/soc/llm-config');}catch(e){return;}
  if(!cfg||!cfg.enabled)return;
  const card=$('socLlmCard');if(!card)return;card.hidden=false;
  $('socAnalyzeBtn').addEventListener('click',analyzeSocEvent);}
refresh();
initClearfolio();
initSocLlm();
</script>
</body>
</html>"##;

/// Parse the `EVENT_LIMIT` value (already read from the environment as an
/// optional string). Absent falls back to [`AppConfig::DEFAULT_EVENT_LIMIT`]; a
/// non-integer or zero value is a hard configuration error. Kept in the library
/// (rather than the binary) so it is exercised by unit tests.
pub fn parse_event_limit(raw: Option<&str>) -> Result<usize, Box<dyn std::error::Error>> {
    let value = match raw {
        Some(raw) => raw.parse::<usize>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("EVENT_LIMIT must be a positive integer, got {raw:?}: {error}"),
            )
        })?,
        None => AppConfig::DEFAULT_EVENT_LIMIT,
    };
    if value == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "EVENT_LIMIT must be greater than 0",
        )
        .into());
    }
    Ok(value)
}

/// Parse a `u32` environment value (already read as an optional string),
/// returning `default` when absent and a configuration error when malformed.
pub fn parse_u32_env(
    name: &str,
    raw: Option<&str>,
    default: u32,
) -> Result<u32, Box<dyn std::error::Error>> {
    match raw {
        Some(raw) => Ok(raw.parse::<u32>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} must be a non-negative integer, got {raw:?}: {error}"),
            )
        })?),
        None => Ok(default),
    }
}

/// Parse a `u64` environment value (already read as an optional string),
/// returning `default` when absent and a configuration error when malformed.
pub fn parse_u64_env(
    name: &str,
    raw: Option<&str>,
    default: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    match raw {
        Some(raw) => Ok(raw.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} must be a positive integer, got {raw:?}: {error}"),
            )
        })?),
        None => Ok(default),
    }
}

/// Read gateway configuration from the process environment, bind the listener,
/// and serve until `shutdown` resolves. The binary entrypoint is a thin shim
/// over this function so every branch is reachable from tests (the parse/error
/// paths in-process, the bind/serve path via an ephemeral listener and an
/// immediate shutdown).
pub async fn run_from_env(
    shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let config = AppConfig {
        admin_token: std::env::var("ADMIN_TOKEN").ok(),
        state_path: std::env::var("WAF_IDS_STATE_PATH").ok().map(PathBuf::from),
        dnsbl_origin: std::env::var("DNSBL_ORIGIN")
            .unwrap_or_else(|_| AppConfig::DEFAULT_DNSBL_ORIGIN.to_string()),
        event_limit: parse_event_limit(std::env::var("EVENT_LIMIT").ok().as_deref())?,
    };
    let rate_limit = parse_u32_env("RATE_LIMIT", std::env::var("RATE_LIMIT").ok().as_deref(), 0)?;
    let rate_limit_window = parse_u64_env(
        "RATE_LIMIT_WINDOW",
        std::env::var("RATE_LIMIT_WINDOW").ok().as_deref(),
        60,
    )?;
    let admin_tokens = parse_admin_tokens(&std::env::var("ADMIN_TOKENS").unwrap_or_default());
    let max_body_bytes = parse_u64_env(
        "MAX_BODY_BYTES",
        std::env::var("MAX_BODY_BYTES").ok().as_deref(),
        1_048_576,
    )? as usize;
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let local_addr = listener.local_addr()?;
    println!("waf-ids-ai-soc listening on http://{local_addr}");
    // Flush so a supervising parent process (the e2e test) sees the readiness
    // line immediately even though stdout is block-buffered when piped.
    std::io::Write::flush(&mut std::io::stdout())?;
    let state = AppState::load(config)
        .await
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidData, message))?
        .with_rate_limit(rate_limit, rate_limit_window)
        .with_admin_tokens(admin_tokens)
        .with_max_body_size(max_body_bytes);
    let served = axum::serve(listener, build_app(state))
        .with_graceful_shutdown(shutdown)
        .await;
    served?;
    Ok(())
}

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

    // Serializes the environment-driven `run_from_env` tests, which mutate
    // process-global environment variables.
    // An async mutex so it can be held across the `run_from_env` await points
    // while serializing the tests that mutate process-global environment vars.
    static ENV_GUARD: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    fn clear_run_env() {
        for name in [
            "BIND_ADDR",
            "ADMIN_TOKEN",
            "ADMIN_TOKENS",
            "WAF_IDS_STATE_PATH",
            "DNSBL_ORIGIN",
            "EVENT_LIMIT",
            "RATE_LIMIT",
            "RATE_LIMIT_WINDOW",
            "MAX_BODY_BYTES",
        ] {
            unsafe { std::env::remove_var(name) };
        }
    }

    #[test]
    fn parse_event_limit_reads_optional_env() {
        assert_eq!(
            parse_event_limit(None).unwrap(),
            AppConfig::DEFAULT_EVENT_LIMIT
        );
        assert_eq!(parse_event_limit(Some("25")).unwrap(), 25);
        assert!(parse_event_limit(Some("0")).is_err());
        assert!(parse_event_limit(Some("not-a-number")).is_err());
    }

    #[test]
    fn parse_u32_env_reads_optional_env() {
        assert_eq!(parse_u32_env("RATE_LIMIT", None, 7).unwrap(), 7);
        assert_eq!(parse_u32_env("RATE_LIMIT", Some("120"), 0).unwrap(), 120);
        assert!(parse_u32_env("RATE_LIMIT", Some("-1"), 0).is_err());
    }

    #[test]
    fn parse_u64_env_reads_optional_env() {
        assert_eq!(parse_u64_env("RATE_LIMIT_WINDOW", None, 60).unwrap(), 60);
        assert_eq!(
            parse_u64_env("RATE_LIMIT_WINDOW", Some("30"), 60).unwrap(),
            30
        );
        assert!(parse_u64_env("RATE_LIMIT_WINDOW", Some("abc"), 60).is_err());
    }

    #[test]
    fn parses_and_limits_phishing_database_feeds() {
        let domains = parse_phishing_domains(
            "https://Phish.EXAMPLE/login\n#comment\n\nbad value\na..b.example\n203.0.113.7\nphish.example\nphish.example\n",
            2,
        );
        assert_eq!(domains, vec!["phish.example".to_string()]);

        let ips = parse_phishing_ips("198.51.100.8\n#skip\nbad-ip\n198.51.100.8\n203.0.113.5", 2);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "198.51.100.8".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn run_from_env_binds_and_serves_until_shutdown() {
        let _guard = ENV_GUARD.lock().await;
        clear_run_env();
        unsafe {
            std::env::set_var("BIND_ADDR", "127.0.0.1:0");
            std::env::set_var("RATE_LIMIT", "5");
            std::env::set_var("RATE_LIMIT_WINDOW", "30");
            std::env::set_var("ADMIN_TOKENS", "tok:operator");
        }
        // An already-ready shutdown makes the server bind, then return at once.
        run_from_env(Box::pin(std::future::ready(())))
            .await
            .unwrap();
        clear_run_env();
    }

    #[tokio::test]
    async fn run_from_env_defaults_bind_addr_when_unset() {
        let _guard = ENV_GUARD.lock().await;
        clear_run_env();
        // With BIND_ADDR unset the default listen address is used (exercising the
        // fallback). The result is ignored because the default port may be busy
        // in CI; the immediate shutdown keeps any successful bind momentary.
        let _ = run_from_env(Box::pin(std::future::ready(()))).await;
        clear_run_env();
    }

    #[tokio::test]
    async fn run_from_env_rejects_malformed_rate_limit_window() {
        let _guard = ENV_GUARD.lock().await;
        clear_run_env();
        unsafe {
            std::env::set_var("BIND_ADDR", "127.0.0.1:0");
            std::env::set_var("RATE_LIMIT_WINDOW", "not-a-number");
        }
        // A malformed window is a hard configuration error, surfaced before bind.
        assert!(
            run_from_env(Box::pin(std::future::ready(())))
                .await
                .is_err()
        );
        clear_run_env();
    }

    #[tokio::test]
    async fn run_from_env_rejects_malformed_max_body_bytes() {
        let _guard = ENV_GUARD.lock().await;
        clear_run_env();
        unsafe {
            std::env::set_var("BIND_ADDR", "127.0.0.1:0");
            std::env::set_var("MAX_BODY_BYTES", "not-a-number");
        }
        assert!(
            run_from_env(Box::pin(std::future::ready(())))
                .await
                .is_err()
        );
        clear_run_env();
    }

    #[tokio::test]
    async fn run_from_env_surfaces_state_load_failure() {
        let _guard = ENV_GUARD.lock().await;
        clear_run_env();
        let path = std::env::temp_dir().join(format!(
            "waf_ids_bad_state_{}_{}.json",
            std::process::id(),
            now_unix()
        ));
        std::fs::write(&path, b"{ not valid json").unwrap();
        unsafe {
            std::env::set_var("BIND_ADDR", "127.0.0.1:0");
            std::env::set_var("WAF_IDS_STATE_PATH", path.to_str().unwrap());
        }
        // Bind succeeds, but loading corrupt persisted state maps to an error.
        assert!(
            run_from_env(Box::pin(std::future::ready(())))
                .await
                .is_err()
        );
        clear_run_env();
        std::fs::remove_file(&path).ok();
    }

    fn route() -> RouteConfig {
        RouteConfig {
            id: "api".to_string(),
            path_prefix: "/api".to_string(),
            upstream: "https://origin.example".to_string(),
            mode: EnforcementMode::Block,
            enabled: true,
            block_threshold: None,
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
                prefix_len: None,
            }],
        }
    }

    fn phishing_database_import_request(base_url: &str) -> PhishingDatabaseImportRequest {
        PhishingDatabaseImportRequest {
            feed_id: "phishing-db-seoul".to_string(),
            source: "https://github.com/Phishing-Database/Phishing.Database".to_string(),
            domain_url: format!("{base_url}/domains"),
            ip_url: format!("{base_url}/ips"),
            ttl_seconds: 900,
            domain_limit: 10,
            ip_limit: 10,
            severity: Severity::Critical,
            import_domains: true,
            import_ips: true,
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

    #[test]
    fn prometheus_exposition_emits_typed_gauges() {
        let text = prometheus_exposition(&kpi_snapshot_at(&AppData::seeded(), 0));
        // HELP/TYPE metadata plus a value line for a representative metric.
        assert!(text.contains("# TYPE waf_ids_routes gauge"));
        assert!(text.contains("waf_ids_routes 1")); // seed has one route
        assert!(text.contains("waf_ids_dnsbl_entries 1")); // seed has one DNSBL entry
        assert!(text.contains("waf_ids_security_events 0"));
        assert!(text.contains("waf_ids_security_events_blocked 0"));
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let app = build_app(AppState::seeded(None));
        let response = app_request(&app, empty_request(Method::GET, "/metrics")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.starts_with("text/plain"),
            "unexpected content-type: {content_type}"
        );
        let body = body_text(response).await;
        assert!(body.contains("waf_ids_security_events_blocked"));
    }

    #[tokio::test]
    async fn signatures_endpoint_lists_redacted_catalog() {
        let app = build_app(AppState::seeded(None));
        let response = app_request(&app, empty_request(Method::GET, "/api/signatures")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        // Exposes rule id, class, and severity for buyer/operator review.
        assert!(body.contains("sqli-union-select"));
        assert!(body.contains("\"class\":\"sqli\""));
        assert!(body.contains("\"severity\":\"critical\"")); // the JNDI/Log4Shell rule
        // But never the raw match patterns (which would aid evasion).
        assert!(!body.contains("union select"));
        assert!(!body.contains("${jndi:"));
    }

    #[test]
    fn parse_admin_tokens_maps_tokens_to_actors() {
        let map = parse_admin_tokens("tokA:alice, tokB:bob ,tokC, ,:noname, tokD:");
        assert_eq!(map.get("tokA").map(String::as_str), Some("alice"));
        assert_eq!(map.get("tokB").map(String::as_str), Some("bob"));
        // No explicit actor, or an empty actor, is labelled "admin".
        assert_eq!(map.get("tokC").map(String::as_str), Some("admin"));
        assert_eq!(map.get("tokD").map(String::as_str), Some("admin"));
        // Blank items and blank tokens (":noname") are ignored.
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn rbac_tokens_authorize_and_name_the_actor() {
        let mut tokens = HashMap::new();
        tokens.insert("tokA".to_string(), "alice".to_string());
        let state = AppState::seeded(None).with_admin_tokens(tokens);

        let mut valid = HeaderMap::new();
        valid.insert("x-admin-token", "tokA".parse().unwrap());
        assert!(admin_authorized(&state, &valid));
        assert_eq!(audit_actor(&state, &valid), "alice");

        // A token not in the RBAC set is rejected, and never used as the actor.
        let mut wrong = HeaderMap::new();
        wrong.insert("x-admin-token", "nope".parse().unwrap());
        assert!(!admin_authorized(&state, &wrong));
        assert_eq!(audit_actor(&state, &wrong), "admin-token");

        // Missing token header is unauthorized under RBAC.
        assert!(!admin_authorized(&state, &HeaderMap::new()));

        // Without a matching RBAC token, audit_actor honours X-Admin-Actor.
        let mut named = HeaderMap::new();
        named.insert("x-admin-actor", "carol".parse().unwrap());
        assert_eq!(audit_actor(&state, &named), "carol");
    }

    #[test]
    fn security_event_log_line_is_single_line_json() {
        let event = SecurityEvent {
            id: 7,
            timestamp_unix: 1_700_000_000,
            client_ip: Some("203.0.113.5".parse().unwrap()),
            route_id: Some("app".to_string()),
            action: "blocked".to_string(),
            reason: "builtin sqli rule sqli-union-select".to_string(),
            score: 100,
            path: "/app".to_string(),
        };
        let line = security_event_log_line(&event);
        assert!(!line.contains('\n'), "log line must be single-line");
        // Round-trips as JSON with the expected fields.
        let parsed: SecurityEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, event);
        assert!(line.contains("\"action\":\"blocked\""));
        assert!(line.contains("\"score\":100"));
    }

    async fn json_body<T: DeserializeOwned>(response: Response) -> T {
        serde_json::from_str(&body_text(response).await).unwrap()
    }

    #[tokio::test]
    async fn evaluate_endpoint_scores_payloads_offline() {
        let app = build_app(AppState::seeded(None));
        let sqli = json_request(
            Method::POST,
            "/api/evaluate",
            None,
            &serde_json::json!({"path": "/products", "query": "id=1 UNION SELECT password"}),
        );
        let response = app_request(&app, sqli).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = json_body(response).await;
        assert!(body["score"].as_u64().unwrap() >= u64::from(BLOCK_SCORE));
        assert_eq!(body["would_block"], true);
        assert!(body["reason"].as_str().unwrap().contains("sqli"));
        let body_req = json_request(
            Method::POST,
            "/api/evaluate",
            None,
            &serde_json::json!({"path": "/upload", "body": "x=1 union select 1"}),
        );
        let body: serde_json::Value = json_body(app_request(&app, body_req).await).await;
        assert_eq!(body["would_block"], true);
        let benign = json_request(
            Method::POST,
            "/api/evaluate",
            None,
            &serde_json::json!({"path": "/account", "query": "tab=settings"}),
        );
        let body: serde_json::Value = json_body(app_request(&app, benign).await).await;
        assert_eq!(body["score"], 0);
        assert_eq!(body["would_block"], false);
    }

    #[tokio::test]
    async fn version_and_readiness_endpoints() {
        let app = build_app(AppState::seeded(None));
        let response = app_request(&app, empty_request(Method::GET, "/api/version")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = json_body(response).await;
        assert_eq!(body["name"], env!("CARGO_PKG_NAME"));
        assert!(!body["version"].as_str().unwrap().is_empty());
        let response = app_request(&app, empty_request(Method::GET, "/readyz")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = json_body(response).await;
        assert_eq!(body["ready"], true);
        let disable = json_request(
            Method::POST,
            "/api/routes",
            None,
            &serde_json::json!({"id": "demo", "path_prefix": "/demo", "upstream": "mock://x", "mode": "monitor", "enabled": false}),
        );
        assert!(app_request(&app, disable).await.status().is_success());
        let response = app_request(&app, empty_request(Method::GET, "/readyz")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = json_body(response).await;
        assert_eq!(body["ready"], false);
    }

    #[tokio::test]
    async fn events_endpoint_filters_by_action_and_limit() {
        let app = build_app(AppState::seeded(None));
        let route = json_request(
            Method::POST,
            "/api/routes",
            None,
            &serde_json::json!({"id": "app", "path_prefix": "/app", "upstream": "mock://x", "mode": "block", "enabled": true}),
        );
        assert!(app_request(&app, route).await.status().is_success());
        app_request(
            &app,
            gateway_get_from_ip("/gateway/app?q=1%20UNION%20SELECT%201", "203.0.113.9"),
        )
        .await;
        app_request(
            &app,
            gateway_get_from_ip("/gateway/demo?q=hi", "203.0.113.9"),
        )
        .await;
        let all: Vec<serde_json::Value> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/events")).await).await;
        assert_eq!(all.len(), 2);
        let blocked: Vec<serde_json::Value> = json_body(
            app_request(
                &app,
                empty_request(Method::GET, "/api/events?action=blocked"),
            )
            .await,
        )
        .await;
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0]["action"], "blocked");
        let recent: Vec<serde_json::Value> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/events?limit=1")).await)
                .await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0]["action"], "monitored");
    }

    #[tokio::test]
    async fn per_route_block_threshold_overrides_global() {
        let app = build_app(AppState::seeded(None));
        let indicator = json_request(
            Method::POST,
            "/api/threats",
            None,
            &serde_json::json!({"value": "probe-xyz", "indicator_type": "test", "severity": "low", "source": "t", "ttl_seconds": 60}),
        );
        assert!(app_request(&app, indicator).await.status().is_success());
        let low = json_request(
            Method::POST,
            "/api/routes",
            None,
            &serde_json::json!({"id": "low", "path_prefix": "/low", "upstream": "mock://x", "mode": "block", "enabled": true, "block_threshold": 5}),
        );
        assert!(app_request(&app, low).await.status().is_success());
        let hi = json_request(
            Method::POST,
            "/api/routes",
            None,
            &serde_json::json!({"id": "hi", "path_prefix": "/hi", "upstream": "mock://x", "mode": "block", "enabled": true}),
        );
        assert!(app_request(&app, hi).await.status().is_success());
        let blocked =
            app_request(&app, empty_request(Method::GET, "/gateway/low?q=probe-xyz")).await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let allowed =
            app_request(&app, empty_request(Method::GET, "/gateway/hi?q=probe-xyz")).await;
        assert_ne!(allowed.status(), StatusCode::FORBIDDEN);
        let bad = json_request(
            Method::POST,
            "/api/routes",
            None,
            &serde_json::json!({"id": "z", "path_prefix": "/z", "upstream": "mock://x", "mode": "block", "enabled": true, "block_threshold": 0}),
        );
        assert_eq!(
            app_request(&app, bad).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn oversized_request_body_is_rejected() {
        let app = build_app(AppState::seeded(None).with_max_body_size(16));
        let big = Request::builder()
            .method(Method::POST)
            .uri("/gateway/demo")
            .body(Body::from("x".repeat(64)))
            .unwrap();
        assert_eq!(
            app_request(&app, big).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let small = Request::builder()
            .method(Method::POST)
            .uri("/gateway/demo")
            .body(Body::from("x"))
            .unwrap();
        assert_ne!(
            app_request(&app, small).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn admin_console_serves_designed_ui() {
        let app = build_app(AppState::seeded(None));
        let html = body_text(app_request(&app, empty_request(Method::GET, "/")).await).await;

        // Foundation design tokens are source-true (must match Figma variables).
        assert!(html.contains("--brand:#14213d"), "brand token missing");
        assert!(html.contains("--canvas:#f7f8fa"), "canvas token missing");
        // Designed components render, not the old raw-JSON <pre> dumps.
        assert!(
            html.contains("id=\"routesBody\""),
            "routes table container missing"
        );
        assert!(
            html.contains("id=\"threatsBody\""),
            "threats table container missing"
        );
        // Create forms are wired to the real API endpoints.
        assert!(
            html.contains("data-url=\"/api/routes\""),
            "add-route form missing"
        );
        assert!(
            html.contains("data-url=\"/api/threats\""),
            "add-threat form missing"
        );
        // Accessibility affordances present.
        assert!(
            html.contains("id=\"hcToggle\""),
            "high-contrast toggle missing"
        );
        assert!(html.contains("Skip to content"), "skip link missing");
        assert!(
            html.contains(":focus-visible"),
            "focus-visible styling missing"
        );
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
                    prefix_len: None,
                },
                DnsblEntry {
                    address: "2001:db8::10".parse().unwrap(),
                    code: "127.0.0.2".to_string(),
                    reason: "ipv6 skip".to_string(),
                    source: "unit".to_string(),
                    ttl_seconds: 300,
                    prefix_len: None,
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
        // Uses a site-specific IoC that does NOT overlap a built-in signature,
        // so this isolates the operator-configured indicator path.
        let score = score_request(
            "/callback",
            Some("id=EVILCORP-C2-BEACON"),
            "",
            None,
            &[ThreatIndicator {
                value: "evilcorp-c2-beacon".to_string(),
                indicator_type: "c2".to_string(),
                severity: Severity::High,
                source: "unit".to_string(),
                ttl_seconds: 60,
            }],
            &[],
        );

        assert_eq!(score.score, 50);
        assert!(score.reason.contains("c2 indicator"));
    }

    #[test]
    fn builtin_waf_detects_common_attack_classes_without_configuration() {
        // No operator-configured indicators and no DNSBL: every detection below
        // must come from the built-in OWASP-shape signature layer alone.
        let cases = [
            ("/products", "id=1 UNION SELECT password FROM users", "sqli"),
            (
                "/search",
                "q=<script>alert(document.cookie)</script>",
                "xss",
            ),
            ("/download", "file=../../../../etc/passwd", "path-traversal"),
            (
                "/ping",
                "host=127.0.0.1; cat /etc/passwd",
                "command-injection",
            ),
            (
                "/fetch",
                "url=http://169.254.169.254/latest/meta-data",
                "ssrf",
            ),
            ("/lookup", "x=${jndi:ldap://evil/a}", "deserialization"),
        ];
        for (path, query, class) in cases {
            let scored = score_request(path, Some(query), "", None, &[], &[]);
            assert!(
                scored.score >= BLOCK_SCORE,
                "{class} payload should reach block score, got {} ({})",
                scored.score,
                scored.reason
            );
            assert!(
                scored.reason.contains(class),
                "reason should name the {class} class, got: {}",
                scored.reason
            );
        }

        // A benign request must not be flagged by the built-in layer.
        let benign = score_request("/account/profile", Some("tab=settings"), "", None, &[], &[]);
        assert_eq!(benign.score, 0, "benign request scored: {}", benign.reason);
        assert_eq!(benign.reason, "no matching indicator");
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
                prefix_len: None,
            }],
        );

        assert_eq!(score.score, 100);
        assert!(score.reason.contains("DNSBL match"));
    }

    #[test]
    fn ip_in_network_masks_by_prefix() {
        let net: IpAddr = "203.0.113.0".parse().unwrap();
        assert!(ip_in_network(net, 24, "203.0.113.200".parse().unwrap()));
        assert!(ip_in_network(net, 24, "203.0.113.0".parse().unwrap()));
        assert!(!ip_in_network(net, 24, "203.0.114.1".parse().unwrap()));
        // /0 matches everything; a full /32 is an exact match.
        assert!(ip_in_network(net, 0, "8.8.8.8".parse().unwrap()));
        assert!(!ip_in_network(net, 32, "203.0.113.1".parse().unwrap()));
        // Mixed address families never match.
        assert!(!ip_in_network(net, 24, "2001:db8::1".parse().unwrap()));
        // IPv6 prefix masking.
        let net6: IpAddr = "2001:db8::".parse().unwrap();
        assert!(ip_in_network(
            net6,
            32,
            "2001:db8:dead:beef::1".parse().unwrap()
        ));
        assert!(!ip_in_network(net6, 32, "2001:db9::1".parse().unwrap()));
        // IPv6 /0 matches everything.
        assert!(ip_in_network(net6, 0, "fe80::1".parse().unwrap()));
    }

    #[test]
    fn scores_dnsbl_cidr_subnet_matches() {
        // A /24 DNSBL entry blocks any client IP inside the subnet.
        let entry = DnsblEntry {
            address: "198.51.100.0".parse().unwrap(),
            code: "127.0.0.2".to_string(),
            reason: "botnet subnet".to_string(),
            source: "unit".to_string(),
            ttl_seconds: 300,
            prefix_len: Some(24),
        };
        let inside = score_request(
            "/",
            None,
            "",
            Some("198.51.100.77".parse().unwrap()),
            &[],
            std::slice::from_ref(&entry),
        );
        assert_eq!(inside.score, 100);
        assert!(inside.reason.contains("DNSBL match"));

        let outside = score_request(
            "/",
            None,
            "",
            Some("198.51.101.77".parse().unwrap()),
            &[],
            std::slice::from_ref(&entry),
        );
        assert_eq!(outside.score, 0);
    }

    #[test]
    fn validate_dnsbl_checks_prefix_len() {
        let base = DnsblEntry {
            address: "10.0.0.0".parse().unwrap(),
            code: "127.0.0.2".to_string(),
            reason: "range".to_string(),
            source: "unit".to_string(),
            ttl_seconds: 60,
            prefix_len: Some(24),
        };
        assert!(validate_dnsbl(&base).is_ok());
        let too_wide = DnsblEntry {
            prefix_len: Some(40),
            ..base.clone()
        };
        assert_eq!(
            validate_dnsbl(&too_wide),
            Err("DNSBL prefix_len exceeds the address family width")
        );
        // IPv6 permits prefixes up to /128.
        let v6 = DnsblEntry {
            address: "2001:db8::".parse().unwrap(),
            prefix_len: Some(64),
            ..base.clone()
        };
        assert!(validate_dnsbl(&v6).is_ok());
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
                block_threshold: None,
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
            block_threshold: None,
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
            prefix_len: None,
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
            block_threshold: None,
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
    async fn phishing_database_import_endpoint_supports_blocking_flow() {
        let feed_mock = Router::new()
            .route(
                "/domains",
                get(|| async {
                    (
                        StatusCode::OK,
                        "evil.example\nhttps://evil.example/path\nlogin.bad.example\n",
                    )
                }),
            )
            .route(
                "/ips",
                get(|| async { (StatusCode::OK, "198.51.100.200\n203.0.113.77\nbad-ip\n") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, feed_mock).into_future());

        let app = build_app(AppState::seeded(Some("secret".to_string())));
        let payload = phishing_database_import_request(&format!("http://{addr}"));

        let unauthorized = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/threat-feeds/import/phishing-database",
                None,
                &payload,
            ),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let invalid_request = PhishingDatabaseImportRequest {
            ttl_seconds: 0,
            domain_url: "file:///tmp/not-allowed".to_string(),
            ..payload.clone()
        };
        let invalid = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/threat-feeds/import/phishing-database",
                Some("secret"),
                &invalid_request,
            ),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let import_result: ThreatFeedImportResult = json_body(
            app_request(
                &app,
                json_request(
                    Method::POST,
                    "/api/threat-feeds/import/phishing-database",
                    Some("secret"),
                    &payload,
                ),
            )
            .await,
        )
        .await;
        assert_eq!(import_result.feed_id, "phishing-db-seoul");
        assert_eq!(import_result.upserted_threats, 2);
        assert_eq!(import_result.upserted_dnsbl, 2);
        let audit_logs: Vec<AuditLogEntry> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/audit-logs")).await).await;
        assert!(
            audit_logs
                .iter()
                .any(|item| item.action == "import_phishing_database_feed")
        );

        let threat_entries: Vec<ThreatIndicator> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/threats")).await).await;
        assert!(threat_entries.iter().any(
            |entry| entry.value == "evil.example" && entry.indicator_type == "phishing_domain"
        ));
        assert!(
            threat_entries
                .iter()
                .any(|entry| entry.value == "login.bad.example"
                    && entry.source == "phishing-db-seoul")
        );

        let dnsbl_entries: Vec<DnsblEntry> =
            json_body(app_request(&app, empty_request(Method::GET, "/api/dnsbl")).await).await;
        assert!(
            dnsbl_entries
                .iter()
                .any(|entry| entry.address == "198.51.100.200".parse::<IpAddr>().unwrap())
        );
        assert!(
            dnsbl_entries
                .iter()
                .any(|entry| entry.address == "203.0.113.77".parse::<IpAddr>().unwrap())
        );

        let block_route = RouteConfig {
            id: "phish".to_string(),
            path_prefix: "/phish".to_string(),
            upstream: "mock://phish".to_string(),
            mode: EnforcementMode::Block,
            enabled: true,
            block_threshold: Some(50),
        };
        let route_response = app_request(
            &app,
            json_request(Method::POST, "/api/routes", Some("secret"), &block_route),
        )
        .await;
        assert_eq!(route_response.status(), StatusCode::CREATED);

        let blocked = app_request(
            &app,
            empty_request(
                Method::GET,
                "/gateway/phish?q=https%3A%2F%2Fevil.example%2Flogin",
            ),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
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
                        block_threshold: None,
                    },
                    RouteConfig {
                        id: "proxy".to_string(),
                        path_prefix: "/proxy".to_string(),
                        upstream: format!("http://{upstream_addr}"),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                        block_threshold: None,
                    },
                    RouteConfig {
                        id: "down".to_string(),
                        path_prefix: "/down".to_string(),
                        upstream: format!("http://{unused_addr}"),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                        block_threshold: None,
                    },
                    RouteConfig {
                        id: "truncated".to_string(),
                        path_prefix: "/truncated".to_string(),
                        upstream: format!("http://{raw_addr}"),
                        mode: EnforcementMode::Monitor,
                        enabled: true,
                        block_threshold: None,
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
                block_threshold: None,
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
                        block_threshold: None,
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
            prefix_len: None,
        }];

        upsert_dnsbl(
            &mut dnsbl,
            DnsblEntry {
                address: "203.0.113.10".parse().unwrap(),
                code: "127.0.0.3".to_string(),
                reason: "botnet".to_string(),
                source: "feed".to_string(),
                ttl_seconds: 600,
                prefix_len: None,
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
                block_threshold: None,
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
                block_threshold: None,
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
                block_threshold: None,
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
                block_threshold: None,
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
                block_threshold: None,
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
                prefix_len: None,
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
                prefix_len: None,
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
                prefix_len: None,
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
                prefix_len: None,
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
                prefix_len: None,
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
                prefix_len: None,
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
                block_threshold: None,
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
                prefix_len: None,
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
                    prefix_len: None,
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
                    block_threshold: None,
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
                    block_threshold: None,
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
                    prefix_len: None,
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

    fn clearfolio_test_config(base_url: &str) -> ClearfolioConfig {
        ClearfolioConfig {
            base_url: base_url.to_string(),
            tenant_id: "buyer-demo".to_string(),
            subject_id: "buyer-demo".to_string(),
            permissions: "job:read".to_string(),
        }
    }

    #[test]
    fn clearfolio_helpers_build_urls_headers_and_documents() {
        assert_eq!(
            clearfolio_submit_url("http://c"),
            "http://c/api/v1/convert/jobs"
        );
        assert_eq!(
            clearfolio_submit_url("http://c/"),
            "http://c/api/v1/convert/jobs"
        );
        assert_eq!(
            clearfolio_status_url("http://c/", "J1"),
            "http://c/api/v1/convert/jobs/J1"
        );
        let config = clearfolio_test_config("http://c");
        let headers = clearfolio_tenant_headers(&config);
        assert_eq!(headers[0], ("X-Clearfolio-Tenant-Id", "buyer-demo"));
        assert_eq!(headers[1], ("X-Clearfolio-Subject-Id", "buyer-demo"));
        assert_eq!(headers[2], ("X-Clearfolio-Permissions", "job:read"));

        let data = AppData::seeded();
        let (name, bytes) = clearfolio_document("evidence-manifest", &data).unwrap();
        assert_eq!(name, "evidence-manifest.txt");
        assert!(!bytes.is_empty());
        let (name, _) = clearfolio_document("soc-export", &data).unwrap();
        assert_eq!(name, "soc-export.txt");
        assert!(clearfolio_document("unknown", &data).is_none());
    }

    #[tokio::test]
    async fn clearfolio_config_reports_enabled_state() {
        let off = build_app(AppState::seeded(None));
        let disabled: serde_json::Value = json_body(
            app_request(&off, empty_request(Method::GET, "/api/clearfolio/config")).await,
        )
        .await;
        assert_eq!(disabled["enabled"], false);
        assert_eq!(disabled["base_url"], serde_json::Value::Null);

        let on = build_app(
            AppState::seeded(None)
                .with_clearfolio(Some(clearfolio_test_config("http://viewer.example"))),
        );
        let enabled: serde_json::Value =
            json_body(app_request(&on, empty_request(Method::GET, "/api/clearfolio/config")).await)
                .await;
        assert_eq!(enabled["enabled"], true);
        assert_eq!(enabled["base_url"], "http://viewer.example");
        assert_eq!(enabled["kinds"][0], "evidence-manifest");
    }

    #[tokio::test]
    async fn clearfolio_submit_and_status_guard_paths() {
        // Admin token required -> 401 without one.
        let secured = build_app(
            AppState::seeded(Some("secret".to_string()))
                .with_clearfolio(Some(clearfolio_test_config("http://127.0.0.1:1"))),
        );
        assert_eq!(
            app_request(
                &secured,
                empty_request(Method::POST, "/api/clearfolio/documents/evidence-manifest")
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app_request(
                &secured,
                empty_request(Method::GET, "/api/clearfolio/jobs/J1")
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );

        // Not configured -> 503.
        let unconfigured = build_app(AppState::seeded(None));
        assert_eq!(
            app_request(
                &unconfigured,
                empty_request(Method::POST, "/api/clearfolio/documents/evidence-manifest")
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            app_request(
                &unconfigured,
                empty_request(Method::GET, "/api/clearfolio/jobs/J1")
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // Configured but unknown document kind -> 404 (before any upstream call).
        let configured = build_app(
            AppState::seeded(None)
                .with_clearfolio(Some(clearfolio_test_config("http://127.0.0.1:1"))),
        );
        assert_eq!(
            app_request(
                &configured,
                empty_request(Method::POST, "/api/clearfolio/documents/unknown")
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn clearfolio_submit_and_status_relay_success_and_upstream_errors() {
        let mock = Router::new()
            .route(
                "/api/v1/convert/jobs",
                post(|| async {
                    (
                        StatusCode::ACCEPTED,
                        [("content-type", "application/json")],
                        r#"{"jobId":"J1","status":"PENDING","statusUrl":"/api/v1/convert/jobs/J1"}"#,
                    )
                }),
            )
            .route(
                "/api/v1/convert/jobs/{id}",
                get(|| async {
                    (
                        StatusCode::OK,
                        [("content-type", "application/json")],
                        r#"{"status":"SUCCEEDED","docId":"D1"}"#,
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, mock).into_future());

        let app = build_app(
            AppState::seeded(None)
                .with_clearfolio(Some(clearfolio_test_config(&format!("http://{addr}")))),
        );

        let submit = app_request(
            &app,
            empty_request(Method::POST, "/api/clearfolio/documents/evidence-manifest"),
        )
        .await;
        assert_eq!(submit.status(), StatusCode::ACCEPTED);
        let submit_body: serde_json::Value = json_body(submit).await;
        assert_eq!(submit_body["jobId"], "J1");

        let status = app_request(&app, empty_request(Method::GET, "/api/clearfolio/jobs/J1")).await;
        assert_eq!(status.status(), StatusCode::OK);
        let status_body: serde_json::Value = json_body(status).await;
        assert_eq!(status_body["docId"], "D1");

        // Unreachable upstream -> 502 on both submit and status.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let down = build_app(
            AppState::seeded(None)
                .with_clearfolio(Some(clearfolio_test_config(&format!("http://{dead_addr}")))),
        );
        assert_eq!(
            app_request(
                &down,
                empty_request(Method::POST, "/api/clearfolio/documents/soc-export")
            )
            .await
            .status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            app_request(&down, empty_request(Method::GET, "/api/clearfolio/jobs/J1"))
                .await
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }

    fn soc_test_event() -> SecurityEvent {
        SecurityEvent {
            id: 1,
            timestamp_unix: 1000,
            client_ip: Some("203.0.113.5".parse().unwrap()),
            route_id: Some("demo".to_string()),
            action: "blocked".to_string(),
            reason: "sqli signature".to_string(),
            score: 90,
            path: "/gateway/demo".to_string(),
        }
    }

    fn state_with_event_and_llm(base_url: &str) -> AppState {
        let mut data = AppData::seeded();
        data.events.push(soc_test_event());
        AppState::new(data, AppConfig::memory(None)).with_soc_llm(Some(SocLlmConfig {
            base_url: base_url.to_string(),
            token: "test-token".to_string(),
            model: "contextual-orchestrator".to_string(),
        }))
    }

    async fn spawn_chat_mock(response: &'static str) -> std::net::SocketAddr {
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move || async move {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    response,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        addr
    }

    #[test]
    fn soc_llm_chat_body_and_extract() {
        let body = soc_llm_chat_body("m1", &soc_test_event());
        assert_eq!(body["model"], "m1");
        assert_eq!(body["messages"][0]["role"], "system");
        assert!(
            body["messages"][1]["content"]
                .as_str()
                .unwrap()
                .contains("sqli signature")
        );
        // client_ip None branch renders "unknown".
        let mut anon = soc_test_event();
        anon.client_ip = None;
        let anon_body = soc_llm_chat_body("m1", &anon);
        assert!(
            anon_body["messages"][1]["content"]
                .as_str()
                .unwrap()
                .contains("client_ip: unknown")
        );

        let good = serde_json::json!({"choices":[{"message":{"content":"verdict"}}]});
        assert_eq!(soc_llm_extract_content(&good).unwrap(), "verdict");
        assert!(soc_llm_extract_content(&serde_json::json!({})).is_none());
        // Empty `choices` array: the first-element lookup must short-circuit to None.
        assert!(soc_llm_extract_content(&serde_json::json!({"choices":[]})).is_none());
        // A choice with no `message` object must short-circuit to None.
        assert!(soc_llm_extract_content(&serde_json::json!({"choices":[{}]})).is_none());
        assert!(
            soc_llm_extract_content(&serde_json::json!({"choices":[{"message":{}}]})).is_none()
        );
    }

    #[tokio::test]
    async fn soc_llm_config_reports_enabled_state() {
        let off = build_app(AppState::seeded(None));
        let disabled: serde_json::Value =
            json_body(app_request(&off, empty_request(Method::GET, "/api/soc/llm-config")).await)
                .await;
        assert_eq!(disabled["enabled"], false);

        let on = build_app(state_with_event_and_llm("http://llm.example"));
        let enabled: serde_json::Value =
            json_body(app_request(&on, empty_request(Method::GET, "/api/soc/llm-config")).await)
                .await;
        assert_eq!(enabled["enabled"], true);
        assert_eq!(enabled["model"], "contextual-orchestrator");
    }

    #[tokio::test]
    async fn soc_analyze_guard_paths() {
        // Unauthorized.
        let secured = build_app(
            AppState::seeded(Some("secret".to_string())).with_soc_llm(Some(SocLlmConfig {
                base_url: "http://127.0.0.1:1".to_string(),
                token: "t".to_string(),
                model: "m".to_string(),
            })),
        );
        assert_eq!(
            app_request(
                &secured,
                json_request(
                    Method::POST,
                    "/api/soc/analyze",
                    None,
                    &serde_json::json!({"event_id": 1})
                )
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );

        // Not configured -> 503.
        let unconfigured = build_app(AppState::seeded(None));
        assert_eq!(
            app_request(
                &unconfigured,
                json_request(
                    Method::POST,
                    "/api/soc/analyze",
                    None,
                    &serde_json::json!({"event_id": 1})
                )
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // Configured but unknown event id -> 404.
        let configured = build_app(state_with_event_and_llm("http://127.0.0.1:1"));
        assert_eq!(
            app_request(
                &configured,
                json_request(
                    Method::POST,
                    "/api/soc/analyze",
                    None,
                    &serde_json::json!({"event_id": 999})
                )
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn soc_analyze_success_and_upstream_errors() {
        // Success: mock returns a chat completion.
        let ok_addr =
            spawn_chat_mock(r#"{"choices":[{"message":{"content":"Likely SQLi. High severity. Block the source IP."}}]}"#)
                .await;
        let app = build_app(state_with_event_and_llm(&format!("http://{ok_addr}")));
        let resp = app_request(
            &app,
            json_request(
                Method::POST,
                "/api/soc/analyze",
                None,
                &serde_json::json!({"event_id": 1}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = json_body(resp).await;
        assert_eq!(body["event_id"], 1);
        assert!(body["analysis"].as_str().unwrap().contains("SQLi"));

        // Missing choices[0].message.content -> 502.
        let empty_addr = spawn_chat_mock("{}").await;
        let empty_app = build_app(state_with_event_and_llm(&format!("http://{empty_addr}")));
        assert_eq!(
            app_request(
                &empty_app,
                json_request(
                    Method::POST,
                    "/api/soc/analyze",
                    None,
                    &serde_json::json!({"event_id": 1})
                )
            )
            .await
            .status(),
            StatusCode::BAD_GATEWAY
        );

        // Non-JSON response -> 502.
        let bad_addr = spawn_chat_mock("not json").await;
        let bad_app = build_app(state_with_event_and_llm(&format!("http://{bad_addr}")));
        assert_eq!(
            app_request(
                &bad_app,
                json_request(
                    Method::POST,
                    "/api/soc/analyze",
                    None,
                    &serde_json::json!({"event_id": 1})
                )
            )
            .await
            .status(),
            StatusCode::BAD_GATEWAY
        );

        // Unreachable upstream -> 502.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let down = build_app(state_with_event_and_llm(&format!("http://{dead_addr}")));
        assert_eq!(
            app_request(
                &down,
                json_request(
                    Method::POST,
                    "/api/soc/analyze",
                    None,
                    &serde_json::json!({"event_id": 1})
                )
            )
            .await
            .status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
