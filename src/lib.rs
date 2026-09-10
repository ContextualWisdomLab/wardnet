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
    replace_threat_feed_ownership, select_route, signature_catalog, threat_feed_freshness_snapshot,
    threat_indicator_key, upsert_dnsbl, upsert_route, upsert_threat, upsert_threat_feed,
    validate_commercial_profile, validate_dnsbl, validate_route, validate_threat,
    validate_threat_feed_import,
};
pub use waf_ids_core::{
    AuditLogEntry, BuyerEvidenceEndpoint, BuyerEvidenceManifest, BuyerEvidenceRuntimeCounts,
    CommercialProfile, CommercialReadiness, DnsblEntry, EnforcementMode, LicenseStatus,
    NewAuditLogEntry, ProductEdition, ReadinessCheck, ReadinessStatus, RouteConfig, ScoredRequest,
    SecurityEvent, Severity, SignatureInfo, SocKpiSnapshot, TARGET_SALE_VALUE_KRW,
    ThreatFeedFreshness, ThreatFeedImport, ThreatFeedImportResult, ThreatFeedStatus,
    ThreatIndicator, export_dnsbl_zone, ip_in_network, reverse_ipv4_for_dnsbl, score_request,
};

mod coraza_audit;
mod credentials;
mod kev_import;
mod misp_import;
mod opencti_import;
mod stix_import;
mod suricata_eve;
mod taxii;
pub use credentials::{CRED_ADMIN_TOKEN, CRED_ADMIN_TOKENS, CredentialRegistry, CredentialSource};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppData>>,
    persist_lock: Arc<Mutex<()>>,
    http: reqwest::Client,
    feed_http: reqwest::Client,
    admin_token: Option<String>,
    // RBAC: multiple admin tokens each mapped to an actor + write capability.
    // Empty falls back to the single `admin_token`. Token values are never logged.
    admin_tokens: HashMap<String, AdminPrincipal>,
    /// Where admin secrets were bootstrapped from (file/env/none). Never holds values.
    credentials_source: CredentialSource,
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
    // Non-test runtime always fetches the built-in CISA KEV URL. Tests can
    // override it to point at a loopback mock server.
    #[cfg(test)]
    kev_catalog_url: Option<String>,
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
            feed_http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to build no-redirect feed client"),
            admin_token: config.admin_token,
            admin_tokens: HashMap::new(),
            credentials_source: CredentialSource::None,
            state_path: config.state_path,
            dnsbl_origin: normalized_origin(&config.dnsbl_origin),
            event_limit: config.event_limit.max(1),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: 0,
            rate_limit_window: 60,
            max_body_bytes: 1_048_576,
            clearfolio: None,
            soc_llm: None,
            #[cfg(test)]
            kev_catalog_url: None,
        }
    }

    /// Override the CISA KEV catalog URL (default: the real CISA feed).
    /// Deployment-time config only, for pointing at a local mock server in
    /// tests -- see `validate_kev_catalog_url`, which restricts the fetch to
    /// CISA's own host (or loopback) with no mirror override. Builder-style.
    #[cfg(test)]
    pub fn with_kev_catalog_url(mut self, url: impl Into<String>) -> Self {
        self.kev_catalog_url = Some(url.into());
        self
    }

    #[cfg(test)]
    fn kev_catalog_url(&self) -> &str {
        self.kev_catalog_url.as_deref().unwrap_or(KEV_DEFAULT_URL)
    }

    #[cfg(not(test))]
    fn kev_catalog_url(&self) -> &str {
        KEV_DEFAULT_URL
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

    /// Configure RBAC admin tokens (token -> principal). A non-empty map takes
    /// precedence over the single `admin_token`. Builder-style.
    pub fn with_admin_tokens(mut self, tokens: HashMap<String, AdminPrincipal>) -> Self {
        self.admin_tokens = tokens;
        self
    }

    /// Record how admin secrets were bootstrapped into the process (never values).
    pub fn with_credentials_source(mut self, source: CredentialSource) -> Self {
        self.credentials_source = source;
        self
    }

    /// The principal mapped to the request's `X-Admin-Token`, if configured.
    fn principal_for_token(&self, headers: &HeaderMap) -> Option<&AdminPrincipal> {
        headers
            .get("x-admin-token")
            .and_then(|value| value.to_str().ok())
            .and_then(|token| self.admin_tokens.get(token))
    }

    /// The actor name mapped to the request's `X-Admin-Token`, if that token is a
    /// configured RBAC token.
    fn actor_for_token(&self, headers: &HeaderMap) -> Option<String> {
        self.principal_for_token(headers)
            .map(|principal| principal.actor.clone())
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
            credentials_source: self.credentials_source.as_str().to_string(),
            admin_auth_configured: self.admin_token.is_some() || !self.admin_tokens.is_empty(),
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
    /// Bootstrap origin for admin secrets: `file`, `env`, or `none` (never secret values).
    pub credentials_source: String,
    /// True when at least one admin write token is configured.
    pub admin_auth_configured: bool,
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
const PHISHING_DATABASE_ALLOWED_HOSTS: &[&str] = &["raw.githubusercontent.com", "phish.co.za"];

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

const KEV_DEFAULT_FEED_ID: &str = "cisa-kev";
const KEV_DEFAULT_SOURCE: &str = "feed:cisa-kev";
const KEV_DEFAULT_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_DEFAULT_TTL_SECONDS: u64 = 86_400;
const KEV_ALLOWED_HOSTS: &[&str] = &["www.cisa.gov"];

fn kev_default_feed_id() -> String {
    KEV_DEFAULT_FEED_ID.to_string()
}

fn kev_default_source() -> String {
    KEV_DEFAULT_SOURCE.to_string()
}

fn kev_default_ttl_seconds() -> u64 {
    KEV_DEFAULT_TTL_SECONDS
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
        .route("/api/commercial/license", get(get_commercial_license).post(update_commercial_license))
        .route("/api/commercial/readiness", get(commercial_readiness))
        .route("/api/commercial/evidence-manifest", get(commercial_evidence_manifest))
        .route("/api/threat-feeds", get(list_threat_feeds))
        .route("/api/threat-feeds/freshness", get(threat_feed_freshness))
        .route("/api/threat-feeds/import", post(import_threat_feed))
        .route("/api/threat-feeds/import/phishing-database", post(import_phishing_database_feed))
        .route("/api/ids/suricata/eve", post(import_suricata_eve))
        .route("/api/waf/coraza/audit", post(import_coraza_audit))
        .route("/api/threat-intel/stix", post(import_stix_document))
        .route("/api/threat-intel/misp", post(import_misp_document))
        .route("/api/threat-intel/taxii/poll", post(poll_taxii_collection))
        .route("/api/threat-intel/opencti", post(import_opencti_document))
        .route("/api/threat-intel/cisa-kev", post(import_kev_feed))
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

fn clearfolio_submit_url(base: &str) -> String {
    format!("{}/api/v1/convert/jobs", base.trim_end_matches('/'))
}
fn clearfolio_status_url(base: &str, job_id: &str) -> String {
    format!("{}/api/v1/convert/jobs/{job_id}", base.trim_end_matches('/'))
}
fn clearfolio_tenant_headers(config: &ClearfolioConfig) -> [(&'static str, &str); 3] {
    [
        ("X-Clearfolio-Tenant-Id", config.tenant_id.as_str()),
        ("X-Clearfolio-Subject-Id", config.subject_id.as_str()),
        ("X-Clearfolio-Permissions", config.permissions.as_str()),
    ]
}
fn clearfolio_document(kind: &str, data: &AppData) -> Option<(String, Vec<u8>)> {
    let (name, text) = match kind {
        "evidence-manifest" => (
            "evidence-manifest.txt",
            serde_json::to_string_pretty(&buyer_evidence_manifest_at(data, now_unix())).expect("evidence manifest is JSON-serializable"),
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
    let status = StatusCode::from_u16(response.status().as_u16()).expect("clearfolio status codes are valid HTTP status codes");
    let body = response.bytes().await.unwrap_or_default();
    (status, [("content-type", "application/json")], body).into_response()
}
#[derive(Serialize)]
struct ClearfolioConfigView { enabled: bool, base_url: Option<String>, kinds: [&'static str; 2] }
async fn clearfolio_config(State(state): State<AppState>) -> Json<ClearfolioConfigView> {
    let base_url = state.clearfolio.as_ref().map(|c| c.base_url.clone());
    Json(ClearfolioConfigView { enabled: base_url.is_some(), base_url, kinds: ["evidence-manifest", "soc-export"] })
}
async fn clearfolio_submit(State(state): State<AppState>, PathParam(kind): PathParam<String>, headers: HeaderMap) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    let Some(config) = state.clearfolio.clone() else { return error(StatusCode::SERVICE_UNAVAILABLE, "Clearfolio integration is not configured"); };
    let document = { let data = state.inner.read().await; clearfolio_document(&kind, &data) };
    let Some((filename, bytes)) = document else { return error(StatusCode::NOT_FOUND, format!("unknown document kind: {kind}")); };
    let part = reqwest::multipart::Part::bytes(bytes).file_name(filename).mime_str("text/plain").expect("text/plain is a valid MIME type");
    let form = reqwest::multipart::Form::new().part("file", part);
    let mut request = state.http.post(clearfolio_submit_url(&config.base_url)).multipart(form);
    for (name, value) in clearfolio_tenant_headers(&config) { request = request.header(name, value); }
    match request.send().await {
        Ok(response) => clearfolio_relay_json(response).await,
        Err(err) => error(StatusCode::BAD_GATEWAY, format!("clearfolio request failed: {err}")),
    }
}
async fn clearfolio_status(State(state): State<AppState>, PathParam(job_id): PathParam<String>, headers: HeaderMap) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    let Some(config) = state.clearfolio.clone() else { return error(StatusCode::SERVICE_UNAVAILABLE, "Clearfolio integration is not configured"); };
    let mut request = state.http.get(clearfolio_status_url(&config.base_url, &job_id));
    for (name, value) in clearfolio_tenant_headers(&config) { request = request.header(name, value); }
    match request.send().await {
        Ok(response) => clearfolio_relay_json(response).await,
        Err(err) => error(StatusCode::BAD_GATEWAY, format!("clearfolio request failed: {err}")),
    }
}

fn soc_llm_chat_body(model: &str, event: &SecurityEvent) -> serde_json::Value {
    let client_ip = event.client_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string());
    let user = format!("WAF/IDS security event:\n- action: {}\n- reason: {}\n- score: {}\n- path: {}\n- client_ip: {}\n- timestamp_unix: {}", event.action, event.reason, event.score, event.path, client_ip, event.timestamp_unix);
    serde_json::json!({"model": model,"orchestration_mode": "auto","messages": [{"role": "system","content": "You are a senior SOC analyst. For the WAF/IDS event, state the likely attack class, a severity judgement, and one recommended action. Answer in under 120 words."},{ "role": "user", "content": user }]})
}
fn soc_llm_extract_content(body: &serde_json::Value) -> Option<String> {
    body.get("choices")?.get(0)?.get("message")?.get("content")?.as_str().map(|text| text.to_string())
}
#[derive(Serialize)]
struct SocLlmConfigView { enabled: bool, model: Option<String> }
async fn soc_llm_config(State(state): State<AppState>) -> Json<SocLlmConfigView> {
    let model = state.soc_llm.as_ref().map(|c| c.model.clone());
    Json(SocLlmConfigView { enabled: model.is_some(), model })
}
#[derive(Deserialize)]
struct SocAnalyzeRequest { event_id: u64 }
#[derive(Debug, Clone, Deserialize, Serialize)]
struct PhishingDatabaseImportRequest {
    #[serde(default = "phishing_database_default_feed_id")] feed_id: String,
    #[serde(default = "phishing_database_default_source")] source: String,
    #[serde(default = "phishing_database_default_domain_url")] domain_url: String,
    #[serde(default = "phishing_database_default_ip_url")] ip_url: String,
    #[serde(default = "phishing_database_default_ttl_seconds")] ttl_seconds: u64,
    #[serde(default = "phishing_database_default_domain_limit")] domain_limit: usize,
    #[serde(default = "phishing_database_default_ip_limit")] ip_limit: usize,
    #[serde(default = "phishing_database_default_severity")] severity: Severity,
    #[serde(default = "default_true")] import_domains: bool,
    #[serde(default = "default_true")] import_ips: bool,
    #[serde(default)] allow_non_default_hosts: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct KevImportRequest {
    #[serde(default = "kev_default_feed_id")] feed_id: String,
    #[serde(default = "kev_default_source")] source: String,
    #[serde(default = "kev_default_ttl_seconds")] ttl_seconds: u64,
}
#[derive(Debug, Serialize)]
struct KevImportResult { feed_id: String, upserted_threats: usize, upserted_dnsbl: usize, skipped_entries: usize, last_updated_unix: u64 }
#[derive(Serialize)]
struct SocAnalyzeResponse { event_id: u64, model: String, analysis: String }
async fn soc_analyze(State(state): State<AppState>, headers: HeaderMap, Json(request): Json<SocAnalyzeRequest>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    let Some(config) = state.soc_llm.clone() else { return error(StatusCode::SERVICE_UNAVAILABLE, "LLM SOC analysis is not configured"); };
    let event = { let data = state.inner.read().await; data.events.iter().find(|event| event.id == request.event_id).cloned() };
    let Some(event) = event else { return error(StatusCode::NOT_FOUND, format!("unknown event id: {}", request.event_id)); };
    let body = soc_llm_chat_body(&config.model, &event);
    let endpoint = format!("{}/v1/chat/completions", config.base_url.trim_end_matches('/'));
    let response = state.http.post(endpoint).bearer_auth(&config.token).json(&body).send().await;
    match response {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(json) => match soc_llm_extract_content(&json) {
                Some(analysis) => Json(SocAnalyzeResponse { event_id: event.id, model: config.model, analysis }).into_response(),
                None => error(StatusCode::BAD_GATEWAY, "llm response missing choices[0].message.content"),
            },
            Err(err) => error(StatusCode::BAD_GATEWAY, format!("llm response read failed: {err}")),
        },
        Err(err) => error(StatusCode::BAD_GATEWAY, format!("llm request failed: {err}")),
    }
}

async fn healthz(State(state): State<AppState>) -> Json<HealthStatus> { Json(state.health_status()) }
async fn version() -> Json<serde_json::Value> { Json(serde_json::json!({"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")})) }
async fn readyz(State(state): State<AppState>) -> Response {
    let routes_enabled = { let data = state.inner.read().await; data.routes.iter().filter(|route| route.enabled).count() };
    let ready = routes_enabled > 0;
    let status = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(serde_json::json!({"ready": ready,"routes_enabled": routes_enabled}))).into_response()
}
async fn admin_console() -> Html<&'static str> { Html(ADMIN_HTML) }
async fn list_routes(State(state): State<AppState>) -> Json<Vec<RouteConfig>> { Json(state.inner.read().await.routes.clone()) }
async fn create_route(State(state): State<AppState>, headers: HeaderMap, Json(route): Json<RouteConfig>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if let Err(message) = validate_route(&route) { return error(StatusCode::BAD_REQUEST, message); }
    let actor = audit_actor(&state, &headers);
    match state.mutate_and_persist(|data| { let saved = upsert_route(&mut data.routes, route.clone()); record_successful_audit_log(data, actor, "upsert_route", "route", saved.id.clone()); saved }).await {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}
async fn list_threats(State(state): State<AppState>) -> Json<Vec<ThreatIndicator>> { Json(state.inner.read().await.threats.clone()) }
async fn create_threat(State(state): State<AppState>, headers: HeaderMap, Json(indicator): Json<ThreatIndicator>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if let Err(message) = validate_threat(&indicator) { return error(StatusCode::BAD_REQUEST, message); }
    let actor = audit_actor(&state, &headers);
    match state.mutate_and_persist(|data| { let saved = upsert_threat(&mut data.threats, indicator.clone()); mark_operator_threat_key(data, &saved); record_successful_audit_log(data, actor, "upsert_threat", "threat_indicator", threat_resource_id(&saved)); saved }).await {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}
async fn list_dnsbl(State(state): State<AppState>) -> Json<Vec<DnsblEntry>> { Json(state.inner.read().await.dnsbl.clone()) }
async fn create_dnsbl(State(state): State<AppState>, headers: HeaderMap, Json(entry): Json<DnsblEntry>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if let Err(message) = validate_dnsbl(&entry) { return error(StatusCode::BAD_REQUEST, message); }
    let actor = audit_actor(&state, &headers);
    match state.mutate_and_persist(|data| { let saved = upsert_dnsbl(&mut data.dnsbl, entry.clone()); record_successful_audit_log(data, actor, "upsert_dnsbl", "dnsbl_entry", saved.address.to_string()); saved }).await {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}
#[derive(Deserialize)] struct EventQuery { #[serde(default)] action: Option<String>, #[serde(default)] limit: Option<usize> }
async fn list_events(State(state): State<AppState>, Query(query): Query<EventQuery>) -> Json<Vec<SecurityEvent>> {
    let data = state.inner.read().await;
    let mut events: Vec<SecurityEvent> = match &query.action { Some(action) => data.events.iter().filter(|event| &event.action == action).cloned().collect(), None => data.events.clone() };
    if let Some(limit) = query.limit { let start = events.len().saturating_sub(limit); events.drain(..start); }
    Json(events)
}
async fn list_audit_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !admin_authenticated(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    Json(state.inner.read().await.audit_logs.clone()).into_response()
}
async fn kpis(State(state): State<AppState>) -> Json<SocKpiSnapshot> { let data = state.inner.read().await; Json(kpi_snapshot_at(&data, now_unix())) }
async fn list_signatures() -> Json<Vec<SignatureInfo>> { Json(signature_catalog()) }
#[derive(Deserialize)] struct EvaluateRequest { path: String, #[serde(default)] query: Option<String>, #[serde(default)] body: Option<String>, #[serde(default)] client_ip: Option<IpAddr> }
#[derive(Serialize)] struct EvaluateResponse { score: u16, reason: String, would_block: bool }
async fn evaluate_request(State(state): State<AppState>, Json(request): Json<EvaluateRequest>) -> Json<EvaluateResponse> {
    let data = state.inner.read().await;
    let scored = score_request(&request.path, request.query.as_deref(), request.body.as_deref().unwrap_or(""), request.client_ip, &data.threats, &data.dnsbl);
    Json(EvaluateResponse { would_block: scored.score >= BLOCK_SCORE, score: scored.score, reason: scored.reason })
}
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = { let data = state.inner.read().await; prometheus_exposition(&kpi_snapshot_at(&data, now_unix())) };
    ([(axum::http::header::CONTENT_TYPE,"text/plain; version=0.0.4; charset=utf-8")],body)
}
async fn get_commercial_license(State(state): State<AppState>) -> Json<CommercialProfile> { Json(state.inner.read().await.commercial.clone()) }
async fn update_commercial_license(State(state): State<AppState>, headers: HeaderMap, Json(profile): Json<CommercialProfile>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if let Err(message) = validate_commercial_profile(&profile) { return error(StatusCode::BAD_REQUEST, message); }
    let actor = audit_actor(&state, &headers);
    match state.mutate_and_persist(|data| { data.commercial = profile.clone(); record_successful_audit_log(data, actor, "update_commercial_license", "commercial_license", profile.tenant_id.clone()); profile }).await {
        Ok(saved) => (StatusCode::CREATED, Json(saved)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}
async fn commercial_readiness(State(state): State<AppState>) -> Json<CommercialReadiness> { let data = state.inner.read().await; Json(commercial_readiness_snapshot_at(&data, now_unix())) }
async fn commercial_evidence_manifest(State(state): State<AppState>) -> Json<BuyerEvidenceManifest> { let data = state.inner.read().await; Json(buyer_evidence_manifest_at(&data, now_unix())) }
async fn list_threat_feeds(State(state): State<AppState>) -> Json<Vec<ThreatFeedStatus>> { Json(state.inner.read().await.threat_feeds.clone()) }
async fn threat_feed_freshness(State(state): State<AppState>) -> Json<Vec<ThreatFeedFreshness>> { let data = state.inner.read().await; Json(threat_feed_freshness_snapshot(&data.threat_feeds, now_unix())) }
async fn import_threat_feed(State(state): State<AppState>, headers: HeaderMap, Json(feed): Json<ThreatFeedImport>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if let Err(message) = validate_threat_feed_import(&feed) { return error(StatusCode::BAD_REQUEST, message); }
    let actor = audit_actor(&state, &headers);
    match apply_threat_feed_import(&state, actor, "import_threat_feed", feed).await { Ok(result) => (StatusCode::CREATED, Json(result)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message) }
}

fn stix_default_feed_id() -> String { "stix-import".to_string() }
fn stix_default_source() -> String { "stix".to_string() }
fn stix_default_ttl_seconds() -> u64 { 86_400 }
#[derive(Debug, Deserialize)] struct StixImportQuery { #[serde(default = "stix_default_feed_id")] feed_id: String, #[serde(default = "stix_default_source")] source: String, #[serde(default = "stix_default_ttl_seconds")] ttl_seconds: u64 }
#[derive(Debug, Serialize)] struct StixImportResult { feed_id: String, upserted_threats: usize, upserted_dnsbl: usize, skipped_objects: usize, last_updated_unix: u64 }
async fn import_stix_document(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<StixImportQuery>, body: Bytes) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if query.feed_id.trim().is_empty() || query.source.trim().is_empty() { return error(StatusCode::BAD_REQUEST, "feed_id and source must be non-empty"); }
    if query.ttl_seconds == 0 { return error(StatusCode::BAD_REQUEST, "ttl_seconds must be greater than 0"); }
    let body_text = match std::str::from_utf8(&body) { Ok(text) => text, Err(_) => return error(StatusCode::BAD_REQUEST, "STIX body must be UTF-8 text") };
    let material = match stix_import::parse_stix_document(body_text, query.source.trim(), query.ttl_seconds) { Ok(material) => material, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    let actor = audit_actor(&state, &headers);
    let feed = ThreatFeedImport { feed_id: query.feed_id.trim().to_string(), source: query.source.trim().to_string(), ttl_seconds: query.ttl_seconds, threats: material.threats, dnsbl: material.dnsbl };
    if let Err(message) = validate_threat_feed_import(&feed) { return error(StatusCode::BAD_REQUEST, message); }
    let skipped_objects = material.skipped_objects;
    match apply_threat_feed_import(&state, actor, "import_stix_document", feed).await { Ok(result) => (StatusCode::CREATED, Json(StixImportResult { feed_id: result.feed_id, upserted_threats: result.upserted_threats, upserted_dnsbl: result.upserted_dnsbl, skipped_objects, last_updated_unix: result.last_updated_unix })).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message) }
}

fn misp_default_feed_id() -> String { "misp-import".to_string() }
fn misp_default_source() -> String { "misp".to_string() }
fn misp_default_ttl_seconds() -> u64 { 86_400 }
#[derive(Debug, Deserialize)] struct MispImportQuery { #[serde(default = "misp_default_feed_id")] feed_id: String, #[serde(default = "misp_default_source")] source: String, #[serde(default = "misp_default_ttl_seconds")] ttl_seconds: u64 }
#[derive(Debug, Serialize)] struct MispImportResult { feed_id: String, upserted_threats: usize, upserted_dnsbl: usize, skipped_attributes: usize, last_updated_unix: u64 }
async fn import_misp_document(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<MispImportQuery>, body: Bytes) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if query.feed_id.trim().is_empty() || query.source.trim().is_empty() { return error(StatusCode::BAD_REQUEST, "feed_id and source must be non-empty"); }
    if query.ttl_seconds == 0 { return error(StatusCode::BAD_REQUEST, "ttl_seconds must be greater than 0"); }
    let body_text = match std::str::from_utf8(&body) { Ok(text) => text, Err(_) => return error(StatusCode::BAD_REQUEST, "MISP body must be UTF-8 text") };
    let material = match misp_import::parse_misp_document(body_text, query.source.trim(), query.ttl_seconds) { Ok(material) => material, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    let actor = audit_actor(&state, &headers);
    let feed = ThreatFeedImport { feed_id: query.feed_id.trim().to_string(), source: query.source.trim().to_string(), ttl_seconds: query.ttl_seconds, threats: material.threats, dnsbl: material.dnsbl };
    if let Err(message) = validate_threat_feed_import(&feed) { return error(StatusCode::BAD_REQUEST, message); }
    let skipped_attributes = material.skipped_attributes;
    match apply_threat_feed_import(&state, actor, "import_misp_document", feed).await { Ok(result) => (StatusCode::CREATED, Json(MispImportResult { feed_id: result.feed_id, upserted_threats: result.upserted_threats, upserted_dnsbl: result.upserted_dnsbl, skipped_attributes, last_updated_unix: result.last_updated_unix })).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message) }
}

fn opencti_default_feed_id() -> String { "opencti-import".to_string() }
fn opencti_default_source() -> String { "opencti".to_string() }
fn opencti_default_ttl_seconds() -> u64 { 86_400 }
#[derive(Debug, Deserialize)] struct OpenCtiImportQuery { #[serde(default = "opencti_default_feed_id")] feed_id: String, #[serde(default = "opencti_default_source")] source: String, #[serde(default = "opencti_default_ttl_seconds")] ttl_seconds: u64 }
#[derive(Debug, Serialize)] struct OpenCtiImportResult { feed_id: String, upserted_threats: usize, upserted_dnsbl: usize, skipped_objects: usize, last_updated_unix: u64 }
async fn import_opencti_document(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<OpenCtiImportQuery>, body: Bytes) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if query.feed_id.trim().is_empty() || query.source.trim().is_empty() { return error(StatusCode::BAD_REQUEST, "feed_id and source must be non-empty"); }
    if query.ttl_seconds == 0 { return error(StatusCode::BAD_REQUEST, "ttl_seconds must be greater than 0"); }
    let body_text = match std::str::from_utf8(&body) { Ok(text) => text, Err(_) => return error(StatusCode::BAD_REQUEST, "OpenCTI body must be UTF-8 text") };
    let material = match opencti_import::parse_opencti_document(body_text, query.source.trim(), query.ttl_seconds) { Ok(material) => material, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    let actor = audit_actor(&state, &headers);
    let feed = ThreatFeedImport { feed_id: query.feed_id.trim().to_string(), source: query.source.trim().to_string(), ttl_seconds: query.ttl_seconds, threats: material.threats, dnsbl: material.dnsbl };
    if let Err(message) = validate_threat_feed_import(&feed) { return error(StatusCode::BAD_REQUEST, message); }
    let skipped_objects = material.skipped_objects;
    match apply_threat_feed_import(&state, actor, "import_opencti_document", feed).await { Ok(result) => (StatusCode::CREATED, Json(OpenCtiImportResult { feed_id: result.feed_id, upserted_threats: result.upserted_threats, upserted_dnsbl: result.upserted_dnsbl, skipped_objects, last_updated_unix: result.last_updated_unix })).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message) }
}

#[derive(Debug, Deserialize)] struct TaxiiPollRequest { #[serde(default)] objects_url: Option<String>, #[serde(default)] api_root: Option<String>, #[serde(default)] collection_id: Option<String>, #[serde(default = "taxii_default_feed_id")] feed_id: String, #[serde(default = "taxii_default_source")] source: String, #[serde(default = "taxii_default_ttl_seconds")] ttl_seconds: u64, #[serde(default)] added_after: Option<String>, #[serde(default)] bearer_token: Option<String>, #[serde(default)] username: Option<String>, #[serde(default)] password: Option<String> }
fn taxii_default_feed_id() -> String { "taxii-import".to_string() }
fn taxii_default_source() -> String { "taxii".to_string() }
fn taxii_default_ttl_seconds() -> u64 { 86_400 }
#[derive(Debug, Serialize)] struct TaxiiPollResult { feed_id: String, objects_url: String, upserted_threats: usize, upserted_dnsbl: usize, skipped_objects: usize, last_updated_unix: u64 }
async fn poll_taxii_collection(State(state): State<AppState>, headers: HeaderMap, Json(request): Json<TaxiiPollRequest>) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    if request.feed_id.trim().is_empty() || request.source.trim().is_empty() { return error(StatusCode::BAD_REQUEST, "feed_id and source must be non-empty"); }
    if request.ttl_seconds == 0 { return error(StatusCode::BAD_REQUEST, "ttl_seconds must be greater than 0"); }
    let base_url = match resolve_taxii_objects_url(&request) { Ok(url) => url, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    if let Err(message) = validate_http_url(&base_url, true) { return error(StatusCode::BAD_REQUEST, format!("invalid TAXII objects URL: {message}")); }
    let objects_url = match taxii::with_taxii_filters(&base_url, request.added_after.as_deref()) { Ok(url) => url, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    let body_text = match fetch_taxii_objects(&state, &objects_url, request.bearer_token.as_deref(), request.username.as_deref(), request.password.as_deref()).await { Ok(body) => body, Err(message) => return error(StatusCode::BAD_GATEWAY, message) };
    let stix_json = match taxii::stix_json_from_taxii_response(&body_text) { Ok(json) => json, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    let material = match stix_import::parse_stix_document(&stix_json, request.source.trim(), request.ttl_seconds) { Ok(material) => material, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    let actor = audit_actor(&state, &headers);
    let feed = ThreatFeedImport { feed_id: request.feed_id.trim().to_string(), source: request.source.trim().to_string(), ttl_seconds: request.ttl_seconds, threats: material.threats, dnsbl: material.dnsbl };
    if let Err(message) = validate_threat_feed_import(&feed) { return error(StatusCode::BAD_REQUEST, message); }
    let skipped_objects = material.skipped_objects;
    match apply_threat_feed_import(&state, actor, "poll_taxii_collection", feed).await { Ok(result) => (StatusCode::CREATED, Json(TaxiiPollResult { feed_id: result.feed_id, objects_url: base_url, upserted_threats: result.upserted_threats, upserted_dnsbl: result.upserted_dnsbl, skipped_objects, last_updated_unix: result.last_updated_unix })).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message) }
}
fn resolve_taxii_objects_url(request: &TaxiiPollRequest) -> Result<String, String> {
    if let Some(url) = request.objects_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) { return Ok(url.to_string()); }
    let api_root = request.api_root.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let collection_id = request.collection_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match (api_root, collection_id) { (Some(root), Some(id)) => taxii::collection_objects_url(root, id), _ => Err("provide objects_url or both api_root and collection_id for TAXII poll".to_string()) }
}
async fn fetch_taxii_objects(state: &AppState, url: &str, bearer_token: Option<&str>, username: Option<&str>, password: Option<&str>) -> Result<String, String> {
    use futures_util::StreamExt;
    let mut request = state.feed_http.get(url).header("Accept", "application/taxii+json;version=2.1, application/stix+json;version=2.1, application/json").timeout(std::time::Duration::from_secs(PHISHING_DATABASE_FETCH_TIMEOUT_SECS));
    if let Some(token) = bearer_token.map(str::trim).filter(|s| !s.is_empty()) { request = request.bearer_auth(token); } else if let Some(user) = username.map(str::trim).filter(|s| !s.is_empty()) { request = request.basic_auth(user, password); }
    let response = request.send().await.map_err(|error| format!("failed to poll TAXII collection: {error}"))?;
    let status = response.status(); if !status.is_success() { return Err(format!("TAXII server returned HTTP {status}")); }
    if let Some(len) = response.content_length() && len as usize > PHISHING_DATABASE_MAX_BODY_BYTES { return Err(format!("TAXII response body too large: {len} bytes (limit: {PHISHING_DATABASE_MAX_BODY_BYTES})")); }
    let mut bytes = Vec::new(); let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await { let chunk = chunk.map_err(|error| format!("failed to read TAXII body: {error}"))?; if bytes.len().saturating_add(chunk.len()) > PHISHING_DATABASE_MAX_BODY_BYTES { return Err(format!("TAXII response body too large: limit {PHISHING_DATABASE_MAX_BODY_BYTES} bytes exceeded while streaming")); } bytes.extend_from_slice(&chunk); }
    String::from_utf8(bytes).map_err(|error| format!("TAXII response is not valid UTF-8: {error}"))
}

#[derive(Debug, Serialize)] struct SuricataEveImportResult { accepted_alerts: usize, skipped_non_alerts: usize, event_ids: Vec<u64>, enforcement_hints: usize }
async fn import_suricata_eve(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    let body_text = match std::str::from_utf8(&body) { Ok(text) => text, Err(_) => return error(StatusCode::BAD_REQUEST, "Suricata EVE body must be UTF-8 text") };
    let parsed = match suricata_eve::parse_suricata_eve_body(body_text) { Ok(parsed) => parsed, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    if parsed.alerts.is_empty() { return error(StatusCode::BAD_REQUEST, "no Suricata alert events found (event_type=alert required)"); }
    let actor = audit_actor(&state, &headers); let event_limit = state.event_limit; let accepted = parsed.alerts.len(); let skipped_non_alerts = parsed.skipped_non_alerts;
    match state.mutate_and_persist(|data| {
        let mut created_ids = Vec::with_capacity(accepted); let mut enforcement_hints = 0usize; let ingest_now = now_unix();
        for alert in &parsed.alerts { let id = data.next_event_id; data.next_event_id += 1; let event = SecurityEvent { id, timestamp_unix: alert.timestamp_unix.unwrap_or(ingest_now), client_ip: alert.client_ip, route_id: None, action: alert.action.clone(), reason: alert.reason.clone(), score: alert.score, path: alert.path.clone() }; println!("{}", security_event_log_line(&event)); data.events.push(event); created_ids.push(id); enforcement_hints = enforcement_hints.saturating_add(apply_engine_enforcement_hints(data,"engine:suricata",&alert.action,alert.client_ip,&alert.path,&alert.reason,alert.score)); }
        enforce_event_limit(data, event_limit); let retained: HashSet<u64> = data.events.iter().map(|e| e.id).collect(); let event_ids: Vec<u64> = created_ids.into_iter().filter(|id| retained.contains(id)).collect(); record_successful_audit_log(data, actor, "import_suricata_eve", "ids_suricata", format!("{accepted}_alerts")); SuricataEveImportResult { accepted_alerts: accepted, skipped_non_alerts, event_ids, enforcement_hints }
    }).await { Ok(result) => (StatusCode::CREATED, Json(result)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, message) }
}
#[derive(Debug, Serialize)] struct CorazaAuditImportResult { accepted_hits: usize, skipped: usize, event_ids: Vec<u64>, enforcement_hints: usize }
async fn import_coraza_audit(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !admin_authorized(&state, &headers) { return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token"); }
    let body_text = match std::str::from_utf8(&body) { Ok(text) => text, Err(_) => return error(StatusCode::BAD_REQUEST, "Coraza audit body must be UTF-8 text") };
    let parsed = match coraza_audit::parse_coraza_audit_body(body_text) { Ok(parsed) => parsed, Err(message) => return error(StatusCode::BAD_REQUEST, message) };
    if parsed.hits.is_empty() { return error(StatusCode::BAD_REQUEST, "no Coraza WAF hits found (need messages[] or interrupted transaction)"); }
    let actor = audit_actor(&state, &headers); let event_limit = state.event_limit; let accepted = parsed.hits.len(); let skipped = parsed.skipped;
    match state.mutate_and_persist(|data| { let mut created_ids = Vec::with_capacity(accepted); let mut enforcement_hints = 0usize; let ingest_now = now_unix(); for hit in &parsed.hits { let id = data.next_event_id; data.next_event_id += 1; let event = SecurityEvent { id, timestamp_unix: hit.timestamp_unix.unwrap_or(ingest_now), client_ip: hit.client_ip, route_id: None, action: hit.action.clone(), reason: hit.reason.clone(), score: hit.score, path: hit.path.clone() }; println!("{}", security_event_log_line(&event)); data.events.push(event); created_ids.push(id); enforcement_hints = enforcement_hints.saturating_add(apply_engine_enforcement_hints(data,"engine:coraza",&hit.action,hit.client_ip,&hit.path,&hit.reason,hit.score)); } enforce_event_limit(data,event_limit); let retained: HashSet<u64> = data.events.iter().map(|e| e.id).collect(); let event_ids: Vec<u64> = created_ids.into_iter().filter(|id| retained.contains(id)).collect(); record_successful_audit_log(data,actor,"import_coraza_audit","waf_coraza",format!("{accepted}_hits")); CorazaAuditImportResult { accepted_hits: accepted, skipped, event_ids, enforcement_hints } }).await { Ok(result) => (StatusCode::CREATED,Json(result)).into_response(), Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR,message) }
}
fn apply_engine_enforcement_hints(data: &mut AppData, source: &str, action: &str, client_ip: Option<IpAddr>, path: &str, reason: &str, score: u16) -> usize {
    if action != "block" && score < BLOCK_SCORE { return 0; }
    const TTL_SECONDS: u64 = 3_600; let mut written = 0usize; let severity = if score >= 80 { Severity::High } else { Severity::Medium };
    let reason = { let trimmed = reason.trim(); if trimmed.len() > 200 { format!("{}…", &trimmed[..199]) } else if trimmed.is_empty() { format!("{source} engine hit") } else { trimmed.to_string() } };
    if let Some(ip) = client_ip { let dnsbl = DnsblEntry { address: ip, code:"127.0.0.2".to_string(), reason:reason.clone(), source:source.to_string(), ttl_seconds:TTL_SECONDS, prefix_len:None }; if validate_dnsbl(&dnsbl).is_ok() { upsert_dnsbl(&mut data.dnsbl,dnsbl); written += 1; } let ip_indicator = ThreatIndicator { value:ip.to_string(), indicator_type:"client_ip".to_string(), severity:severity.clone(), source:source.to_string(), ttl_seconds:TTL_SECONDS }; if validate_threat(&ip_indicator).is_ok() { upsert_threat(&mut data.threats,ip_indicator); written += 1; } }
    let path_only = path.split('?').next().unwrap_or(path).trim(); if path_only.starts_with('/') && path_only.len() > 1 { let path_indicator = ThreatIndicator { value:path_only.to_string(), indicator_type:"path".to_string(), severity, source:source.to_string(), ttl_seconds:TTL_SECONDS }; if validate_threat(&path_indicator).is_ok() { upsert_threat(&mut data.threats,path_indicator); written += 1; } }
    written
}

async fn import_phishing_database_feed(State(state): State<AppState>, headers: HeaderMap, Json(request): Json<PhishingDatabaseImportRequest>) -> Response {
    if !admin_authorized(&state,&headers) { return error(StatusCode::UNAUTHORIZED,"missing or invalid X-Admin-Token"); }
    if let Err(message)=validate_phishing_database_import_request(&request){return error(StatusCode::BAD_REQUEST,message);}
    let (domains_text,ips_text)=match (request.import_domains,request.import_ips){(true,true)=>match tokio::try_join!(fetch_text_feed(&state,&request.domain_url),fetch_text_feed(&state,&request.ip_url)){Ok((domains,ips))=>(domains,ips),Err(message)=>return error(StatusCode::BAD_GATEWAY,message)},(true,false)=>match fetch_text_feed(&state,&request.domain_url).await{Ok(domains)=>(domains,String::new()),Err(message)=>return error(StatusCode::BAD_GATEWAY,message)},(false,true)=>match fetch_text_feed(&state,&request.ip_url).await{Ok(ips)=>(String::new(),ips),Err(message)=>return error(StatusCode::BAD_GATEWAY,message)},(false,false)=>(String::new(),String::new())};
    let source_tag=request.feed_id.clone(); let threats=if request.import_domains{parse_phishing_domains(&domains_text,request.domain_limit).into_iter().map(|domain|ThreatIndicator{value:domain,indicator_type:"phishing_domain".to_string(),severity:request.severity.clone(),source:source_tag.clone(),ttl_seconds:request.ttl_seconds}).collect()}else{Vec::new()}; let dnsbl=if request.import_ips{parse_phishing_ips(&ips_text,request.ip_limit).into_iter().map(|address|DnsblEntry{address,code:PHISHING_DATABASE_DNSBL_CODE.to_string(),reason:PHISHING_DATABASE_DNSBL_REASON.to_string(),source:source_tag.clone(),ttl_seconds:request.ttl_seconds,prefix_len:None}).collect()}else{Vec::new()}; let feed=ThreatFeedImport{feed_id:request.feed_id,source:request.source,ttl_seconds:request.ttl_seconds,threats,dnsbl}; if let Err(message)=validate_threat_feed_import(&feed){return error(StatusCode::BAD_GATEWAY,format!("invalid fetched feed data: {message}"));} let actor=audit_actor(&state,&headers); match apply_threat_feed_import(&state,actor,"import_phishing_database_feed",feed).await{Ok(result)=>(StatusCode::CREATED,Json(result)).into_response(),Err(message)=>error(StatusCode::INTERNAL_SERVER_ERROR,message)}
}
fn validate_phishing_database_import_request(request:&PhishingDatabaseImportRequest)->Result<(),&'static str>{if request.feed_id.trim().is_empty(){return Err("feed_id is required");}if request.source.trim().is_empty(){return Err("source is required");}if request.ttl_seconds==0{return Err("ttl_seconds must be greater than zero");}if !request.import_domains&&!request.import_ips{return Err("at least one of import_domains or import_ips must be true");}if request.import_domains{if request.domain_limit==0{return Err("domain_limit must be greater than zero when import_domains is enabled");}validate_http_url(&request.domain_url,request.allow_non_default_hosts)?;}if request.import_ips{if request.ip_limit==0{return Err("ip_limit must be greater than zero when import_ips is enabled");}validate_http_url(&request.ip_url,request.allow_non_default_hosts)?;}Ok(())}
fn validate_kev_import_request(request:&KevImportRequest)->Result<(),&'static str>{if request.feed_id.trim().is_empty(){return Err("feed_id is required");}if request.source.trim().is_empty(){return Err("source is required");}if request.ttl_seconds==0{return Err("ttl_seconds must be greater than zero");}Ok(())}
async fn import_kev_feed(State(state):State<AppState>,headers:HeaderMap,Json(request):Json<KevImportRequest>)->Response{if !has_write_admin_credential(&state){return error(StatusCode::SERVICE_UNAVAILABLE,"KEV import requires a configured write-capable admin credential");}if !admin_authorized(&state,&headers){return error(StatusCode::UNAUTHORIZED,"missing or invalid X-Admin-Token");}if let Err(message)=validate_kev_import_request(&request){return error(StatusCode::BAD_REQUEST,message);}let body_text=match fetch_kev_catalog(&state).await{Ok(text)=>text,Err(message)=>return error(StatusCode::BAD_GATEWAY,message)};let material=match kev_import::parse_kev_document(&body_text,request.source.trim(),request.ttl_seconds){Ok(material)=>material,Err(message)=>return error(StatusCode::BAD_GATEWAY,format!("invalid fetched KEV catalog: {message}"))};let actor=audit_actor(&state,&headers);let feed=ThreatFeedImport{feed_id:request.feed_id.trim().to_string(),source:request.source.trim().to_string(),ttl_seconds:request.ttl_seconds,threats:material.threats,dnsbl:material.dnsbl};if let Err(message)=validate_threat_feed_import(&feed){return error(StatusCode::BAD_GATEWAY,format!("invalid fetched feed data: {message}"));}let skipped_entries=material.skipped_entries;match apply_threat_feed_import(&state,actor,"import_kev_feed",feed).await{Ok(result)=>(StatusCode::CREATED,Json(KevImportResult{feed_id:result.feed_id,upserted_threats:result.upserted_threats,upserted_dnsbl:result.upserted_dnsbl,skipped_entries,last_updated_unix:result.last_updated_unix})).into_response(),Err(message)=>error(StatusCode::INTERNAL_SERVER_ERROR,message)}}
fn validate_http_url(value:&str,allow_non_default_hosts:bool)->Result<(),&'static str>{let parsed=reqwest::Url::parse(value).map_err(|_|"feed URL must be an absolute URL")?;let host=parsed.host_str().ok_or("feed URL host is required")?;match parsed.scheme(){"https"=>{},"http" if is_loopback_host(host)=>{},"http"=>return Err("feed URL scheme must be https unless host is loopback"),_=>return Err("feed URL scheme must be http or https"),}if !allow_non_default_hosts&&!PHISHING_DATABASE_ALLOWED_HOSTS.iter().any(|allowed|host.eq_ignore_ascii_case(allowed)){return Err("feed URL host is not allowed");}Ok(())}
fn validate_kev_catalog_url(url:&str)->Result<(),String>{validate_http_url(url,true).map_err(|message|format!("invalid KEV catalog URL {url}: {message}"))?;let parsed=reqwest::Url::parse(url).map_err(|_|format!("invalid KEV catalog URL {url}"))?;let host=parsed.host_str().ok_or_else(||format!("invalid KEV catalog URL {url}: host is required"))?;if !KEV_ALLOWED_HOSTS.iter().any(|allowed|host.eq_ignore_ascii_case(allowed))&&!is_loopback_host(host){return Err(format!("KEV catalog URL {url} host is not on the CISA KEV allowlist"));}Ok(())}
async fn fetch_kev_catalog(state:&AppState)->Result<String,String>{use futures_util::StreamExt;let url=state.kev_catalog_url();validate_kev_catalog_url(url)?;let response=state.feed_http.get(url).timeout(std::time::Duration::from_secs(PHISHING_DATABASE_FETCH_TIMEOUT_SECS)).send().await.map_err(|error|format!("failed to fetch KEV catalog {url}: {error}"))?;let status=response.status();if !status.is_success(){return Err(format!("KEV catalog {url} returned HTTP {status}"));}if let Some(len)=response.content_length()&&len as usize>PHISHING_DATABASE_MAX_BODY_BYTES{return Err(format!("KEV catalog {url} body too large: {len} bytes (limit: {PHISHING_DATABASE_MAX_BODY_BYTES})"));}let mut bytes=Vec::new();let mut stream=response.bytes_stream();while let Some(chunk)=stream.next().await{let chunk=chunk.map_err(|error|format!("failed to read KEV catalog body from {url}: {error}"))?;if bytes.len().saturating_add(chunk.len())>PHISHING_DATABASE_MAX_BODY_BYTES{return Err(format!("KEV catalog {url} body too large: limit {PHISHING_DATABASE_MAX_BODY_BYTES} bytes exceeded while streaming"));}bytes.extend_from_slice(&chunk);}String::from_utf8(bytes).map_err(|error|format!("KEV catalog {url} is not valid UTF-8 text: {error}"))}
fn is_loopback_host(host:&str)->bool{host.eq_ignore_ascii_case("localhost")||host.parse::<IpAddr>().map(|ip|ip.is_loopback()).unwrap_or(false)}

async fn support_bundle(State(state): State<AppState>) -> Json<SupportBundle> { let data=state.inner.read().await;let generated_at_unix=now_unix();Json(SupportBundle{generated_at_unix,health:state.health_status(),kpis:kpi_snapshot_at(&data,generated_at_unix),commercial:data.commercial.clone(),readiness:commercial_readiness_snapshot_at(&data,generated_at_unix),evidence_manifest:buyer_evidence_manifest_at(&data,generated_at_unix),threat_feed_freshness:threat_feed_freshness_snapshot(&data.threat_feeds,generated_at_unix),route_count:data.routes.len(),threat_indicator_count:data.threats.len(),dnsbl_entry_count:data.dnsbl.len(),threat_feed_count:data.threat_feeds.len(),event_count:data.events.len(),audit_log_count:data.audit_logs.len()}) }
async fn events_ndjson(State(state):State<AppState>)->Response{let data=state.inner.read().await;events_ndjson_response(export_events_ndjson(&data.events))}
fn events_ndjson_response(export:Result<String,serde_json::Error>)->Response{match export{Ok(body)=>(StatusCode::OK,[("content-type","application/x-ndjson; charset=utf-8")],body).into_response(),Err(err)=>error(StatusCode::INTERNAL_SERVER_ERROR,format!("failed to serialize security events: {err}"))}}
async fn dnsbl_zone(State(state):State<AppState>)->impl IntoResponse{let data=state.inner.read().await;(StatusCode::OK,[("content-type","text/plain; charset=utf-8")],export_dnsbl_zone(&state.dnsbl_origin,&data.dnsbl))}

async fn gateway(State(state):State<AppState>,method:Method,uri:Uri,headers:HeaderMap,body:Bytes)->Response{let gateway_path=uri.path().strip_prefix("/gateway").filter(|path|!path.is_empty()).unwrap_or("/");let(route,threats,dnsbl)={let data=state.inner.read().await;let Some(route)=select_route(&data.routes,gateway_path)else{return error(StatusCode::NOT_FOUND,"no gateway route matched the request path");};(route.clone(),data.threats.clone(),data.dnsbl.clone())};let client_ip=client_ip_from_headers(&headers);if !state.allow_request(client_ip).await{record_event(&state,client_ip,Some(route.id.clone()),"rate_limited",format!("rate limit exceeded ({} requests per {}s)",state.rate_limit,state.rate_limit_window),0,gateway_path).await;return(StatusCode::TOO_MANY_REQUESTS,Json(serde_json::json!({"action":"rate_limited","route_id":route.id,"limit":state.rate_limit,"window_seconds":state.rate_limit_window}))).into_response();}let body_text=String::from_utf8_lossy(&body);let scored=score_request(gateway_path,uri.query(),&body_text,client_ip,&threats,&dnsbl);if route.mode==EnforcementMode::Block&&scored.score>=route.block_threshold.unwrap_or(BLOCK_SCORE){record_event(&state,client_ip,Some(route.id.clone()),"blocked",scored.reason.clone(),scored.score,gateway_path).await;return(StatusCode::FORBIDDEN,Json(serde_json::json!({"action":"blocked","route_id":route.id,"score":scored.score,"reason":scored.reason}))).into_response();}record_event(&state,client_ip,Some(route.id.clone()),"monitored",scored.reason.clone(),scored.score,gateway_path).await;if route.upstream.starts_with("mock://"){return(StatusCode::OK,Json(serde_json::json!({"action":"monitored","route_id":route.id,"method":method.as_str(),"path":gateway_path,"score":scored.score,"reason":scored.reason,"upstream":route.upstream}))).into_response();}match proxy_request(&state,&route,&method,gateway_path,uri.query(),body).await{Ok(response)=>response,Err(message)=>error(StatusCode::BAD_GATEWAY,message)}}
fn client_ip_from_headers(headers:&HeaderMap)->Option<IpAddr>{headers.get("x-forwarded-for").and_then(|value|value.to_str().ok()).and_then(|value|value.split(',').next()).map(str::trim).or_else(||headers.get("x-real-ip").and_then(|value|value.to_str().ok())).and_then(|value|value.parse().ok())}
async fn proxy_request(state:&AppState,route:&RouteConfig,method:&Method,path:&str,query:Option<&str>,body:Bytes)->Result<Response,String>{let target=upstream_target(route,path,query)?;let method=reqwest::Method::from_bytes(method.as_str().as_bytes()).expect("axum HTTP methods are valid reqwest HTTP methods");let response=state.http.request(method,target).body(body).send().await.map_err(|error|format!("upstream request failed: {error}"))?;let status=StatusCode::from_u16(response.status().as_u16()).expect("reqwest upstream status codes are valid axum status codes");let bytes=response.bytes().await.map_err(|error|format!("upstream body read failed: {error}"))?;Ok((status,bytes).into_response())}
pub fn upstream_target(route:&RouteConfig,path:&str,query:Option<&str>)->Result<String,String>{if !route.upstream.starts_with("http://")&&!route.upstream.starts_with("https://"){return Err("upstream must use http:// or https:// for proxy mode".to_string());}let suffix=path.strip_prefix(&route.path_prefix).unwrap_or(path);let suffix=if suffix.starts_with('/'){suffix.to_string()}else if suffix.is_empty(){"/".to_string()}else{format!("/{suffix}")};let mut target=format!("{}{}",route.upstream.trim_end_matches('/'),suffix);if let Some(query)=query.filter(|value|!value.is_empty()){target.push('?');target.push_str(query);}Ok(target)}
async fn record_event(state:&AppState,client_ip:Option<IpAddr>,route_id:Option<String>,action:&str,reason:String,score:u16,path:&str){let action=action.to_string();let path=path.to_string();let event_limit=state.event_limit;if let Err(error)=state.mutate_and_persist(|data|{let id=data.next_event_id;data.next_event_id+=1;let event=SecurityEvent{id,timestamp_unix:now_unix(),client_ip,route_id,action,reason,score,path};println!("{}",security_event_log_line(&event));data.events.push(event);enforce_event_limit(data,event_limit);}).await{eprintln!("failed to persist security event: {error}");}}
fn security_event_log_line(event:&SecurityEvent)->String{serde_json::to_string(event).expect("SecurityEvent is JSON-serializable")}
#[derive(Debug,Clone,PartialEq,Eq)] pub struct AdminPrincipal{pub actor:String,pub can_write:bool}
fn admin_authenticated(state:&AppState,headers:&HeaderMap)->bool{let presented=headers.get("x-admin-token").and_then(|value|value.to_str().ok());if !state.admin_tokens.is_empty(){return presented.is_some_and(|token|state.admin_tokens.contains_key(token));}let Some(expected)=state.admin_token.as_deref()else{return true;};presented.is_some_and(|actual|actual==expected)}
fn admin_authorized(state:&AppState,headers:&HeaderMap)->bool{let presented=headers.get("x-admin-token").and_then(|value|value.to_str().ok());if !state.admin_tokens.is_empty(){return presented.is_some_and(|token|state.admin_tokens.get(token).is_some_and(|principal|principal.can_write));}let Some(expected)=state.admin_token.as_deref()else{return true;};presented.is_some_and(|actual|actual==expected)}
fn has_write_admin_credential(state:&AppState)->bool{if !state.admin_tokens.is_empty(){return state.admin_tokens.values().any(|principal|principal.can_write);}state.admin_token.as_deref().is_some_and(|token|!token.is_empty())}
fn audit_actor(state:&AppState,headers:&HeaderMap)->String{if let Some(actor)=state.actor_for_token(headers){return actor;}headers.get("x-admin-actor").and_then(|value|value.to_str().ok()).map(str::trim).filter(|value|!value.is_empty()).unwrap_or("admin-token").to_string()}
pub fn parse_admin_tokens(raw:&str)->HashMap<String,AdminPrincipal>{raw.split(',').filter_map(|item|{let item=item.trim();if item.is_empty(){return None;}let mut parts=item.splitn(3,':').map(str::trim);let token=parts.next().unwrap_or("");if token.is_empty(){return None;}let actor_raw=parts.next().unwrap_or("");let role_raw=parts.next().unwrap_or("");let actor=if actor_raw.is_empty(){"admin".to_string()}else{actor_raw.to_string()};if actor.is_empty(){return None;}let can_write=match role_raw.to_ascii_lowercase().as_str(){""|"admin"|"write"|"writer"|"operator"=>true,"readonly"|"read"|"reader"|"ro"=>false,_=>true,};Some((token.to_string(),AdminPrincipal{actor,can_write}))}).collect()}
fn record_successful_audit_log(data:&mut AppData,actor:String,action:&str,resource:&str,resource_id:String)->AuditLogEntry{record_audit_log(data,NewAuditLogEntry{timestamp_unix:now_unix(),actor,action:action.to_string(),resource:resource.to_string(),resource_id,outcome:"success".to_string()})}
fn threat_resource_id(indicator:&ThreatIndicator)->String{format!("{}:{}:{}",indicator.indicator_type,indicator.value,indicator.source)}
fn mark_operator_threat_key(data:&mut AppData,indicator:&ThreatIndicator){let key=threat_indicator_key(indicator);if !data.operator_threat_keys.contains(&key){data.operator_threat_keys.push(key);}}
async fn apply_threat_feed_import(state:&AppState,actor:String,action:&'static str,feed:ThreatFeedImport)->Result<ThreatFeedImportResult,String>{let imported_at=now_unix();state.mutate_and_persist(|data|{let operator_owned:HashSet<_>=data.operator_threat_keys.iter().cloned().collect();let threat_keys:Vec<_>=feed.threats.iter().map(threat_indicator_key).collect();let previous_keys:HashSet<_>=replace_threat_feed_ownership(&mut data.threat_feed_ownership,feed.feed_id.clone(),threat_keys).into_iter().collect();if !previous_keys.is_empty(){let still_owned:HashSet<_>=data.threat_feed_ownership.iter().filter(|ownership|ownership.feed_id!=feed.feed_id).flat_map(|ownership|ownership.threat_keys.iter().cloned()).collect();data.threats.retain(|threat|{let key=threat_indicator_key(threat);!previous_keys.contains(&key)||still_owned.contains(&key)||operator_owned.contains(&key)});}let mut upserted_threats=0usize;for threat in feed.threats.iter().cloned(){if operator_owned.contains(&threat_indicator_key(&threat)){continue;}upsert_threat(&mut data.threats,threat);upserted_threats+=1;}for entry in feed.dnsbl.iter().cloned(){upsert_dnsbl(&mut data.dnsbl,entry);}upsert_threat_feed(&mut data.threat_feeds,ThreatFeedStatus{feed_id:feed.feed_id.clone(),source:feed.source.clone(),last_updated_unix:imported_at,threat_count:feed.threats.len(),dnsbl_count:feed.dnsbl.len(),ttl_seconds:feed.ttl_seconds});let result=ThreatFeedImportResult{feed_id:feed.feed_id.clone(),upserted_threats,upserted_dnsbl:feed.dnsbl.len(),last_updated_unix:imported_at};record_successful_audit_log(data,actor,action,"threat_feed",result.feed_id.clone());result}).await}
async fn fetch_text_feed(state:&AppState,url:&str)->Result<String,String>{use futures_util::StreamExt;validate_http_url(url,true).map_err(|message|format!("invalid feed URL {url}: {message}"))?;let response=state.feed_http.get(url).timeout(std::time::Duration::from_secs(PHISHING_DATABASE_FETCH_TIMEOUT_SECS)).send().await.map_err(|error|format!("failed to fetch feed {url}: {error}"))?;let status=response.status();if !status.is_success(){return Err(format!("feed {url} returned HTTP {status}"));}if let Some(len)=response.content_length()&&len as usize>PHISHING_DATABASE_MAX_BODY_BYTES{return Err(format!("feed {url} body too large: {len} bytes (limit: {PHISHING_DATABASE_MAX_BODY_BYTES})"));}let mut bytes=Vec::new();let mut stream=response.bytes_stream();while let Some(chunk)=stream.next().await{let chunk=chunk.map_err(|error|format!("failed to read feed body from {url}: {error}"))?;if bytes.len().saturating_add(chunk.len())>PHISHING_DATABASE_MAX_BODY_BYTES{return Err(format!("feed {url} body too large: limit {PHISHING_DATABASE_MAX_BODY_BYTES} bytes exceeded while streaming"));}bytes.extend_from_slice(&chunk);}String::from_utf8(bytes).map_err(|error|format!("feed {url} is not valid UTF-8 text: {error}"))}
fn parse_phishing_domains(feed:&str,limit:usize)->Vec<String>{let mut values=Vec::new();let mut unique=HashSet::new();for line in feed.lines(){let Some(domain)=normalize_phishing_domain(line)else{continue;};if unique.insert(domain.clone()){values.push(domain);if values.len()>=limit{break;}}}values}
fn normalize_phishing_domain(value:&str)->Option<String>{let trimmed=value.trim();if trimmed.is_empty()||trimmed.starts_with('#'){return None;}let without_scheme=trimmed.strip_prefix("https://").or_else(||trimmed.strip_prefix("http://")).unwrap_or(trimmed);let host_port=without_scheme.split('/').next().unwrap_or("");let host=host_port.split(':').next().unwrap_or("").trim_end_matches('.');if host.is_empty()||!host.contains('.')||host.starts_with('.')||host.contains(".."){return None;}if host.parse::<IpAddr>().is_ok(){return None;}if !host.bytes().all(|byte|byte.is_ascii_alphanumeric()||byte==b'.'||byte==b'-'){return None;}Some(host.to_ascii_lowercase())}
fn parse_phishing_ips(feed:&str,limit:usize)->Vec<IpAddr>{let mut values=Vec::new();let mut unique=HashSet::new();for line in feed.lines(){let trimmed=line.trim();if trimmed.is_empty()||trimmed.starts_with('#'){continue;}let Ok(address)=trimmed.parse::<IpAddr>()else{continue;};if unique.insert(address){values.push(address);if values.len()>=limit{break;}}}values}
fn error(status:StatusCode,message:impl Into<String>)->Response{(status,Json(ErrorBody{error:message.into()})).into_response()}
fn now_unix()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()}

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
header.app{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:16px 24px;background:var(--brand);color:var(--on-brand)}
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
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:16px;align-items:start}
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
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.section-nav{margin:0 auto 20px;max-width:1600px;padding:0 20px}
.section-nav ul{display:flex;gap:8px;flex-wrap:wrap;list-style:none;padding:0;margin:0}
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
    <label class="sr-only" for="adminToken">Admin token</label>
    <input id="adminToken" class="hdr-input" type="password" placeholder="Admin token (write or readonly)" autocomplete="off" aria-describedby="adminTokenHelp">
    <span id="adminTokenHelp" class="sr-only">Required for management writes and audit log reads.</span>
    <button class="btn-ghost" id="hcToggle" aria-pressed="false">High contrast</button>
    <button class="btn-ghost" id="refreshBtn">Refresh</button>
  </div>
</header>
<nav class="section-nav" aria-label="Console sections">
  <ul>
    <li><a href="#routesCard">Routes</a></li>
    <li><a href="#threatsCard">Threat indicators</a></li>
    <li><a href="#dnsblCard">DNSBL entries</a></li>
    <li><a href="#readinessCard">Commercial readiness</a></li>
    <li><a href="#eventsCard">Recent events</a></li>
    <li><a href="#auditCard">Audit log</a></li>
  </ul>
</nav>
<main id="main" tabindex="-1">
  <div class="kpis" id="kpis" role="status" aria-live="polite" aria-atomic="true"><div class="tile"><div class="label">Loading</div><div class="metric">…</div></div></div>
  <div class="grid">
    <section class="card" id="routesCard" aria-labelledby="routesHeading"><h2 id="routesHeading">Routes</h2><div id="routesBody" class="muted">Loading…</div>
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
    <section class="card" id="threatsCard" aria-labelledby="threatsHeading"><h2 id="threatsHeading">Threat indicators</h2><div id="threatsBody" class="muted">Loading…</div>
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
    <section class="card" id="dnsblCard" aria-labelledby="dnsblHeading"><h2 id="dnsblHeading">DNSBL entries</h2><div id="dnsblBody" class="muted">Loading…</div>
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
    <section class="card" id="readinessCard" aria-labelledby="readinessHeading"><h2 id="readinessHeading">Commercial readiness</h2><div id="readinessBody" class="muted">Loading…</div></section>
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
    <section class="card" id="eventsCard" aria-labelledby="eventsHeading"><h2 id="eventsHeading">Recent events</h2><div id="eventsBody" class="muted">Loading…</div></section>
    <section class="card"><h2>Suricata IDS ingest</h2>
      <p class="muted">POST admin-authenticated Suricata EVE JSON/NDJSON alerts to <code>/api/ids/suricata/eve</code>. Alerts become SOC security events (no hand-rolled IDS rules).</p>
    </section>
    <section class="card"><h2>Coraza / OWASP CRS WAF ingest</h2>
      <p class="muted">POST admin-authenticated Coraza audit JSON/NDJSON to <code>/api/waf/coraza/audit</code>. CRS rule matches become SOC events and block-grade hits also seed DNSBL/<code>client_ip</code> indicators so the gateway enforces subsequent requests (run Coraza outside; do not invent WAF rules here).</p>
    </section>
    <section class="card"><h2>STIX threat intelligence</h2>
      <p class="muted">POST admin-authenticated STIX 2.x indicator or bundle JSON to <code>/api/threat-intel/stix</code> (optional query: <code>feed_id</code>, <code>source</code>, <code>ttl_seconds</code>). Maps ipv4/domain/url patterns into threats/DNSBL for gateway scoring.</p>
    </section>
    <section class="card"><h2>MISP threat intelligence</h2>
      <p class="muted">POST admin-authenticated MISP Event/attribute JSON to <code>/api/threat-intel/misp</code> (optional query: <code>feed_id</code>, <code>source</code>, <code>ttl_seconds</code>). Maps IDS-worthy attributes (ip-src/ip-dst, domain, url, composites, hashes) into threats/DNSBL; attributes with <code>to_ids=false</code> are skipped. Live MISP REST pull is a follow-up.</p>
    </section>
    <section class="card"><h2>TAXII 2.1 collection poll</h2>
      <p class="muted">POST admin-authenticated JSON to <code>/api/threat-intel/taxii/poll</code> with <code>objects_url</code> (or <code>api_root</code>+<code>collection_id</code>), optional Basic/Bearer credentials, and optional <code>added_after</code>. Fetches TAXII objects, normalizes to STIX, and upserts threats/DNSBL. Credentials are never written to audit logs.</p>
    </section>
    <section class="card"><h2>OpenCTI threat intelligence</h2>
      <p class="muted">POST admin-authenticated OpenCTI GraphQL/list export JSON to <code>/api/threat-intel/opencti</code> (optional query: <code>feed_id</code>, <code>source</code>, <code>ttl_seconds</code>). Maps IPv4/IPv6, Domain-Name, Url, file hashes, and STIX indicators into threats/DNSBL. Live OpenCTI GraphQL pull is a follow-up.</p>
    </section>
    <section class="card"><h2>CISA KEV catalog</h2>
      <p class="muted">POST admin-authenticated JSON to <code>/api/threat-intel/cisa-kev</code> with optional <code>feed_id</code>, <code>source</code>, and <code>ttl_seconds</code>. Fetches the deployment-configured CISA Known Exploited Vulnerabilities catalog URL (server-side config only, not part of this request) and upserts a <code>cve</code> threat indicator per entry (severity escalated to critical when CISA has tied the CVE to a known ransomware campaign).</p>
    </section>
    <section class="card" id="socLlmCard" hidden><h2>AI SOC analysis (LLM)</h2>
      <p class="muted">Triage a recorded security event with the configured LLM (contextual-orchestrator).</p>
      <div class="row">
        <input id="socEventId" class="hdr-input" type="number" min="1" placeholder="Event id" aria-label="Security event id to analyze">
        <button type="button" id="socAnalyzeBtn" class="btn-secondary">Analyze event</button>
      </div>
      <pre class="raw" id="socAnalysis" style="margin-top:8px;white-space:pre-wrap"></pre>
    </section>
    <section class="card" id="auditCard" aria-labelledby="auditHeading"><h2 id="auditHeading">Audit log</h2><div id="auditBody" class="muted">Loading…</div></section>
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
  return '<table><caption>'+esc(capt)+'</caption><thead><tr>'+cols.map(c=>'<th scope="col">'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
}
function toast(msg,ok){const d=document.createElement('div');d.className='toast '+(ok?'ok':'bad');d.textContent=msg;$('toast').appendChild(d);setTimeout(()=>d.remove(),4500);}
async function guard(id,fn){try{await fn();}catch(e){$(id).innerHTML='<p class="err">Error: '+esc(e.message)+'</p>';}}
async function loadKpis(){const k=await getJSON('/api/kpis');const t=[['Routes',k.route_count],['Threat indicators',k.threat_indicator_count],['DNSBL entries',k.dnsbl_entry_count],['Blocked events',k.blocked_event_count],['Monitor events',k.monitor_event_count],['Gateway mode',cap(k.gateway_mode)]];$('kpis').innerHTML=t.map(([l,v])=>'<div class="tile"><div class="label">'+esc(l)+'</div><div class="metric">'+esc(v)+'</div></div>').join('');}
async function loadRoutes(){const d=await getJSON('/api/routes');$('routesBody').innerHTML=table('Configured routes',['Path prefix','Upstream','Mode','State'],d.map(r=>[esc(r.path_prefix),esc(r.upstream),modeBadge(r.mode),stateBadge(r.enabled)]));}
async function loadThreats(){const d=await getJSON('/api/threats');$('threatsBody').innerHTML=table('Threat indicators',['Value','Type','Severity','Source','TTL'],d.map(t=>[mono(t.value),esc(t.indicator_type),sevBadge(t.severity),esc(t.source),esc(t.ttl_seconds)+'s']));}
async function loadDnsbl(){const d=await getJSON('/api/dnsbl');$('dnsblBody').innerHTML=table('DNSBL entries',['Address','Code','Reason','Source','TTL'],d.map(x=>[esc(x.address),mono(x.code),esc(x.reason),esc(x.source),esc(x.ttl_seconds)+'s']));}
async function loadLicense(){const c=await getJSON('/api/commercial/license');$('licenseBody').innerHTML='<dl class="def">'+[['tenant_id',esc(c.tenant_id)],['deployment_id',esc(c.deployment_id)],['edition',badge(cap(c.edition),'b-brand')],['license_status',statusBadge(c.license_status)],['licensee',esc(c.licensee??'—')],['support_contact',esc(c.support_contact)],['ACV (KRW)',c.annual_contract_value_krw!=null?esc(c.annual_contract_value_krw):'—']].map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+v+'</dd>').join('')+'</dl>';}
async function loadReadiness(){const r=await getJSON('/api/commercial/readiness');const head='<div class="row" style="margin-bottom:10px">'+badge(r.ready_for_enterprise_sale?'Ready':'Not ready',r.ready_for_enterprise_sale?'b-pass':'b-warn')+'<span class="muted">'+esc(r.readiness_level)+'</span></div>';const checks=(r.checks||[]).map(c=>'<div class="row" style="margin:6px 0">'+statusBadge(c.status)+'<span class="muted">'+esc(c.id)+' — '+esc(c.evidence)+'</span></div>').join('');$('readinessBody').innerHTML=head+checks;}
async function loadFeeds(){const f=await getJSON('/api/threat-feeds/freshness');$('feedsBody').innerHTML=table('Threat feeds',['Feed','Source','Threats','DNSBL','Freshness'],f.map(x=>[esc(x.feed_id),esc(x.source),esc(x.threat_count),esc(x.dnsbl_count),x.stale?badge('Stale','b-fail'):badge('Fresh','b-pass')]));}
async function loadEvents(){const e=await getJSON('/api/events');$('eventsBody').innerHTML=table('Recent events',['ID','Client IP','Action','Score','Path'],e.slice(0,25).map(x=>[esc(x.id),esc(x.client_ip??'—'),esc(x.action),esc(x.score),esc(x.path)]));}
async function loadAudit(){const t=($('adminToken').value||'').trim();const h=t?{'x-admin-token':t}:{};const r=await fetch('/api/audit-logs',{headers:h});if(!r.ok){let m=r.statusText;try{m=(await r.json()).error||m;}catch(e){}throw new Error(m);}const a=await r.json();$('auditBody').innerHTML=table('Audit log',['Actor','Action','Resource','Resource ID','Outcome'],a.slice(0,25).map(x=>[esc(x.actor),esc(x.action),esc(x.resource),esc(x.resource_id),esc(x.outcome)]));}
async function loadRaw(id,url,json){try{const t=json?JSON.stringify(await getJSON(url),null,2):await getText(url);$(id).textContent=t&&t.trim()?t:'(empty)';}catch(e){$(id).textContent='Error: '+e.message;}}
async function refresh(){await Promise.allSettled([guard('kpis',loadKpis),guard('routesBody',loadRoutes),guard('threatsBody',loadThreats),guard('dnsblBody',loadDnsbl),guard('licenseBody',loadLicense),guard('readinessBody',loadReadiness),guard('feedsBody',loadFeeds),guard('eventsBody',loadEvents),guard('auditBody',loadAudit),loadRaw('manifest','/api/commercial/evidence-manifest',true),loadRaw('export','/api/events.ndjson',false),loadRaw('zone','/dnsbl/zone',false)]);}
function wireCreate(formId,buildBody,onOk){const f=$(formId);if(!f)return;f.addEventListener('submit',async ev=>{ev.preventDefault();let body;try{body=buildBody(new FormData(f));}catch(e){toast(e.message,false);return;}const token=($('adminToken').value||'').trim();const h={'content-type':'application/json'};if(token)h['x-admin-token']=token;try{const r=await fetch(f.dataset.url,{method:'POST',headers:h,body:JSON.stringify(body)});if(!r.ok){let m=r.statusText;try{m=(await r.json()).error||m;}catch(e){}throw new Error(m);}toast(f.dataset.ok+' saved',true);f.reset();onOk();}catch(e){toast('Save failed: '+e.message,false);}});}
const num=v=>{const n=parseInt(v,10);return Number.isFinite(n)?n:0;};
wireCreate('routeForm',fd=>{const pp=(fd.get('path_prefix')||'').trim();return {id:pp.replace(/^\//,'').replace(/[^a-zA-Z0-9_-]/g,'-')||'route',path_prefix:pp,upstream:(fd.get('upstream')||'').trim(),mode:fd.get('mode'),enabled:fd.get('enabled')==='on'};},()=>{guard('routesBody',loadRoutes);guard('kpis',loadKpis);});
wireCreate('threatForm',fd=>({value:(fd.get('value')||'').trim(),indicator_type:(fd.get('indicator_type')||'').trim(),severity:fd.get('severity'),source:(fd.get('source')||'').trim(),ttl_seconds:num(fd.get('ttl_seconds'))}),()=>{guard('threatsBody',loadThreats);guard('kpis',loadKpis);});
wireCreate('dnsblForm',fd=>({address:(fd.get('address')||'').trim(),code:(fd.get('code')||'').trim(),reason:(fd.get('reason')||'').trim(),source:(fd.get('source')||'').trim(),ttl_seconds:num(fd.get('ttl_seconds'))}),()=>{guard('dnsblBody',loadDnsbl);guard('kpis',loadKpis);loadRaw('zone','/dnsbl/zone',false);});
wireCreate('licenseForm',fd=>{const feats=(fd.get('features')||'').split(',').map(s=>s.trim()).filter(Boolean);const b={tenant_id:(fd.get('tenant_id')||'').trim(),deployment_id:(fd.get('deployment_id')||'').trim(),edition:fd.get('edition'),license_status:fd.get('license_status'),support_contact:(fd.get('support_contact')||'').trim(),features:feats};const lic=(fd.get('licensee')||'').trim();if(lic)b.licensee=lic;const lid=(fd.get('license_id')||'').trim();if(lid)b.license_id=lid;return b;},()=>{guard('licenseBody',loadLicense);guard('readinessBody',loadReadiness);});
const root=document.documentElement;if(localStorage.getItem('waf-theme')==='hc')root.dataset.theme='hc';function syncHc(){$('hcToggle').setAttribute('aria-pressed',root.dataset.theme==='hc'?'true':'false');}syncHc();$('hcToggle').addEventListener('click',()=>{const on=root.dataset.theme==='hc';if(on){delete root.dataset.theme;}else{root.dataset.theme='hc';}localStorage.setItem('waf-theme',on?'':'hc');syncHc();});$('refreshBtn').addEventListener('click',refresh);
function cfHeaders(){const t=($('adminToken').value||'').trim();return t?{'x-admin-token':t}:{};}
async function pollClearfolio(id){for(let i=0;i<40;i++){const r=await fetch('/api/clearfolio/jobs/'+encodeURIComponent(id),{headers:cfHeaders()});if(r.ok){const j=await r.json();const s=String(j.status||'').toUpperCase();const doc=j.docId||j.doc_id;if(s==='SUCCEEDED'||doc)return doc||id;if(s==='FAILED'||j.deadLettered)throw new Error('conversion failed');}await new Promise(res=>setTimeout(res,1500));}throw new Error('conversion timed out');}
async function openClearfolioDoc(kind,base){const st=$('viewerStatus'),frame=$('viewerFrame');frame.hidden=true;st.textContent='Submitting conversion…';try{const sr=await fetch('/api/clearfolio/documents/'+encodeURIComponent(kind),{method:'POST',headers:cfHeaders()});if(!sr.ok)throw new Error((await sr.json().catch(()=>({}))).error||sr.statusText);const job=await sr.json();const id=job.jobId||job.job_id;if(!id)throw new Error('no job id returned');st.textContent='Converting… (job '+id+')';const doc=await pollClearfolio(id);frame.src=base.replace(/\/+$/,'')+'/viewer/'+encodeURIComponent(doc);frame.hidden=false;st.textContent='Document ready.';}catch(e){st.innerHTML='<span class="err">Viewer error: '+esc(e.message)+'</span>';}}
async function initClearfolio(){let cfg;try{cfg=await getJSON('/api/clearfolio/config');}catch(e){return;}if(!cfg||!cfg.enabled||!cfg.base_url)return;const card=$('viewerCard');if(!card)return;card.hidden=false;card.querySelectorAll('button[data-doc]').forEach(b=>b.addEventListener('click',()=>openClearfolioDoc(b.dataset.doc,cfg.base_url)));}
async function analyzeSocEvent(){const out=$('socAnalysis');const id=parseInt(($('socEventId').value||'').trim(),10);if(!Number.isFinite(id)||id<1){out.innerHTML='<span class="err">Enter a valid event id.</span>';return;}out.textContent='Analyzing…';try{const r=await fetch('/api/soc/analyze',{method:'POST',headers:{'content-type':'application/json',...cfHeaders()},body:JSON.stringify({event_id:id})});if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||r.statusText);const j=await r.json();out.textContent=j.analysis||'(no analysis)';}catch(e){out.innerHTML='<span class="err">Analysis error: '+esc(e.message)+'</span>';}}
async function initSocLlm(){let cfg;try{cfg=await getJSON('/api/soc/llm-config');}catch(e){return;}if(!cfg||!cfg.enabled)return;const card=$('socLlmCard');if(!card)return;card.hidden=false;$('socAnalyzeBtn').addEventListener('click',analyzeSocEvent);}
refresh();initClearfolio();initSocLlm();
</script>
</body>
</html>"##;

pub fn parse_event_limit(raw: Option<&str>) -> Result<usize, Box<dyn std::error::Error>> {
    let value = match raw { Some(raw) => raw.parse::<usize>().map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("EVENT_LIMIT must be a positive integer, got {raw:?}: {error}")))?, None => AppConfig::DEFAULT_EVENT_LIMIT };
    if value == 0 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "EVENT_LIMIT must be greater than 0").into()); }
    Ok(value)
}
pub fn parse_u32_env(name:&str,raw:Option<&str>,default:u32)->Result<u32,Box<dyn std::error::Error>>{match raw{Some(raw)=>Ok(raw.parse::<u32>().map_err(|error|std::io::Error::new(std::io::ErrorKind::InvalidInput,format!("{name} must be a non-negative integer, got {raw:?}: {error}")))?),None=>Ok(default)}}
pub fn parse_u64_env(name:&str,raw:Option<&str>,default:u64)->Result<u64,Box<dyn std::error::Error>>{match raw{Some(raw)=>Ok(raw.parse::<u64>().map_err(|error|std::io::Error::new(std::io::ErrorKind::InvalidInput,format!("{name} must be a positive integer, got {raw:?}: {error}")))?),None=>Ok(default)}}
pub async fn run_from_env(shutdown:std::pin::Pin<Box<dyn std::future::Future<Output=()>+Send>>)->Result<(),Box<dyn std::error::Error>>{let bind_addr=std::env::var("BIND_ADDR").unwrap_or_else(|_|"127.0.0.1:8080".to_string());let credentials_path=std::env::var("WAF_IDS_CREDENTIALS_PATH").ok().map(PathBuf::from);let credentials=CredentialRegistry::bootstrap_secrets(credentials_path.as_deref(),std::env::var("ADMIN_TOKEN").ok(),std::env::var("ADMIN_TOKENS").ok())?;let config=AppConfig{admin_token:credentials.get_credential(CRED_ADMIN_TOKEN).map(str::to_owned),state_path:std::env::var("WAF_IDS_STATE_PATH").ok().map(PathBuf::from),dnsbl_origin:std::env::var("DNSBL_ORIGIN").unwrap_or_else(|_|AppConfig::DEFAULT_DNSBL_ORIGIN.to_string()),event_limit:parse_event_limit(std::env::var("EVENT_LIMIT").ok().as_deref())?};let rate_limit=parse_u32_env("RATE_LIMIT",std::env::var("RATE_LIMIT").ok().as_deref(),0)?;let rate_limit_window=parse_u64_env("RATE_LIMIT_WINDOW",std::env::var("RATE_LIMIT_WINDOW").ok().as_deref(),60)?;let admin_tokens=parse_admin_tokens(credentials.get_credential(CRED_ADMIN_TOKENS).unwrap_or_default());let max_body_bytes=parse_u64_env("MAX_BODY_BYTES",std::env::var("MAX_BODY_BYTES").ok().as_deref(),1_048_576)? as usize;let listener=tokio::net::TcpListener::bind(&bind_addr).await?;let local_addr=listener.local_addr()?;println!("waf-ids-ai-soc listening on http://{local_addr}");std::io::Write::flush(&mut std::io::stdout())?;let state=AppState::load(config).await.map_err(|message|std::io::Error::new(std::io::ErrorKind::InvalidData,message))?.with_rate_limit(rate_limit,rate_limit_window).with_admin_tokens(admin_tokens).with_credentials_source(credentials.source()).with_max_body_size(max_body_bytes);axum::serve(listener,build_app(state)).with_graceful_shutdown(shutdown).await?;Ok(())}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::{Body,to_bytes},http::{HeaderValue,Request}};
    use serde::de::DeserializeOwned;
    use std::{future::IntoFuture,io::{Read,Write},net::TcpListener as StdTcpListener,thread,time::{SystemTime,UNIX_EPOCH}};
    use tower::ServiceExt;
    static ENV_GUARD:std::sync::LazyLock<tokio::sync::Mutex<()>>=std::sync::LazyLock::new(||tokio::sync::Mutex::new(()));
    fn clear_run_env(){for name in ["BIND_ADDR","ADMIN_TOKEN","ADMIN_TOKENS","WAF_IDS_STATE_PATH","WAF_IDS_CREDENTIALS_PATH","DNSBL_ORIGIN","EVENT_LIMIT","RATE_LIMIT","RATE_LIMIT_WINDOW","MAX_BODY_BYTES"]{unsafe{std::env::remove_var(name)};}}
    #[test] fn parse_event_limit_reads_optional_env(){assert_eq!(parse_event_limit(None).unwrap(),AppConfig::DEFAULT_EVENT_LIMIT);assert_eq!(parse_event_limit(Some("25")).unwrap(),25);assert!(parse_event_limit(Some("0")).is_err());assert!(parse_event_limit(Some("not-a-number")).is_err());}
    #[test] fn parse_u32_env_reads_optional_env(){assert_eq!(parse_u32_env("RATE_LIMIT",None,7).unwrap(),7);assert_eq!(parse_u32_env("RATE_LIMIT",Some("120"),0).unwrap(),120);assert!(parse_u32_env("RATE_LIMIT",Some("-1"),0).is_err());}
    #[test] fn parse_u64_env_reads_optional_env(){assert_eq!(parse_u64_env("RATE_LIMIT_WINDOW",None,60).unwrap(),60);assert_eq!(parse_u64_env("RATE_LIMIT_WINDOW",Some("30"),60).unwrap(),30);assert!(parse_u64_env("RATE_LIMIT_WINDOW",Some("abc"),60).is_err());}
    #[test] fn parses_and_limits_phishing_database_feeds(){let domains=parse_phishing_domains("https://Phish.EXAMPLE/login\n#comment\n\nbad value\na..b.example\n203.0.113.7\nphish.example\nphish.example\n",2);assert_eq!(domains,vec!["phish.example".to_string()]);let ips=parse_phishing_ips("198.51.100.8\n#skip\nbad-ip\n198.51.100.8\n203.0.113.5",2);assert_eq!(ips.len(),2);}
    async fn body_text(response:Response)->String{let bytes=to_bytes(response.into_body(),usize::MAX).await.unwrap();String::from_utf8(bytes.to_vec()).unwrap()}
    #[tokio::test] async fn admin_console_serves_designed_ui(){let app=build_app(AppState::seeded(None));let html=body_text(app_request(&app,empty_request(Method::GET,"/")).await).await;assert!(html.contains("--brand:#14213d"));assert!(html.contains("--canvas:#f7f8fa"));assert!(html.contains("id=\"routesBody\""));assert!(html.contains("id=\"threatsBody\""));assert!(html.contains("data-url=\"/api/routes\""));assert!(html.contains("data-url=\"/api/threats\""));assert!(html.contains("id=\"hcToggle\""));assert!(html.contains("Skip to content"));assert!(html.contains(":focus-visible"));assert!(html.contains("aria-label=\"Console sections\""));assert!(html.contains("id=\"main\" tabindex=\"-1\""));assert!(html.contains("aria-describedby=\"adminTokenHelp\""));assert!(html.contains("role=\"status\" aria-live=\"polite\" aria-atomic=\"true\""));}
    async fn app_request(app:&Router,request:Request<Body>)->Response{app.clone().oneshot(request).await.unwrap()}
    fn empty_request(method:Method,uri:&str)->Request<Body>{Request::builder().method(method).uri(uri).body(Body::empty()).unwrap()}
    fn json_request<T:Serialize>(method:Method,uri:&str,token:Option<&str>,payload:&T)->Request<Body>{let mut builder=Request::builder().method(method).uri(uri).header("content-type","application/json");if let Some(token)=token{builder=builder.header("x-admin-token",token);}builder.body(Body::from(serde_json::to_vec(payload).unwrap())).unwrap()}
    fn authed_empty_request(method:Method,uri:&str,token:&str)->Request<Body>{Request::builder().method(method).uri(uri).header("x-admin-token",token).body(Body::empty()).unwrap()}
    fn json_body_sync<T:DeserializeOwned>(_response:Response)->T{unreachable!()}
    async fn json_body<T:DeserializeOwned>(response:Response)->T{serde_json::from_str(&body_text(response).await).unwrap()}
    fn temp_state_path(name:&str)->PathBuf{let nanos=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();std::env::temp_dir().join(format!("waf-ids-ai-soc-{name}-{}-{nanos}.json",std::process::id()))}
}
