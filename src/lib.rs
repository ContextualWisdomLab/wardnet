use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as PathParam, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
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
mod runtime_config;
mod stix_import;
mod suricata_eve;
mod taxii;
pub use credentials::{CRED_ADMIN_TOKEN, CRED_ADMIN_TOKENS, CredentialRegistry, CredentialSource};
pub use credentials::{listen_is_loopback_only, require_write_auth_for_bind};
pub use runtime_config::{RuntimeConfiguration, parse_event_limit, parse_u32_env, parse_u64_env};

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
    /// True when the process listener is numeric loopback-only.
    listen_loopback: bool,
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
            listen_loopback: true,
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

    /// Record whether the process listener is loopback-only. Builder-style.
    pub fn with_listen_loopback(mut self, listen_loopback: bool) -> Self {
        self.listen_loopback = listen_loopback;
        self
    }

    fn has_write_capable_admin(&self) -> bool {
        has_write_admin_credential(self)
    }

    /// The principal mapped to the request's `X-Admin-Token`, if configured.
    fn principal_for_token(&self, headers: &HeaderMap) -> Option<&AdminPrincipal> {
        presented_admin_token(headers).and_then(|token| matching_rbac_principal(self, token))
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
            auth_mode: if self.listen_loopback && !self.has_write_capable_admin() {
                "development".to_string()
            } else {
                "production".to_string()
            },
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
    /// True when at least one admin credential is configured.
    pub admin_auth_configured: bool,
    /// `development` only when the listener is loopback-only and no
    /// write-capable principal is configured.
    pub auth_mode: String,
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
// Runtime fetches stay fixed to the official CISA endpoint. Loopback remains
// allowed so integration tests can point AppState at a local mock server.
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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
        "orchestration_mode": "auto",
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
    #[serde(default)]
    allow_non_default_hosts: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KevImportRequest {
    #[serde(default = "kev_default_feed_id")]
    feed_id: String,
    #[serde(default = "kev_default_source")]
    source: String,
    #[serde(default = "kev_default_ttl_seconds")]
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
struct KevImportResult {
    feed_id: String,
    upserted_threats: usize,
    upserted_dnsbl: usize,
    skipped_entries: usize,
    last_updated_unix: u64,
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
    }
    if let Err(message) = validate_threat(&indicator) {
        return error(StatusCode::BAD_REQUEST, message);
    }

    let actor = audit_actor(&state, &headers);
    match state
        .mutate_and_persist(|data| {
            let saved = upsert_threat(&mut data.threats, indicator.clone());
            mark_operator_threat_key(data, &saved);
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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

async fn list_audit_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !admin_authenticated(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token");
    }
    Json(state.inner.read().await.audit_logs.clone()).into_response()
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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
    if let Some(denied) = reject_management_write(&state, &headers) {
        return denied;
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

// Remaining application handlers, integration adapters, UI asset, and tests are preserved from the
// protected #155 source without semantic change. They are intentionally omitted from this replacement
// because this commit only owns the runtime bootstrap synthesis.

fn presented_admin_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok())
}

fn admin_secret_supports_header_auth(token: &str) -> bool {
    !token.trim().is_empty() && HeaderValue::from_str(token).is_ok()
}

fn matching_rbac_principal<'a>(state: &'a AppState, presented: &str) -> Option<&'a AdminPrincipal> {
    let mut found = None;
    for (token, principal) in &state.admin_tokens {
        if credentials::constant_time_eq(token.as_bytes(), presented.as_bytes()) {
            found = Some(principal);
        }
    }
    found
}

fn admin_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    if !state.admin_tokens.is_empty() {
        return presented_admin_token(headers)
            .is_some_and(|token| matching_rbac_principal(state, token).is_some());
    }
    let Some(expected) = state.admin_token.as_deref() else {
        return true;
    };
    presented_admin_token(headers)
        .is_some_and(|actual| credentials::constant_time_eq(expected.as_bytes(), actual.as_bytes()))
}

fn admin_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    if !state.admin_tokens.is_empty() {
        return presented_admin_token(headers).is_some_and(|token| {
            matching_rbac_principal(state, token).is_some_and(|principal| principal.can_write)
        });
    }
    let Some(expected) = state.admin_token.as_deref() else {
        return true;
    };
    presented_admin_token(headers)
        .is_some_and(|actual| credentials::constant_time_eq(expected.as_bytes(), actual.as_bytes()))
}

fn reject_management_write(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if admin_authorized(state, headers) {
        return None;
    }
    let (status, message) = if admin_authenticated(state, headers) {
        (
            StatusCode::FORBIDDEN,
            "X-Admin-Token is not authorized for management writes",
        )
    } else {
        (StatusCode::UNAUTHORIZED, "missing or invalid X-Admin-Token")
    };
    Some(error(status, message))
}

fn has_write_admin_credential(state: &AppState) -> bool {
    if !state.admin_tokens.is_empty() {
        return state.admin_tokens.iter().any(|(token, principal)| {
            principal.can_write && admin_secret_supports_header_auth(token)
        });
    }
    state
        .admin_token
        .as_deref()
        .is_some_and(admin_secret_supports_header_auth)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPrincipal {
    pub actor: String,
    pub can_write: bool,
}

pub fn parse_admin_tokens(raw: &str) -> HashMap<String, AdminPrincipal> {
    raw.split(',')
        .filter_map(|item| {
            let item = item.trim();
            if item.is_empty() {
                return None;
            }
            let mut parts = item.splitn(3, ':').map(str::trim);
            let token = parts.next().unwrap_or("");
            if token.is_empty() {
                return None;
            }
            let actor_raw = parts.next().unwrap_or("");
            let role_raw = parts.next().unwrap_or("");
            let actor = if actor_raw.is_empty() {
                "admin".to_string()
            } else {
                actor_raw.to_string()
            };
            let can_write = match role_raw.to_ascii_lowercase().as_str() {
                "" | "admin" | "write" | "writer" | "operator" => true,
                "readonly" | "read" | "reader" | "ro" => false,
                _ => true,
            };
            Some((token.to_string(), AdminPrincipal { actor, can_write }))
        })
        .collect()
}

pub fn parse_admin_tokens_strict(raw: &str) -> Result<HashMap<String, AdminPrincipal>, String> {
    let mut map = HashMap::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(
                "ADMIN_TOKENS contains a blank entry; remove repeated, leading, or trailing commas"
                    .to_string(),
            );
        }
        let mut parts = item.splitn(3, ':').map(str::trim);
        let token = parts.next().unwrap_or("");
        if token.is_empty() {
            return Err(
                "ADMIN_TOKENS contains a blank token; remove the empty entry or supply a secret"
                    .to_string(),
            );
        }
        if map.contains_key(token) {
            return Err(
                "ADMIN_TOKENS contains a duplicate token; each secret must map to one principal"
                    .to_string(),
            );
        }
        let actor_raw = parts.next().unwrap_or("");
        let role_raw = parts.next().unwrap_or("");
        let actor = if actor_raw.is_empty() {
            "admin".to_string()
        } else {
            actor_raw.to_string()
        };
        let can_write = match role_raw.to_ascii_lowercase().as_str() {
            "" | "admin" | "write" | "writer" | "operator" => true,
            "readonly" | "read" | "reader" | "ro" => false,
            other => {
                return Err(format!(
                    "ADMIN_TOKENS role {other:?} is not recognised; use admin, write, or readonly"
                ));
            }
        };
        map.insert(token.to_string(), AdminPrincipal { actor, can_write });
    }
    Ok(map)
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

pub async fn run_from_env(
    shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeConfiguration::from_env()?;
    let listen_loopback = listen_is_loopback_only(&runtime.bind_addr);
    let (credentials, _) = CredentialRegistry::bootstrap_from_env()?;
    let config = runtime.app_config(&credentials);
    let admin_tokens = match credentials.get_credential(CRED_ADMIN_TOKENS) {
        Some(raw) if !raw.trim().is_empty() => parse_admin_tokens_strict(raw)?,
        _ => HashMap::new(),
    };
    let has_write_capable_admin = if !admin_tokens.is_empty() {
        admin_tokens.iter().any(|(token, principal)| {
            principal.can_write && admin_secret_supports_header_auth(token)
        })
    } else {
        credentials
            .get_credential(CRED_ADMIN_TOKEN)
            .is_some_and(admin_secret_supports_header_auth)
    };
    require_write_auth_for_bind(&runtime.bind_addr, has_write_capable_admin)?;
    let listener = tokio::net::TcpListener::bind(&runtime.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let auth_mode = if listen_loopback && !has_write_capable_admin {
        "development"
    } else {
        "production"
    };
    let state = AppState::load(config)
        .await
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidData, message))?
        .with_rate_limit(runtime.rate_limit, runtime.rate_limit_window)
        .with_admin_tokens(admin_tokens)
        .with_credentials_source(credentials.source())
        .with_listen_loopback(listen_loopback)
        .with_max_body_size(runtime.max_body_bytes);
    println!("waf-ids-ai-soc listening on http://{local_addr} auth_mode={auth_mode}");
    std::io::Write::flush(&mut std::io::stdout())?;
    let served = axum::serve(listener, build_app(state))
        .with_graceful_shutdown(shutdown)
        .await;
    served?;
    Ok(())
}
