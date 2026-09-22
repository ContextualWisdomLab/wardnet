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
mod proven_engine;
mod stix_import;
mod suricata_eve;
mod taxii;
pub use credentials::{CRED_ADMIN_TOKEN, CRED_ADMIN_TOKENS, CredentialRegistry, CredentialSource};
pub use credentials::{listen_is_loopback_only, require_write_auth_for_bind};
pub use proven_engine::ProvenEngineConfig;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppData>>,
    persist_lock: Arc<Mutex<()>>,
    http: reqwest::Client,
    feed_http: reqwest::Client,
    waf_http: reqwest::Client,
    proven_engine: ProvenEngineConfig,
    admin_token: Option<String>,
    admin_tokens: HashMap<String, AdminPrincipal>,
    credentials_source: CredentialSource,
    listen_loopback: bool,
    state_path: Option<PathBuf>,
    dnsbl_origin: String,
    event_limit: usize,
    rate_limiter: Arc<Mutex<HashMap<IpAddr, (u64, u32)>>>,
    rate_limit: u32,
    rate_limit_window: u64,
    max_body_bytes: usize,
    clearfolio: Option<ClearfolioConfig>,
    soc_llm: Option<SocLlmConfig>,
    #[cfg(test)]
    kev_catalog_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SocLlmConfig {
    pub base_url: String,
    pub token: String,
    pub model: String,
}

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
            waf_http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to build no-redirect WAF client"),
            proven_engine: ProvenEngineConfig::disabled(),
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

    pub fn with_max_body_size(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_proven_engine(mut self, config: ProvenEngineConfig) -> Self {
        self.proven_engine = config;
        self
    }

    pub fn with_clearfolio(mut self, config: Option<ClearfolioConfig>) -> Self {
        self.clearfolio = config;
        self
    }

    pub fn with_soc_llm(mut self, config: Option<SocLlmConfig>) -> Self {
        self.soc_llm = config;
        self
    }

    pub fn with_rate_limit(mut self, limit: u32, window_secs: u64) -> Self {
        self.rate_limit = limit;
        self.rate_limit_window = window_secs.max(1);
        self
    }

    pub fn with_admin_tokens(mut self, tokens: HashMap<String, AdminPrincipal>) -> Self {
        self.admin_tokens = tokens;
        self
    }

    pub fn with_credentials_source(mut self, source: CredentialSource) -> Self {
        self.credentials_source = source;
        self
    }

    pub fn with_listen_loopback(mut self, listen_loopback: bool) -> Self {
        self.listen_loopback = listen_loopback;
        self
    }

    fn has_write_capable_admin(&self) -> bool {
        has_write_admin_credential(self)
    }

    fn principal_for_token(&self, headers: &HeaderMap) -> Option<&AdminPrincipal> {
        presented_admin_token(headers).and_then(|token| matching_rbac_principal(self, token))
    }

    fn actor_for_token(&self, headers: &HeaderMap) -> Option<String> {
        self.principal_for_token(headers)
            .map(|principal| principal.actor.clone())
    }

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
    pub credentials_source: String,
    pub admin_auth_configured: bool,
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

// ---- Clearfolio and SOC integration helpers omitted here for brevity? NO — this tool requires complete replacement.
