//! PostgreSQL control plane (issue #80).
//!
//! Production (non-loopback) binds require a control-plane URL. The JSON file
//! adapter remains for loopback/community use and is never selected as the
//! production authority. Tenant isolation is default-deny row-level security
//! with `FORCE ROW LEVEL SECURITY`; each transaction sets `wardnet.tenant_id`.

use std::net::IpAddr;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio_postgres::{Client, GenericClient, NoTls};
use waf_ids_core::{
    AppData, AuditLogEntry, CommercialProfile, DnsblEntry, EnforcementMode, LicenseStatus,
    ProductEdition, RouteConfig, SecurityEvent, Severity, ThreatFeedStatus, ThreatIndicator,
};

/// Default tenant used until Keyverse supplies claims (#82).
pub const DEFAULT_TENANT_ID: &str = "local-lab";

const MIGRATION_VERSION: i32 = 1;

/// Recoverable forward migration. Two-word snake_case names, 3NF, RLS.
pub const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migration (
  migration_version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_account (
  tenant_id TEXT PRIMARY KEY,
  event_sequence BIGINT NOT NULL,
  audit_sequence BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_profile (
  tenant_id TEXT PRIMARY KEY REFERENCES tenant_account (tenant_id),
  deployment_id TEXT NOT NULL,
  edition_name TEXT NOT NULL,
  license_status TEXT NOT NULL,
  license_id TEXT,
  licensee_name TEXT,
  licensed_until_unix BIGINT,
  licensed_node_count INTEGER,
  annual_contract_value_krw BIGINT,
  support_contact TEXT NOT NULL,
  feature_list TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS route_config (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  route_id TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  enforcement_mode TEXT NOT NULL,
  is_enabled BOOLEAN NOT NULL,
  block_threshold INTEGER,
  PRIMARY KEY (tenant_id, route_id)
);

CREATE TABLE IF NOT EXISTS threat_indicator (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  indicator_type TEXT NOT NULL,
  indicator_value TEXT NOT NULL,
  indicator_source TEXT NOT NULL,
  severity_name TEXT NOT NULL,
  ttl_seconds BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, indicator_type, indicator_value, indicator_source)
);

CREATE TABLE IF NOT EXISTS dnsbl_entry (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  host_address TEXT NOT NULL,
  response_code TEXT NOT NULL,
  block_reason TEXT NOT NULL,
  entry_source TEXT NOT NULL,
  ttl_seconds BIGINT NOT NULL,
  prefix_length SMALLINT,
  PRIMARY KEY (tenant_id, host_address)
);

CREATE TABLE IF NOT EXISTS security_event (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  event_id BIGINT NOT NULL,
  timestamp_unix BIGINT NOT NULL,
  client_address TEXT,
  route_id TEXT,
  action_name TEXT NOT NULL,
  event_reason TEXT NOT NULL,
  event_score INTEGER NOT NULL,
  request_path TEXT NOT NULL,
  PRIMARY KEY (tenant_id, event_id)
);

CREATE TABLE IF NOT EXISTS audit_record (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  audit_id BIGINT NOT NULL,
  timestamp_unix BIGINT NOT NULL,
  actor_name TEXT NOT NULL,
  action_name TEXT NOT NULL,
  resource_name TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  action_outcome TEXT NOT NULL,
  PRIMARY KEY (tenant_id, audit_id)
);

CREATE TABLE IF NOT EXISTS threat_feed (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  feed_id TEXT NOT NULL,
  feed_source TEXT NOT NULL,
  last_updated_unix BIGINT NOT NULL,
  threat_count INTEGER NOT NULL,
  dnsbl_count INTEGER NOT NULL,
  ttl_seconds BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, feed_id)
);

CREATE INDEX IF NOT EXISTS security_event_tenant_event
  ON security_event (tenant_id, event_id);

ALTER TABLE tenant_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_account FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_account;
CREATE POLICY tenant_isolation ON tenant_account
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE tenant_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_profile FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_profile;
CREATE POLICY tenant_isolation ON tenant_profile
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE route_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE route_config FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON route_config;
CREATE POLICY tenant_isolation ON route_config
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE threat_indicator ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_indicator FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON threat_indicator;
CREATE POLICY tenant_isolation ON threat_indicator
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE dnsbl_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE dnsbl_entry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON dnsbl_entry;
CREATE POLICY tenant_isolation ON dnsbl_entry
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE security_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_event FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON security_event;
CREATE POLICY tenant_isolation ON security_event
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE audit_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_record FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON audit_record;
CREATE POLICY tenant_isolation ON audit_record
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE threat_feed ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_feed FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON threat_feed;
CREATE POLICY tenant_isolation ON threat_feed
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));
"#;

/// Fail closed when a non-loopback bind has no control-plane URL.
pub fn require_postgres_for_bind(
    bind_addr: &str,
    database_url: Option<&str>,
) -> Result<(), String> {
    if crate::bind_is_loopback(bind_addr) {
        return Ok(());
    }
    match database_url.map(str::trim).filter(|value| !value.is_empty()) {
        Some(_) => Ok(()),
        None => Err(
            "production bind requires CONTROL_PLANE_DATABASE_URL; JSON file state is not production authority"
                .to_string(),
        ),
    }
}

/// Structural URL checks. TLS (`sslmode=require`) is fail-closed until rustls
/// is wired. Password stays in the registry, not logs.
pub fn parse_database_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("CONTROL_PLANE_DATABASE_URL is empty".to_string());
    }
    let lower = raw.to_ascii_lowercase();
    if !(lower.starts_with("postgres://") || lower.starts_with("postgresql://")) {
        return Err("CONTROL_PLANE_DATABASE_URL must be a postgres:// URL".to_string());
    }
    if lower.contains("sslmode=require") || lower.contains("sslmode=verify") {
        return Err(
            "CONTROL_PLANE_DATABASE_URL TLS (sslmode=require/verify) is not wired yet".to_string(),
        );
    }
    Ok(raw.to_string())
}

/// Live PostgreSQL snapshot store for one tenant.
pub struct PostgresPlane {
    client: Mutex<Client>,
    tenant_id: String,
}

impl PostgresPlane {
    pub async fn connect(url: &str) -> Result<Self, String> {
        let url = parse_database_url(url)?;
        let (client, connection) = tokio_postgres::connect(&url, NoTls)
            .await
            .map_err(|error| format!("control plane connect failed: {error}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let plane = Self {
            client: Mutex::new(client),
            tenant_id: DEFAULT_TENANT_ID.to_string(),
        };
        plane.migrate().await?;
        Ok(plane)
    }

    async fn migrate(&self) -> Result<(), String> {
        let client = self.client.lock().await;
        client
            .batch_execute(MIGRATION_SQL)
            .await
            .map_err(|error| format!("control plane migration failed: {error}"))?;
        client
            .execute(
                "INSERT INTO schema_migration (migration_version) VALUES ($1) ON CONFLICT (migration_version) DO NOTHING",
                &[&MIGRATION_VERSION],
            )
            .await
            .map_err(|error| format!("control plane migration version failed: {error}"))?;
        Ok(())
    }

    /// Load the tenant snapshot, or `None` when the tenant has no rows yet.
    pub async fn load(&self) -> Result<Option<AppData>, String> {
        let mut client = self.client.lock().await;
        load_snapshot(&mut client, &self.tenant_id).await
    }

    /// Replace the tenant snapshot in one transaction (mutation + audit).
    pub async fn save(&self, data: &AppData) -> Result<(), String> {
        let mut client = self.client.lock().await;
        save_snapshot(&mut client, &self.tenant_id, data).await
    }
}

async fn load_snapshot(client: &mut Client, tenant_id: &str) -> Result<Option<AppData>, String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane load transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let account = tx
        .query_opt(
            "SELECT event_sequence, audit_sequence FROM tenant_account WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load tenant_account failed: {error}"))?;
    let Some(account) = account else {
        tx.rollback()
            .await
            .map_err(|error| format!("control plane load rollback failed: {error}"))?;
        return Ok(None);
    };

    let commercial = load_commercial(&tx, tenant_id).await?;
    let routes = load_routes(&tx, tenant_id).await?;
    let threats = load_threats(&tx, tenant_id).await?;
    let dnsbl = load_dnsbl(&tx, tenant_id).await?;
    let events = load_events(&tx, tenant_id).await?;
    let audit_logs = load_audit(&tx, tenant_id).await?;
    let threat_feeds = load_feeds(&tx, tenant_id).await?;
    tx.commit()
        .await
        .map_err(|error| format!("control plane load commit failed: {error}"))?;

    Ok(Some(AppData {
        routes,
        threats,
        dnsbl,
        events,
        next_event_id: account.get::<_, i64>(0) as u64,
        audit_logs,
        next_audit_log_id: account.get::<_, i64>(1) as u64,
        commercial,
        threat_feeds,
    }))
}

async fn save_snapshot(client: &mut Client, tenant_id: &str, data: &AppData) -> Result<(), String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;

    tx.execute(
        "INSERT INTO tenant_account (tenant_id, event_sequence, audit_sequence)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id) DO UPDATE SET
           event_sequence = EXCLUDED.event_sequence,
           audit_sequence = EXCLUDED.audit_sequence",
        &[
            &tenant_id,
            &(data.next_event_id as i64),
            &(data.next_audit_log_id as i64),
        ],
    )
    .await
    .map_err(|error| format!("control plane upsert tenant_account failed: {error}"))?;

    for table in [
        "route_config",
        "threat_indicator",
        "dnsbl_entry",
        "security_event",
        "audit_record",
        "threat_feed",
        "tenant_profile",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE tenant_id = $1"),
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane delete {table} failed: {error}"))?;
    }

    let features = serde_json::to_string(&data.commercial.features)
        .expect("feature list is JSON-serializable");
    tx.execute(
        "INSERT INTO tenant_profile (
            tenant_id, deployment_id, edition_name, license_status, license_id,
            licensee_name, licensed_until_unix, licensed_node_count,
            annual_contract_value_krw, support_contact, feature_list
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &tenant_id,
            &data.commercial.deployment_id,
            &edition_sql(&data.commercial.edition),
            &license_sql(&data.commercial.license_status),
            &data.commercial.license_id,
            &data.commercial.licensee,
            &data.commercial.licensed_until_unix.map(|v| v as i64),
            &data.commercial.licensed_node_count.map(|v| v as i32),
            &data.commercial.annual_contract_value_krw.map(|v| v as i64),
            &data.commercial.support_contact,
            &features,
        ],
    )
    .await
    .map_err(|error| format!("control plane insert tenant_profile failed: {error}"))?;

    for route in &data.routes {
        tx.execute(
            "INSERT INTO route_config (
                tenant_id, route_id, path_prefix, upstream_url, enforcement_mode,
                is_enabled, block_threshold
             ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[
                &tenant_id,
                &route.id,
                &route.path_prefix,
                &route.upstream,
                &mode_sql(&route.mode),
                &route.enabled,
                &route.block_threshold.map(i32::from),
            ],
        )
        .await
        .map_err(|error| format!("control plane insert route_config failed: {error}"))?;
    }

    for threat in &data.threats {
        tx.execute(
            "INSERT INTO threat_indicator (
                tenant_id, indicator_type, indicator_value, indicator_source,
                severity_name, ttl_seconds
             ) VALUES ($1,$2,$3,$4,$5,$6)",
            &[
                &tenant_id,
                &threat.indicator_type,
                &threat.value,
                &threat.source,
                &severity_sql(&threat.severity),
                &(threat.ttl_seconds as i64),
            ],
        )
        .await
        .map_err(|error| format!("control plane insert threat_indicator failed: {error}"))?;
    }

    for entry in &data.dnsbl {
        let address = entry.address.to_string();
        tx.execute(
            "INSERT INTO dnsbl_entry (
                tenant_id, host_address, response_code, block_reason, entry_source,
                ttl_seconds, prefix_length
             ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[
                &tenant_id,
                &address,
                &entry.code,
                &entry.reason,
                &entry.source,
                &(entry.ttl_seconds as i64),
                &entry.prefix_len.map(i16::from),
            ],
        )
        .await
        .map_err(|error| format!("control plane insert dnsbl_entry failed: {error}"))?;
    }

    for event in &data.events {
        let client_address = event.client_ip.map(|ip| ip.to_string());
        tx.execute(
            "INSERT INTO security_event (
                tenant_id, event_id, timestamp_unix, client_address, route_id,
                action_name, event_reason, event_score, request_path
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &tenant_id,
                &(event.id as i64),
                &(event.timestamp_unix as i64),
                &client_address,
                &event.route_id,
                &event.action,
                &event.reason,
                &i32::from(event.score),
                &event.path,
            ],
        )
        .await
        .map_err(|error| format!("control plane insert security_event failed: {error}"))?;
    }

    for audit in &data.audit_logs {
        tx.execute(
            "INSERT INTO audit_record (
                tenant_id, audit_id, timestamp_unix, actor_name, action_name,
                resource_name, resource_id, action_outcome
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &tenant_id,
                &(audit.id as i64),
                &(audit.timestamp_unix as i64),
                &audit.actor,
                &audit.action,
                &audit.resource,
                &audit.resource_id,
                &audit.outcome,
            ],
        )
        .await
        .map_err(|error| format!("control plane insert audit_record failed: {error}"))?;
    }

    for feed in &data.threat_feeds {
        tx.execute(
            "INSERT INTO threat_feed (
                tenant_id, feed_id, feed_source, last_updated_unix, threat_count,
                dnsbl_count, ttl_seconds
             ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[
                &tenant_id,
                &feed.feed_id,
                &feed.source,
                &(feed.last_updated_unix as i64),
                &(feed.threat_count as i32),
                &(feed.dnsbl_count as i32),
                &(feed.ttl_seconds as i64),
            ],
        )
        .await
        .map_err(|error| format!("control plane insert threat_feed failed: {error}"))?;
    }

    tx.commit()
        .await
        .map_err(|error| format!("control plane commit failed: {error}"))?;
    Ok(())
}

async fn load_commercial<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<CommercialProfile, String> {
    let row = client
        .query_opt(
            "SELECT deployment_id, edition_name, license_status, license_id, licensee_name,
                    licensed_until_unix, licensed_node_count, annual_contract_value_krw,
                    support_contact, feature_list
             FROM tenant_profile WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load tenant_profile failed: {error}"))?;
    let Some(row) = row else {
        return Ok(CommercialProfile::seeded());
    };
    let features: String = row.get(9);
    Ok(CommercialProfile {
        tenant_id: tenant_id.to_string(),
        deployment_id: row.get(0),
        edition: parse_edition(row.get(1))?,
        license_status: parse_license(row.get(2))?,
        license_id: row.get(3),
        licensee: row.get(4),
        licensed_until_unix: row.get::<_, Option<i64>>(5).map(|v| v as u64),
        licensed_node_count: row.get::<_, Option<i32>>(6).map(|v| v as u32),
        annual_contract_value_krw: row.get::<_, Option<i64>>(7).map(|v| v as u64),
        support_contact: row.get(8),
        features: serde_json::from_str(&features)
            .map_err(|error| format!("control plane feature_list is not JSON: {error}"))?,
    })
}

async fn load_routes<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<Vec<RouteConfig>, String> {
    let rows = client
        .query(
            "SELECT route_id, path_prefix, upstream_url, enforcement_mode, is_enabled, block_threshold
             FROM route_config WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load route_config failed: {error}"))?;
    rows.iter()
        .map(|row| {
            Ok(RouteConfig {
                id: row.get(0),
                path_prefix: row.get(1),
                upstream: row.get(2),
                mode: parse_mode(row.get(3))?,
                enabled: row.get(4),
                block_threshold: row.get::<_, Option<i32>>(5).map(|v| v as u16),
            })
        })
        .collect()
}

async fn load_threats<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<Vec<ThreatIndicator>, String> {
    let rows = client
        .query(
            "SELECT indicator_type, indicator_value, indicator_source, severity_name, ttl_seconds
             FROM threat_indicator WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load threat_indicator failed: {error}"))?;
    rows.iter()
        .map(|row| {
            Ok(ThreatIndicator {
                indicator_type: row.get(0),
                value: row.get(1),
                source: row.get(2),
                severity: parse_severity(row.get(3))?,
                ttl_seconds: row.get::<_, i64>(4) as u64,
            })
        })
        .collect()
}

async fn load_dnsbl<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<Vec<DnsblEntry>, String> {
    let rows = client
        .query(
            "SELECT host_address, response_code, block_reason, entry_source, ttl_seconds, prefix_length
             FROM dnsbl_entry WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load dnsbl_entry failed: {error}"))?;
    rows.iter()
        .map(|row| {
            let address: String = row.get(0);
            Ok(DnsblEntry {
                address: IpAddr::from_str(&address)
                    .map_err(|error| format!("control plane host_address {address}: {error}"))?,
                code: row.get(1),
                reason: row.get(2),
                source: row.get(3),
                ttl_seconds: row.get::<_, i64>(4) as u64,
                prefix_len: row.get::<_, Option<i16>>(5).map(|v| v as u8),
            })
        })
        .collect()
}

async fn load_events<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<Vec<SecurityEvent>, String> {
    let rows = client
        .query(
            "SELECT event_id, timestamp_unix, client_address, route_id, action_name,
                    event_reason, event_score, request_path
             FROM security_event WHERE tenant_id = $1 ORDER BY event_id",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load security_event failed: {error}"))?;
    rows.iter()
        .map(|row| {
            let client_address: Option<String> = row.get(2);
            Ok(SecurityEvent {
                id: row.get::<_, i64>(0) as u64,
                timestamp_unix: row.get::<_, i64>(1) as u64,
                client_ip: client_address
                    .map(|value| {
                        IpAddr::from_str(&value).map_err(|error| {
                            format!("control plane client_address {value}: {error}")
                        })
                    })
                    .transpose()?,
                route_id: row.get(3),
                action: row.get(4),
                reason: row.get(5),
                score: row.get::<_, i32>(6) as u16,
                path: row.get(7),
            })
        })
        .collect()
}

async fn load_audit<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<Vec<AuditLogEntry>, String> {
    let rows = client
        .query(
            "SELECT audit_id, timestamp_unix, actor_name, action_name, resource_name,
                    resource_id, action_outcome
             FROM audit_record WHERE tenant_id = $1 ORDER BY audit_id",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load audit_record failed: {error}"))?;
    Ok(rows
        .iter()
        .map(|row| AuditLogEntry {
            id: row.get::<_, i64>(0) as u64,
            timestamp_unix: row.get::<_, i64>(1) as u64,
            actor: row.get(2),
            action: row.get(3),
            resource: row.get(4),
            resource_id: row.get(5),
            outcome: row.get(6),
        })
        .collect())
}

async fn load_feeds<C: GenericClient>(
    client: &C,
    tenant_id: &str,
) -> Result<Vec<ThreatFeedStatus>, String> {
    let rows = client
        .query(
            "SELECT feed_id, feed_source, last_updated_unix, threat_count, dnsbl_count, ttl_seconds
             FROM threat_feed WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane load threat_feed failed: {error}"))?;
    Ok(rows
        .iter()
        .map(|row| ThreatFeedStatus {
            feed_id: row.get(0),
            source: row.get(1),
            last_updated_unix: row.get::<_, i64>(2) as u64,
            threat_count: row.get::<_, i32>(3) as usize,
            dnsbl_count: row.get::<_, i32>(4) as usize,
            ttl_seconds: row.get::<_, i64>(5) as u64,
        })
        .collect())
}

fn mode_sql(mode: &EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Monitor => "monitor",
        EnforcementMode::Block => "block",
    }
}

fn parse_mode(value: &str) -> Result<EnforcementMode, String> {
    match value {
        "monitor" => Ok(EnforcementMode::Monitor),
        "block" => Ok(EnforcementMode::Block),
        other => Err(format!("unknown enforcement_mode {other}")),
    }
}

fn severity_sql(severity: &Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    match value {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!("unknown severity_name {other}")),
    }
}

fn edition_sql(edition: &ProductEdition) -> &'static str {
    match edition {
        ProductEdition::Community => "community",
        ProductEdition::Evaluation => "evaluation",
        ProductEdition::Enterprise => "enterprise",
    }
}

fn parse_edition(value: &str) -> Result<ProductEdition, String> {
    match value {
        "community" => Ok(ProductEdition::Community),
        "evaluation" => Ok(ProductEdition::Evaluation),
        "enterprise" => Ok(ProductEdition::Enterprise),
        other => Err(format!("unknown edition_name {other}")),
    }
}

fn license_sql(status: &LicenseStatus) -> &'static str {
    match status {
        LicenseStatus::Unlicensed => "unlicensed",
        LicenseStatus::Evaluation => "evaluation",
        LicenseStatus::Active => "active",
        LicenseStatus::Expired => "expired",
    }
}

fn parse_license(value: &str) -> Result<LicenseStatus, String> {
    match value {
        "unlicensed" => Ok(LicenseStatus::Unlicensed),
        "evaluation" => Ok(LicenseStatus::Evaluation),
        "active" => Ok(LicenseStatus::Active),
        "expired" => Ok(LicenseStatus::Expired),
        other => Err(format!("unknown license_status {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_bind_requires_control_plane_url() {
        require_postgres_for_bind("0.0.0.0:8080", None).unwrap_err();
        require_postgres_for_bind("0.0.0.0:8080", Some("postgres://wardnet@127.0.0.1/wardnet"))
            .unwrap();
        require_postgres_for_bind("127.0.0.1:8080", None).unwrap();
        require_postgres_for_bind("[::1]:8080", None).unwrap();
    }

    #[test]
    fn database_url_rejects_non_postgres_and_tls_until_wired() {
        parse_database_url("").unwrap_err();
        parse_database_url("mysql://x").unwrap_err();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet?sslmode=require").unwrap_err();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet").unwrap();
        parse_database_url("postgresql://wardnet@127.0.0.1/wardnet?sslmode=disable").unwrap();
    }

    #[test]
    fn migration_sql_is_3nf_rls_and_two_word_names() {
        for table in [
            "tenant_account",
            "tenant_profile",
            "route_config",
            "threat_indicator",
            "dnsbl_entry",
            "security_event",
            "audit_record",
            "threat_feed",
            "schema_migration",
        ] {
            assert!(MIGRATION_SQL.contains(table), "missing table {table}");
        }
        assert!(MIGRATION_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(MIGRATION_SQL.contains("wardnet.tenant_id"));
        assert!(MIGRATION_SQL.contains("PRIMARY KEY (tenant_id, route_id)"));
        assert!(MIGRATION_SQL.contains("REFERENCES tenant_account"));
        assert!(
            !MIGRATION_SQL.contains("json_blob"),
            "do not dump AppData as one JSON column"
        );
    }

    #[tokio::test]
    async fn postgres_roundtrip_seeded_snapshot_when_database_url_is_set() {
        let Ok(url) = std::env::var("CONTROL_PLANE_TEST_DATABASE_URL") else {
            return;
        };
        if url.trim().is_empty() {
            return;
        }
        let plane = PostgresPlane::connect(&url)
            .await
            .expect("test database must accept the control plane");
        let seeded = AppData::seeded();
        plane.save(&seeded).await.expect("save seeded snapshot");
        let loaded = plane
            .load()
            .await
            .expect("load snapshot")
            .expect("tenant rows must exist after save");
        assert_eq!(loaded.routes, seeded.routes);
        assert_eq!(loaded.threats, seeded.threats);
        assert_eq!(loaded.dnsbl, seeded.dnsbl);
        assert_eq!(loaded.next_event_id, seeded.next_event_id);
        assert_eq!(loaded.commercial.tenant_id, DEFAULT_TENANT_ID);
    }
}
