//! PostgreSQL control plane (issue #80).
//!
//! Production (non-loopback) binds require a control-plane URL. The JSON file
//! adapter remains for loopback/community use and is never selected as the
//! production authority. Tenant isolation is default-deny row-level security
//! with `FORCE ROW LEVEL SECURITY`; each transaction sets `wardnet.tenant_id`.

use crate::outbox::{
    self, CLAIM_BATCH, DispatchError, EVENT_SECURITY_RECORDED, EVENT_SNAPSHOT_REPLACED,
    LEASE_SECONDS, LIST_LIMIT, OutboxHealth, OutboxMessage, SCHEMA_VERSION, STATUS_DEAD_LETTER,
    STATUS_LEASED, STATUS_PENDING, STATUS_PROCESSED,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio_postgres::{Client, GenericClient, NoTls, Transaction};
use tokio_postgres_rustls::MakeRustlsConnect;
use waf_ids_core::{
    AppData, AuditLogEntry, CommercialProfile, DnsblEntry, EnforcementMode, LicenseStatus,
    ProductEdition, RouteConfig, SecurityEvent, Severity, ThreatFeedStatus, ThreatIndicator,
};

/// Default tenant used until Keyverse supplies claims (#82).
pub const DEFAULT_TENANT_ID: &str = "local-lab";

const MIGRATION_VERSION: i32 = 5;
/// Oldest logical-backup schema that restores on this binary.
///
/// v3 only provisions `wardnet_runtime`. v4 HASH-partitions `security_event`
/// without changing the logical snapshot shape. A snapshot exported at schema
/// 2 is restorable here so those upgrades cannot void the declared RPO.
const MIN_RESTORABLE_SCHEMA_VERSION: i32 = 2;
/// HASH partitions for `security_event` (by `tenant_id`).
pub const EVENT_PARTITION_MODULUS: i32 = 8;
/// Non-owner, non-superuser role used after migrations so FORCE RLS binds.
pub const RUNTIME_ROLE: &str = "wardnet_runtime";
/// Declared RPO: last successful `GET /api/backup` (on-demand logical snapshot).
pub const BACKUP_RPO: &str = "on-demand-logical-snapshot";
/// Declared RTO budget for an isolated restore drill.
pub const BACKUP_RTO_BUDGET_MS: u64 = 60_000;
/// Session advisory lock for schema/partition DDL (cross-process).
const MIGRATION_LOCK_KEY: i64 = 80_201_680;

/// Recoverable forward migration. Two-word snake_case names, 3NF, RLS.
pub const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migration (
  migration_version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_account (
  tenant_id TEXT PRIMARY KEY,
  event_sequence BIGINT NOT NULL,
  audit_sequence BIGINT NOT NULL,
  snapshot_version BIGINT NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS outbox_message (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  message_id TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  created_unix BIGINT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  message_status TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_unix BIGINT,
  attempt_count INTEGER NOT NULL,
  first_attempt_unix BIGINT,
  last_attempt_unix BIGINT,
  next_available_unix BIGINT NOT NULL,
  terminal_reason TEXT,
  PRIMARY KEY (tenant_id, message_id),
  UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS outbox_receipt (
  tenant_id TEXT NOT NULL REFERENCES tenant_account (tenant_id),
  idempotency_key TEXT NOT NULL,
  message_id TEXT NOT NULL,
  processed_unix BIGINT NOT NULL,
  receipt_evidence TEXT NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS outbox_message_claim
  ON outbox_message (tenant_id, message_status, next_available_unix);

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

ALTER TABLE outbox_message ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_message FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON outbox_message;
CREATE POLICY tenant_isolation ON outbox_message
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

ALTER TABLE outbox_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_receipt FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON outbox_receipt;
CREATE POLICY tenant_isolation ON outbox_receipt
  USING (tenant_id = current_setting('wardnet.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_runtime') THEN
    CREATE ROLE wardnet_runtime
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN
      NOBYPASSRLS NOREPLICATION;
  END IF;
END
$$;
GRANT wardnet_runtime TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO wardnet_runtime;
REVOKE CREATE ON SCHEMA public FROM wardnet_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenant_account, tenant_profile, route_config, threat_indicator,
  dnsbl_entry, security_event, audit_record, threat_feed,
  outbox_message, outbox_receipt TO wardnet_runtime;
GRANT SELECT ON schema_migration TO wardnet_runtime;
ALTER TABLE tenant_account ADD COLUMN IF NOT EXISTS snapshot_version BIGINT NOT NULL DEFAULT 0;
"#;

fn hash_partition_sql_for(parent: &str) -> Result<String, String> {
    if parent.is_empty()
        || !parent.as_bytes()[0].is_ascii_lowercase()
        || !parent
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("hash partition parent must be a lowercase SQL identifier".to_string());
    }
    let modulus = EVENT_PARTITION_MODULUS;
    let unpartitioned = format!("{parent}_unpartitioned");
    Ok(format!(
        r#"
DO $hash$
DECLARE
  kind "char";
  i integer;
BEGIN
  SELECT c.relkind INTO kind
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND c.relname = '{parent}';

  IF kind = 'r' THEN
    ALTER TABLE {parent} RENAME TO {unpartitioned};
    DROP INDEX IF EXISTS {parent}_tenant_event;
    CREATE TABLE {parent} (
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
    ) PARTITION BY HASH (tenant_id);
    i := 0;
    WHILE i < {modulus} LOOP
      EXECUTE format(
        'CREATE TABLE {parent}_p%s PARTITION OF {parent} FOR VALUES WITH (MODULUS {modulus}, REMAINDER %s)',
        i, i
      );
      i := i + 1;
    END LOOP;
    INSERT INTO {parent} (
      tenant_id, event_id, timestamp_unix, client_address, route_id,
      action_name, event_reason, event_score, request_path
    )
    SELECT tenant_id, event_id, timestamp_unix, client_address, route_id,
      action_name, event_reason, event_score, request_path
    FROM {unpartitioned};
    DROP TABLE {unpartitioned};
    ALTER TABLE {parent} ENABLE ROW LEVEL SECURITY;
    ALTER TABLE {parent} FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON {parent};
    CREATE POLICY tenant_isolation ON {parent}
      USING (tenant_id = current_setting('wardnet.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('wardnet.tenant_id', true));
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_runtime') THEN
      GRANT SELECT, INSERT, UPDATE, DELETE ON {parent} TO wardnet_runtime;
      i := 0;
      WHILE i < {modulus} LOOP
        EXECUTE format(
          'GRANT SELECT, INSERT, UPDATE, DELETE ON {parent}_p%s TO wardnet_runtime',
          i
        );
        i := i + 1;
      END LOOP;
    END IF;
  ELSIF kind = 'p' THEN
    i := 0;
    WHILE i < {modulus} LOOP
      IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
          AND c.relname = format('{parent}_p%s', i)
      ) THEN
        EXECUTE format(
          'CREATE TABLE {parent}_p%s PARTITION OF {parent} FOR VALUES WITH (MODULUS {modulus}, REMAINDER %s)',
          i, i
        );
      END IF;
      i := i + 1;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_runtime') THEN
      GRANT SELECT, INSERT, UPDATE, DELETE ON {parent} TO wardnet_runtime;
      i := 0;
      WHILE i < {modulus} LOOP
        IF EXISTS (
          SELECT 1 FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = current_schema()
            AND c.relname = format('{parent}_p%s', i)
        ) THEN
          EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON {parent}_p%s TO wardnet_runtime',
            i
          );
        END IF;
        i := i + 1;
      END LOOP;
    END IF;
  END IF;
END
$hash$;
"#,
    ))
}

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

/// Structural URL checks. Password stays in the registry, not logs.
pub fn parse_database_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("CONTROL_PLANE_DATABASE_URL is empty".to_string());
    }
    let lower = raw.to_ascii_lowercase();
    if !(lower.starts_with("postgres://") || lower.starts_with("postgresql://")) {
        return Err("CONTROL_PLANE_DATABASE_URL must be a postgres:// URL".to_string());
    }
    ssl_mode(raw)?;
    Ok(raw.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslMode {
    Disable,
    Require,
}

/// `disable` (or omitted) uses plaintext. `require` / `verify-ca` /
/// `verify-full` use rustls with Mozilla roots (certificates are always
/// verified — stricter than libpq `require`). `allow` / `prefer` are rejected
/// because they can silently drop to plaintext.
fn ssl_mode(raw: &str) -> Result<SslMode, String> {
    let lower = raw.to_ascii_lowercase();
    let Some((_, query)) = lower.split_once('?') else {
        return Ok(SslMode::Disable);
    };
    for part in query.split('&').flat_map(|chunk| chunk.split('#')) {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if key != "sslmode" {
            continue;
        }
        return match value {
            "disable" => Ok(SslMode::Disable),
            "require" | "verify-ca" | "verify-full" => Ok(SslMode::Require),
            other => Err(format!(
                "unsupported sslmode {other}; use disable or require/verify-full"
            )),
        };
    }
    Ok(SslMode::Disable)
}

/// tokio-postgres 0.7 only parses `disable` / `prefer` / `require`. Map the
/// libpq verification modes we already treat as `Require` so rustls can
/// still verify certificates.
fn rewrite_sslmode_for_tokio(raw: &str) -> String {
    let Some((head, query)) = raw.split_once('?') else {
        return raw.to_string();
    };
    let rewritten = query
        .split('&')
        .map(|part| {
            let Some((key, value)) = part.split_once('=') else {
                return part.to_string();
            };
            if key.eq_ignore_ascii_case("sslmode")
                && (value.eq_ignore_ascii_case("verify-ca")
                    || value.eq_ignore_ascii_case("verify-full"))
            {
                format!("{key}=require")
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{head}?{rewritten}")
}

fn rustls_connector() -> Result<MakeRustlsConnect, String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    Ok(MakeRustlsConnect::with_webpki_roots())
}

async fn assume_runtime_role(client: &Client) -> Result<(), String> {
    let current: String = client
        .query_one("SELECT current_user", &[])
        .await
        .map_err(|error| format!("control plane current_user failed: {error}"))?
        .get(0);
    if current != RUNTIME_ROLE {
        client
            .batch_execute(
                "DO $$
                 BEGIN
                   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_runtime') THEN
                     CREATE ROLE wardnet_runtime
                       NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN
                       NOBYPASSRLS NOREPLICATION;
                   END IF;
                 END
                 $$;
                 GRANT wardnet_runtime TO CURRENT_USER;
                 GRANT USAGE ON SCHEMA public TO wardnet_runtime;
                 REVOKE CREATE ON SCHEMA public FROM wardnet_runtime;
                 GRANT SELECT, INSERT, UPDATE, DELETE ON
                   tenant_account, tenant_profile, route_config, threat_indicator,
                   dnsbl_entry, security_event, audit_record, threat_feed,
                   outbox_message, outbox_receipt TO wardnet_runtime;
                 GRANT SELECT ON schema_migration TO wardnet_runtime;
                 SET ROLE wardnet_runtime;",
            )
            .await
            .map_err(|error| {
                format!(
                    "control plane runtime role {RUNTIME_ROLE} failed (provision NOSUPERUSER NOBYPASSRLS and GRANT it to the login role): {error}"
                )
            })?;
    }
    let row = client
        .query_one("SELECT current_user, current_setting('is_superuser')", &[])
        .await
        .map_err(|error| format!("control plane runtime identity failed: {error}"))?;
    let user: String = row.get(0);
    let superuser: String = row.get(1);
    if user != RUNTIME_ROLE {
        return Err(format!(
            "control plane must run as {RUNTIME_ROLE}, current_user is {user}"
        ));
    }
    if superuser == "on" {
        return Err(format!(
            "control plane role {RUNTIME_ROLE} must not be a superuser"
        ));
    }
    Ok(())
}

async fn apply_schema(client: &Client) -> Result<(), String> {
    let applied = match client
        .query_one(
            "SELECT COALESCE(MAX(migration_version), 0) FROM schema_migration",
            &[],
        )
        .await
    {
        Ok(row) => row.get::<_, i32>(0),
        Err(_) => 0,
    };
    if applied < MIGRATION_VERSION {
        client
            .batch_execute(MIGRATION_SQL)
            .await
            .map_err(|error| format!("control plane migration failed: {error:?}"))?;
        client
            .execute(
                "INSERT INTO schema_migration (migration_version) VALUES ($1) ON CONFLICT (migration_version) DO NOTHING",
                &[&MIGRATION_VERSION],
            )
            .await
            .map_err(|error| format!("control plane migration version failed: {error}"))?;
    }
    let hash_sql = hash_partition_sql_for("security_event")?;
    client
        .batch_execute(&hash_sql)
        .await
        .map_err(|error| format!("control plane event hash partition failed: {error:?}"))?;
    Ok(())
}

async fn event_partition_count(client: &Client) -> Result<i64, String> {
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint
             FROM pg_partition_tree('security_event'::regclass)
             WHERE level = 1",
            &[],
        )
        .await
        .map_err(|error| format!("control plane event partition count failed: {error}"))?;
    Ok(row.get(0))
}

/// Serializes schema application and runtime GRANTs across connections
/// (DROP/CREATE POLICY and ACL updates are not concurrent-safe).
static MIGRATION_GATE: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

/// Live PostgreSQL snapshot store for one tenant.
pub struct PostgresPlane {
    client: Mutex<Client>,
    tenant_id: String,
    /// Processed-outbox retention; mirrors operator `EVENT_LIMIT`.
    event_limit: i64,
}

impl PostgresPlane {
    pub async fn connect(url: &str) -> Result<Self, String> {
        Self::connect_tenant(url, DEFAULT_TENANT_ID).await
    }

    pub async fn connect_tenant(url: &str, tenant_id: &str) -> Result<Self, String> {
        let url = parse_database_url(url)?;
        let mode = ssl_mode(&url)?;
        let connect_url = rewrite_sslmode_for_tokio(&url);
        let (client, connection) = match mode {
            SslMode::Disable => {
                let (client, connection) = tokio_postgres::connect(&connect_url, NoTls)
                    .await
                    .map_err(|error| format!("control plane connect failed: {error}"))?;
                (
                    client,
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
            }
            SslMode::Require => {
                let tls = rustls_connector()?;
                let (client, connection) = tokio_postgres::connect(&connect_url, tls)
                    .await
                    .map_err(|error| format!("control plane TLS connect failed: {error}"))?;
                (
                    client,
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
            }
        };
        std::mem::drop(connection);
        let plane = Self {
            client: Mutex::new(client),
            tenant_id: tenant_id.to_string(),
            event_limit: LIST_LIMIT,
        };
        plane.migrate().await?;
        Ok(plane)
    }

    /// Use the operator-configured `EVENT_LIMIT` for processed-outbox retention.
    pub fn with_event_limit(mut self, event_limit: usize) -> Self {
        self.event_limit = event_limit.max(1) as i64;
        self
    }

    async fn migrate(&self) -> Result<(), String> {
        let _gate = MIGRATION_GATE.lock().await;
        let client = self.client.lock().await;
        client
            .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await
            .map_err(|error| format!("control plane migration lock failed: {error}"))?;
        // HASH convert GRANT and SET ROLE GRANT both mutate pg_class ACL
        // tuples. Hold the lock across both so parallel connects cannot
        // `tuple concurrently updated`.
        let result = async {
            apply_schema(&client).await?;
            assume_runtime_role(&client).await
        }
        .await;
        let _ = client
            .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
            .await;
        result
    }

    #[cfg(test)]
    async fn runtime_identity(&self) -> Result<(String, bool), String> {
        let client = self.client.lock().await;
        let row = client
            .query_one(
                "SELECT current_user, current_setting('is_superuser') = 'on'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok((row.get(0), row.get(1)))
    }

    #[cfg(test)]
    async fn unscoped_route_count(&self) -> Result<i64, String> {
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|error| error.to_string())?;
        let count: i64 = tx
            .query_one("SELECT COUNT(*)::bigint FROM route_config", &[])
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        tx.rollback().await.map_err(|error| error.to_string())?;
        Ok(count)
    }

    pub async fn event_partition_count(&self) -> Result<i64, String> {
        let client = self.client.lock().await;
        event_partition_count(&client).await
    }

    #[cfg(test)]
    async fn security_event_tableoid(&self) -> Result<String, String> {
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|error| error.to_string())?;
        tx.execute(
            "SELECT set_config('wardnet.tenant_id', $1, true)",
            &[&self.tenant_id],
        )
        .await
        .map_err(|error| error.to_string())?;
        let row = tx
            .query_one(
                "SELECT tableoid::regclass::text FROM security_event WHERE tenant_id = $1 LIMIT 1",
                &[&self.tenant_id],
            )
            .await
            .map_err(|error| error.to_string())?;
        tx.commit().await.map_err(|error| error.to_string())?;
        Ok(row.get(0))
    }

    #[cfg(test)]
    async fn runtime_ddl_is_denied(&self) -> Result<bool, String> {
        let client = self.client.lock().await;
        let drop_denied = client
            .batch_execute("DROP TABLE route_config")
            .await
            .is_err();
        let disable_denied = client
            .batch_execute("ALTER TABLE route_config DISABLE ROW LEVEL SECURITY")
            .await
            .is_err();
        Ok(drop_denied && disable_denied)
    }

    /// Load the tenant snapshot, or `None` when the tenant has no rows yet.
    pub async fn load(&self) -> Result<Option<AppData>, String> {
        let mut client = self.client.lock().await;
        load_snapshot(&mut client, &self.tenant_id).await
    }

    /// Replace the tenant snapshot in one transaction (mutation + audit + outbox).
    pub async fn save(&self, data: &AppData) -> Result<(), String> {
        let mut client = self.client.lock().await;
        save_snapshot(&mut client, &self.tenant_id, data, self.event_limit).await
    }

    /// Append one security event and its outbox row without rewriting the snapshot.
    pub async fn append_security_event(
        &self,
        event: &SecurityEvent,
        event_limit: usize,
    ) -> Result<(), String> {
        let mut client = self.client.lock().await;
        append_security_event(&mut client, &self.tenant_id, event, event_limit).await
    }

    #[cfg(test)]
    pub async fn drain_once<F>(
        &self,
        owner: &str,
        now_unix: i64,
        dispatch: F,
    ) -> Result<usize, String>
    where
        F: Fn(&OutboxMessage) -> Result<String, DispatchError>,
    {
        let mut client = self.client.lock().await;
        drain_once(
            &mut client,
            &self.tenant_id,
            owner,
            now_unix,
            self.event_limit,
            dispatch,
        )
        .await
    }

    /// Claim due messages, dispatch without holding the client lock, then ack.
    /// HTTP consumers must not pin the PostgreSQL connection during outbound I/O.
    pub async fn drain_due_async<F, Fut>(
        &self,
        owner: &str,
        now_unix: i64,
        dispatch: F,
    ) -> Result<usize, String>
    where
        F: Fn(OutboxMessage) -> Fut,
        Fut: Future<Output = Result<String, DispatchError>>,
    {
        let claimed = {
            let mut client = self.client.lock().await;
            claim_batch(&mut client, &self.tenant_id, owner, now_unix).await?
        };
        let mut processed = 0;
        for message in claimed {
            let duplicate = {
                let mut client = self.client.lock().await;
                receipt_exists(&mut client, &self.tenant_id, &message.idempotency_key).await?
            };
            if duplicate {
                let mut client = self.client.lock().await;
                ack_processed(
                    &mut client,
                    &self.tenant_id,
                    &message,
                    "duplicate-receipt",
                    now_unix,
                    self.event_limit,
                )
                .await?;
                processed += 1;
                continue;
            }
            match dispatch(message.clone()).await {
                Ok(evidence) => {
                    let mut client = self.client.lock().await;
                    ack_processed(
                        &mut client,
                        &self.tenant_id,
                        &message,
                        &evidence,
                        now_unix,
                        self.event_limit,
                    )
                    .await?;
                    processed += 1;
                }
                Err(error) => {
                    let mut client = self.client.lock().await;
                    fail_claimed(&mut client, &self.tenant_id, &message, now_unix, &error).await?;
                }
            }
        }
        Ok(processed)
    }

    /// Persist an operator-triggered external effect (TAXII / Clearfolio / SOC).
    /// Secrets must not appear in `payload_json`.
    pub async fn enqueue_effect(
        &self,
        event_type: &'static str,
        aggregate_id: &str,
        payload_json: String,
    ) -> Result<String, String> {
        let created_unix = unix_now_i64();
        let hash = outbox::payload_hash(&payload_json);
        let unique = format!("{created_unix}:{hash}");
        let (message_id, idempotency_key) =
            outbox::effect_ids(event_type, &self.tenant_id, &unique);
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|error| format!("control plane effect transaction failed: {error}"))?;
        tx.execute(
            "SELECT set_config('wardnet.tenant_id', $1, true)",
            &[&self.tenant_id],
        )
        .await
        .map_err(|error| format!("control plane tenant context failed: {error}"))?;
        insert_outbox(
            &tx,
            &self.tenant_id,
            &OutboxInsert {
                message_id: message_id.clone(),
                aggregate_id: aggregate_id.to_string(),
                aggregate_version: created_unix,
                event_type,
                created_unix,
                payload_json,
                payload_hash: hash,
                idempotency_key,
            },
        )
        .await?;
        prune_processed_outbox(&tx, &self.tenant_id, self.event_limit).await?;
        tx.commit()
            .await
            .map_err(|error| format!("control plane effect commit failed: {error}"))?;
        Ok(message_id)
    }

    /// Load one outbox row plus receipt evidence when processed.
    pub async fn get_outbox_item(
        &self,
        message_id: &str,
    ) -> Result<Option<(OutboxMessage, Option<String>)>, String> {
        let mut client = self.client.lock().await;
        let tx = client
            .transaction()
            .await
            .map_err(|error| format!("control plane get-outbox transaction failed: {error}"))?;
        tx.execute(
            "SELECT set_config('wardnet.tenant_id', $1, true)",
            &[&self.tenant_id],
        )
        .await
        .map_err(|error| format!("control plane tenant context failed: {error}"))?;
        let row = tx
            .query_opt(
                "SELECT message_id, aggregate_id, aggregate_version, event_type, schema_version,
                        created_unix, payload_json, payload_hash, idempotency_key, message_status,
                        lease_owner, lease_expires_unix, attempt_count, first_attempt_unix,
                        last_attempt_unix, next_available_unix, terminal_reason
                 FROM outbox_message WHERE tenant_id = $1 AND message_id = $2",
                &[&self.tenant_id, &message_id],
            )
            .await
            .map_err(|error| format!("control plane get outbox_message failed: {error}"))?;
        let Some(row) = row else {
            tx.commit()
                .await
                .map_err(|error| format!("control plane get-outbox commit failed: {error}"))?;
            return Ok(None);
        };
        let message = row_to_outbox(&row, &self.tenant_id);
        let evidence = tx
            .query_opt(
                "SELECT receipt_evidence FROM outbox_receipt
                 WHERE tenant_id = $1 AND message_id = $2",
                &[&self.tenant_id, &message_id],
            )
            .await
            .map_err(|error| format!("control plane get outbox_receipt failed: {error}"))?
            .map(|row| row.get::<_, String>(0));
        tx.commit()
            .await
            .map_err(|error| format!("control plane get-outbox commit failed: {error}"))?;
        Ok(Some((message, evidence)))
    }

    pub async fn outbox_health(&self, now_unix: i64) -> Result<OutboxHealth, String> {
        let mut client = self.client.lock().await;
        outbox_health(&mut client, &self.tenant_id, now_unix).await
    }

    pub async fn list_outbox_limited(&self, limit: i64) -> Result<Vec<OutboxMessage>, String> {
        let mut client = self.client.lock().await;
        list_outbox(&mut client, &self.tenant_id, limit.max(1)).await
    }

    pub async fn replay_dead_letter(&self, message_id: &str, now_unix: i64) -> Result<(), String> {
        let mut client = self.client.lock().await;
        replay_dead_letter(&mut client, &self.tenant_id, message_id, now_unix).await
    }

    /// Tenant-scoped logical backup. Client IPs, paths, and actor names stay unmasked.
    pub async fn logical_backup(&self) -> Result<ControlPlaneBackup, String> {
        let mut client = self.client.lock().await;
        export_backup(&mut client, &self.tenant_id).await
    }

    /// Restore a verified artifact into this tenant. Fail closed on schema or hash mismatch.
    pub async fn restore_logical_backup(&self, backup: &ControlPlaneBackup) -> Result<(), String> {
        backup.verify()?;
        let mut client = self.client.lock().await;
        restore_backup(&mut client, &self.tenant_id, backup).await
    }

    /// Restore into an isolated tenant, compare invariants, then drop the drill tenant.
    pub async fn restore_drill(&self) -> Result<BackupDrillReport, String> {
        let started = Instant::now();
        let backup = self.logical_backup().await?;
        let isolated = format!("restore-drill-{}-{}", std::process::id(), unix_now_i64());
        let mut client = self.client.lock().await;
        restore_backup(&mut client, &isolated, &backup).await?;
        let restored = export_backup(&mut client, &isolated).await?;
        drop_tenant(&mut client, &isolated).await?;
        let source_hash = backup.semantic_hash()?;
        let restored_hash = restored.semantic_hash()?;
        let passed = source_hash == restored_hash
            && restored.snapshot.routes == backup.snapshot.routes
            && restored.snapshot.events == backup.snapshot.events
            && restored.snapshot.threats == backup.snapshot.threats
            && restored.snapshot.dnsbl == backup.snapshot.dnsbl
            && restored.outbox.len() == backup.outbox.len()
            && restored.receipts.len() == backup.receipts.len();
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(BackupDrillReport {
            passed,
            duration_ms,
            rpo: BACKUP_RPO.to_string(),
            rto_budget_ms: BACKUP_RTO_BUDGET_MS,
            source_hash,
            restored_hash,
            route_count: backup.snapshot.routes.len(),
            event_count: backup.snapshot.events.len(),
            outbox_count: backup.outbox.len(),
            receipt_count: backup.receipts.len(),
            isolated_tenant_id: isolated,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxReceiptRow {
    pub tenant_id: String,
    pub idempotency_key: String,
    pub message_id: String,
    pub processed_unix: i64,
    pub receipt_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlPlaneBackup {
    pub schema_version: i32,
    pub tenant_id: String,
    pub created_unix: i64,
    pub snapshot: AppData,
    pub outbox: Vec<OutboxMessage>,
    pub receipts: Vec<OutboxReceiptRow>,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupDrillReport {
    pub passed: bool,
    pub duration_ms: u64,
    pub rpo: String,
    pub rto_budget_ms: u64,
    pub source_hash: String,
    pub restored_hash: String,
    pub route_count: usize,
    pub event_count: usize,
    pub outbox_count: usize,
    pub receipt_count: usize,
    pub isolated_tenant_id: String,
}

impl ControlPlaneBackup {
    fn unsigned_json(&self) -> Result<String, String> {
        let mut unsigned = self.clone();
        unsigned.payload_hash.clear();
        serde_json::to_string(&unsigned)
            .map_err(|error| format!("backup serialize failed: {error}"))
    }

    fn seal(mut self) -> Result<Self, String> {
        self.payload_hash.clear();
        let json = self.unsigned_json()?;
        self.payload_hash = outbox::payload_hash(&json);
        Ok(self)
    }

    /// Fail closed when the schema is unsupported or the artifact was tampered with.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema_version < MIN_RESTORABLE_SCHEMA_VERSION
            || self.schema_version > MIGRATION_VERSION
        {
            return Err(format!(
                "backup schema_version {} is unsupported; accepted {MIN_RESTORABLE_SCHEMA_VERSION}..={MIGRATION_VERSION}",
                self.schema_version
            ));
        }
        if self.tenant_id.trim().is_empty() {
            return Err("backup tenant_id must be non-empty".to_string());
        }
        let expected = outbox::payload_hash(&self.unsigned_json()?);
        if expected != self.payload_hash {
            return Err("backup payload_hash does not match contents".to_string());
        }
        Ok(())
    }

    fn semantic_hash(&self) -> Result<String, String> {
        let mut snapshot = self.snapshot.clone();
        snapshot.commercial.tenant_id.clear();
        let mut outbox: Vec<_> = self
            .outbox
            .iter()
            .map(|message| {
                (
                    message.idempotency_key.clone(),
                    message.payload_hash.clone(),
                    message.message_status.clone(),
                    message.payload_json.clone(),
                )
            })
            .collect();
        outbox.sort();
        let mut receipts: Vec<_> = self
            .receipts
            .iter()
            .map(|row| (row.idempotency_key.clone(), row.receipt_evidence.clone()))
            .collect();
        receipts.sort();
        let body = serde_json::json!({
            "snapshot": snapshot,
            "outbox": outbox,
            "receipts": receipts,
        })
        .to_string();
        Ok(outbox::payload_hash(&body))
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
            "SELECT event_sequence, audit_sequence, snapshot_version FROM tenant_account WHERE tenant_id = $1",
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
        snapshot_version: account.get::<_, i64>(2) as u64,
    }))
}

async fn save_snapshot(
    client: &mut Client,
    tenant_id: &str,
    data: &AppData,
    keep: i64,
) -> Result<(), String> {
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

    write_snapshot_rows(&tx, tenant_id, data, true).await?;
    enqueue_snapshot_outbox(&tx, tenant_id, data).await?;
    prune_processed_outbox(&tx, tenant_id, keep).await?;

    tx.commit()
        .await
        .map_err(|error| format!("control plane commit failed: {error}"))?;
    Ok(())
}

async fn write_snapshot_rows(
    tx: &Transaction<'_>,
    tenant_id: &str,
    data: &AppData,
    enforce_snapshot_version: bool,
) -> Result<(), String> {
    let expected = data.snapshot_version as i64;
    let next_version = if enforce_snapshot_version {
        expected.saturating_add(1)
    } else {
        expected
    };
    let written = if enforce_snapshot_version {
        tx.execute(
            "INSERT INTO tenant_account (tenant_id, event_sequence, audit_sequence, snapshot_version)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id) DO UPDATE SET
               event_sequence = EXCLUDED.event_sequence,
               audit_sequence = EXCLUDED.audit_sequence,
               snapshot_version = EXCLUDED.snapshot_version
             WHERE tenant_account.snapshot_version = $5",
            &[
                &tenant_id,
                &(data.next_event_id as i64),
                &(data.next_audit_log_id as i64),
                &next_version,
                &expected,
            ],
        )
        .await
        .map_err(|error| format!("control plane upsert tenant_account failed: {error}"))?
    } else {
        tx.execute(
            "INSERT INTO tenant_account (tenant_id, event_sequence, audit_sequence, snapshot_version)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id) DO UPDATE SET
               event_sequence = EXCLUDED.event_sequence,
               audit_sequence = EXCLUDED.audit_sequence,
               snapshot_version = EXCLUDED.snapshot_version",
            &[
                &tenant_id,
                &(data.next_event_id as i64),
                &(data.next_audit_log_id as i64),
                &next_version,
            ],
        )
        .await
        .map_err(|error| format!("control plane upsert tenant_account failed: {error}"))?
    };
    if enforce_snapshot_version && written == 0 {
        return Err("control plane snapshot conflict".to_string());
    }

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
             FROM route_config WHERE tenant_id = $1 ORDER BY route_id",
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
             FROM threat_indicator WHERE tenant_id = $1
             ORDER BY indicator_type, indicator_value, indicator_source",
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
             FROM dnsbl_entry WHERE tenant_id = $1 ORDER BY host_address",
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
             FROM threat_feed WHERE tenant_id = $1 ORDER BY feed_id",
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

async fn enqueue_snapshot_outbox(
    tx: &Transaction<'_>,
    tenant_id: &str,
    data: &AppData,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "route_count": data.routes.len(),
        "threat_count": data.threats.len(),
        "dnsbl_count": data.dnsbl.len(),
        "event_count": data.events.len(),
        "audit_count": data.audit_logs.len(),
        "event_sequence": data.next_event_id,
        "audit_sequence": data.next_audit_log_id,
    })
    .to_string();
    let hash = outbox::payload_hash(&payload);
    let (message_id, idempotency_key) =
        outbox::snapshot_ids(tenant_id, data.next_event_id, data.next_audit_log_id, &hash);
    insert_outbox(
        tx,
        tenant_id,
        &OutboxInsert {
            message_id,
            aggregate_id: tenant_id.to_string(),
            aggregate_version: data.next_audit_log_id as i64,
            event_type: EVENT_SNAPSHOT_REPLACED,
            created_unix: unix_now_i64(),
            payload_json: payload,
            payload_hash: hash,
            idempotency_key,
        },
    )
    .await
}

async fn append_security_event(
    client: &mut Client,
    tenant_id: &str,
    event: &SecurityEvent,
    event_limit: usize,
) -> Result<(), String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane event transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;

    let next_event_id = event.id.saturating_add(1) as i64;
    tx.execute(
        "INSERT INTO tenant_account (tenant_id, event_sequence, audit_sequence)
         VALUES ($1, $2, 1)
         ON CONFLICT (tenant_id) DO UPDATE SET
           event_sequence = GREATEST(tenant_account.event_sequence, EXCLUDED.event_sequence)",
        &[&tenant_id, &next_event_id],
    )
    .await
    .map_err(|error| format!("control plane upsert tenant_account failed: {error}"))?;

    let client_address = event.client_ip.map(|ip| ip.to_string());
    tx.execute(
        "INSERT INTO security_event (
            tenant_id, event_id, timestamp_unix, client_address, route_id,
            action_name, event_reason, event_score, request_path
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (tenant_id, event_id) DO NOTHING",
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

    let keep_from = next_event_id.saturating_sub(event_limit.max(1) as i64);
    tx.execute(
        "DELETE FROM security_event WHERE tenant_id = $1 AND event_id < $2",
        &[&tenant_id, &keep_from],
    )
    .await
    .map_err(|error| format!("control plane event retention failed: {error}"))?;

    let payload = serde_json::to_string(event).expect("SecurityEvent is JSON-serializable");
    let hash = outbox::payload_hash(&payload);
    let (message_id, idempotency_key) = outbox::security_event_ids(tenant_id, event.id);
    insert_outbox(
        &tx,
        tenant_id,
        &OutboxInsert {
            message_id,
            aggregate_id: event.id.to_string(),
            aggregate_version: event.id as i64,
            event_type: EVENT_SECURITY_RECORDED,
            created_unix: event.timestamp_unix as i64,
            payload_json: payload,
            payload_hash: hash,
            idempotency_key,
        },
    )
    .await?;
    prune_processed_outbox(&tx, tenant_id, event_limit as i64).await?;

    tx.commit()
        .await
        .map_err(|error| format!("control plane event commit failed: {error}"))?;
    Ok(())
}

struct OutboxInsert {
    message_id: String,
    aggregate_id: String,
    aggregate_version: i64,
    event_type: &'static str,
    created_unix: i64,
    payload_json: String,
    payload_hash: String,
    idempotency_key: String,
}

async fn insert_outbox(
    tx: &Transaction<'_>,
    tenant_id: &str,
    row: &OutboxInsert,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO outbox_message (
            tenant_id, message_id, aggregate_id, aggregate_version, event_type,
            schema_version, created_unix, payload_json, payload_hash, idempotency_key,
            message_status, attempt_count, next_available_unix
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,$7)
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        &[
            &tenant_id,
            &row.message_id,
            &row.aggregate_id,
            &row.aggregate_version,
            &row.event_type,
            &SCHEMA_VERSION,
            &row.created_unix,
            &row.payload_json,
            &row.payload_hash,
            &row.idempotency_key,
            &STATUS_PENDING,
        ],
    )
    .await
    .map_err(|error| format!("control plane insert outbox_message failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
async fn drain_once<F>(
    client: &mut Client,
    tenant_id: &str,
    owner: &str,
    now_unix: i64,
    keep: i64,
    dispatch: F,
) -> Result<usize, String>
where
    F: Fn(&OutboxMessage) -> Result<String, DispatchError>,
{
    let claimed = claim_batch(client, tenant_id, owner, now_unix).await?;
    let mut processed = 0;
    for message in claimed {
        if receipt_exists(client, tenant_id, &message.idempotency_key).await? {
            ack_processed(
                client,
                tenant_id,
                &message,
                "duplicate-receipt",
                now_unix,
                keep,
            )
            .await?;
            processed += 1;
            continue;
        }
        match dispatch(&message) {
            Ok(evidence) => {
                ack_processed(client, tenant_id, &message, &evidence, now_unix, keep).await?;
                processed += 1;
            }
            Err(error) => {
                fail_claimed(client, tenant_id, &message, now_unix, &error).await?;
            }
        }
    }
    Ok(processed)
}

async fn claim_batch(
    client: &mut Client,
    tenant_id: &str,
    owner: &str,
    now_unix: i64,
) -> Result<Vec<OutboxMessage>, String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane claim transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let lease_expires = now_unix.saturating_add(LEASE_SECONDS);
    let rows = tx
        .query(
            "WITH picked AS (
                SELECT message_id FROM outbox_message
                WHERE tenant_id = $1
                  AND (
                    (message_status = $2 AND next_available_unix <= $5)
                    OR (message_status = $3 AND COALESCE(lease_expires_unix, 0) <= $5)
                  )
                ORDER BY aggregate_id, aggregate_version, created_unix
                FOR UPDATE SKIP LOCKED
                LIMIT $6
             )
             UPDATE outbox_message AS message
             SET message_status = $3,
                 lease_owner = $4,
                 lease_expires_unix = $7,
                 attempt_count = message.attempt_count + 1,
                 first_attempt_unix = COALESCE(message.first_attempt_unix, $5),
                 last_attempt_unix = $5
             FROM picked
             WHERE message.tenant_id = $1 AND message.message_id = picked.message_id
             RETURNING message.message_id, message.aggregate_id, message.aggregate_version,
                       message.event_type, message.schema_version, message.created_unix,
                       message.payload_json, message.payload_hash, message.idempotency_key,
                       message.message_status, message.lease_owner, message.lease_expires_unix,
                       message.attempt_count, message.first_attempt_unix,
                       message.last_attempt_unix, message.next_available_unix,
                       message.terminal_reason",
            &[
                &tenant_id,
                &STATUS_PENDING,
                &STATUS_LEASED,
                &owner,
                &now_unix,
                &CLAIM_BATCH,
                &lease_expires,
            ],
        )
        .await
        .map_err(|error| format!("control plane claim outbox failed: {error}"))?;
    let messages = rows
        .iter()
        .map(|row| row_to_outbox(row, tenant_id))
        .collect();
    tx.commit()
        .await
        .map_err(|error| format!("control plane claim commit failed: {error}"))?;
    Ok(messages)
}

fn row_to_outbox(row: &tokio_postgres::Row, tenant_id: &str) -> OutboxMessage {
    OutboxMessage {
        message_id: row.get(0),
        tenant_id: tenant_id.to_string(),
        aggregate_id: row.get(1),
        aggregate_version: row.get(2),
        event_type: row.get(3),
        schema_version: row.get(4),
        created_unix: row.get(5),
        payload_json: row.get(6),
        payload_hash: row.get(7),
        idempotency_key: row.get(8),
        message_status: row.get(9),
        lease_owner: row.get(10),
        lease_expires_unix: row.get(11),
        attempt_count: row.get(12),
        first_attempt_unix: row.get(13),
        last_attempt_unix: row.get(14),
        next_available_unix: row.get(15),
        terminal_reason: row.get(16),
    }
}

async fn receipt_exists(
    client: &mut Client,
    tenant_id: &str,
    idempotency_key: &str,
) -> Result<bool, String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane receipt transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let row = tx
        .query_opt(
            "SELECT 1 FROM outbox_receipt WHERE tenant_id = $1 AND idempotency_key = $2",
            &[&tenant_id, &idempotency_key],
        )
        .await
        .map_err(|error| format!("control plane load outbox_receipt failed: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("control plane receipt commit failed: {error}"))?;
    Ok(row.is_some())
}

async fn ack_processed(
    client: &mut Client,
    tenant_id: &str,
    message: &OutboxMessage,
    evidence: &str,
    now_unix: i64,
    keep: i64,
) -> Result<(), String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane ack transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    tx.execute(
        "INSERT INTO outbox_receipt (
            tenant_id, idempotency_key, message_id, processed_unix, receipt_evidence
         ) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        &[
            &tenant_id,
            &message.idempotency_key,
            &message.message_id,
            &now_unix,
            &evidence,
        ],
    )
    .await
    .map_err(|error| format!("control plane insert outbox_receipt failed: {error}"))?;
    tx.execute(
        "UPDATE outbox_message
         SET message_status = $3, lease_owner = NULL, lease_expires_unix = NULL,
             terminal_reason = NULL, next_available_unix = $4
         WHERE tenant_id = $1 AND message_id = $2",
        &[
            &tenant_id,
            &message.message_id,
            &STATUS_PROCESSED,
            &now_unix,
        ],
    )
    .await
    .map_err(|error| format!("control plane ack outbox_message failed: {error}"))?;
    prune_processed_outbox(&tx, tenant_id, keep).await?;
    tx.commit()
        .await
        .map_err(|error| format!("control plane ack commit failed: {error}"))?;
    Ok(())
}

async fn fail_claimed(
    client: &mut Client,
    tenant_id: &str,
    message: &OutboxMessage,
    now_unix: i64,
    error: &DispatchError,
) -> Result<(), String> {
    let dead = outbox::should_dead_letter(message.attempt_count, error);
    let status = if dead {
        STATUS_DEAD_LETTER
    } else {
        STATUS_PENDING
    };
    let next = if dead {
        now_unix
    } else {
        outbox::next_available_unix(now_unix, message.attempt_count, &message.message_id)
    };
    let reason = error.as_str();
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane fail transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    tx.execute(
        "UPDATE outbox_message
         SET message_status = $3, lease_owner = NULL, lease_expires_unix = NULL,
             next_available_unix = $4, terminal_reason = $5
         WHERE tenant_id = $1 AND message_id = $2",
        &[&tenant_id, &message.message_id, &status, &next, &reason],
    )
    .await
    .map_err(|error| format!("control plane fail outbox_message failed: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("control plane fail commit failed: {error}"))?;
    Ok(())
}

async fn outbox_health(
    client: &mut Client,
    tenant_id: &str,
    now_unix: i64,
) -> Result<OutboxHealth, String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane health transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let row = tx
        .query_one(
            "SELECT
                COUNT(*) FILTER (WHERE message_status = $2),
                COUNT(*) FILTER (WHERE message_status = $3),
                COUNT(*) FILTER (WHERE message_status = $4),
                MIN(created_unix) FILTER (
                    WHERE message_status IN ($2, $3)
                )
             FROM outbox_message WHERE tenant_id = $1",
            &[
                &tenant_id,
                &STATUS_PENDING,
                &STATUS_LEASED,
                &STATUS_DEAD_LETTER,
            ],
        )
        .await
        .map_err(|error| format!("control plane outbox health failed: {error}"))?;
    let oldest: Option<i64> = row.get(3);
    tx.commit()
        .await
        .map_err(|error| format!("control plane health commit failed: {error}"))?;
    Ok(OutboxHealth {
        status: "ready".to_string(),
        pending: row.get(0),
        leased: row.get(1),
        dead_letter: row.get(2),
        oldest_age_seconds: oldest.map(|created| now_unix.saturating_sub(created).max(0)),
    })
}

async fn prune_processed_outbox<C: GenericClient>(
    client: &C,
    tenant_id: &str,
    keep: i64,
) -> Result<(), String> {
    let keep = keep.max(1);
    client
        .execute(
            "DELETE FROM outbox_message
             WHERE tenant_id = $1
               AND message_status = $2
               AND message_id IN (
                 SELECT message_id FROM (
                   SELECT message_id FROM outbox_message
                   WHERE tenant_id = $1 AND message_status = $2
                   ORDER BY created_unix DESC, message_id DESC
                   OFFSET $3
                 ) old_processed
               )",
            &[&tenant_id, &STATUS_PROCESSED, &keep],
        )
        .await
        .map_err(|error| format!("control plane prune outbox_message failed: {error}"))?;
    Ok(())
}

async fn list_outbox(
    client: &mut Client,
    tenant_id: &str,
    limit: i64,
) -> Result<Vec<OutboxMessage>, String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane list transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let rows = tx
        .query(
            "SELECT message_id, aggregate_id, aggregate_version, event_type, schema_version,
                    created_unix, payload_json, payload_hash, idempotency_key, message_status,
                    lease_owner, lease_expires_unix, attempt_count, first_attempt_unix,
                    last_attempt_unix, next_available_unix, terminal_reason
             FROM outbox_message WHERE tenant_id = $1
             ORDER BY CASE message_status
                        WHEN 'dead_letter' THEN 0
                        WHEN 'pending' THEN 1
                        WHEN 'leased' THEN 2
                        ELSE 3
                      END,
                      created_unix DESC, message_id DESC
             LIMIT $2",
            &[&tenant_id, &limit],
        )
        .await
        .map_err(|error| format!("control plane list outbox failed: {error}"))?;
    let messages = rows
        .iter()
        .map(|row| row_to_outbox(row, tenant_id))
        .collect();
    tx.commit()
        .await
        .map_err(|error| format!("control plane list commit failed: {error}"))?;
    Ok(messages)
}

async fn replay_dead_letter(
    client: &mut Client,
    tenant_id: &str,
    message_id: &str,
    now_unix: i64,
) -> Result<(), String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane replay transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let updated = tx
        .execute(
            "UPDATE outbox_message
             SET message_status = $3, lease_owner = NULL, lease_expires_unix = NULL,
                 attempt_count = 0, next_available_unix = $4, terminal_reason = NULL
             WHERE tenant_id = $1 AND message_id = $2 AND message_status = $5",
            &[
                &tenant_id,
                &message_id,
                &STATUS_PENDING,
                &now_unix,
                &STATUS_DEAD_LETTER,
            ],
        )
        .await
        .map_err(|error| format!("control plane replay outbox failed: {error}"))?;
    if updated != 1 {
        tx.rollback()
            .await
            .map_err(|error| format!("control plane replay rollback failed: {error}"))?;
        return Err(format!("outbox message {message_id} is not in dead_letter"));
    }
    tx.commit()
        .await
        .map_err(|error| format!("control plane replay commit failed: {error}"))?;
    Ok(())
}

async fn export_backup(client: &mut Client, tenant_id: &str) -> Result<ControlPlaneBackup, String> {
    let snapshot = load_snapshot(client, tenant_id)
        .await?
        .ok_or_else(|| format!("tenant {tenant_id} has no snapshot to back up"))?;
    let outbox = list_outbox(client, tenant_id, i64::MAX).await?;
    let receipts = list_receipts(client, tenant_id).await?;
    ControlPlaneBackup {
        schema_version: MIGRATION_VERSION,
        tenant_id: tenant_id.to_string(),
        created_unix: unix_now_i64(),
        snapshot,
        outbox,
        receipts,
        payload_hash: String::new(),
    }
    .seal()
}

async fn list_receipts(
    client: &mut Client,
    tenant_id: &str,
) -> Result<Vec<OutboxReceiptRow>, String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane receipt list transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    let rows = tx
        .query(
            "SELECT idempotency_key, message_id, processed_unix, receipt_evidence
             FROM outbox_receipt WHERE tenant_id = $1
             ORDER BY processed_unix, idempotency_key",
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane list outbox_receipt failed: {error}"))?;
    let receipts = rows
        .iter()
        .map(|row| OutboxReceiptRow {
            tenant_id: tenant_id.to_string(),
            idempotency_key: row.get(0),
            message_id: row.get(1),
            processed_unix: row.get(2),
            receipt_evidence: row.get(3),
        })
        .collect();
    tx.commit()
        .await
        .map_err(|error| format!("control plane receipt list commit failed: {error}"))?;
    Ok(receipts)
}

async fn restore_backup(
    client: &mut Client,
    tenant_id: &str,
    backup: &ControlPlaneBackup,
) -> Result<(), String> {
    backup.verify()?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane restore transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    write_snapshot_rows(&tx, tenant_id, &backup.snapshot, false).await?;
    for table in ["outbox_receipt", "outbox_message"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE tenant_id = $1"),
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane delete {table} failed: {error}"))?;
    }
    for message in &backup.outbox {
        insert_restored_outbox(&tx, tenant_id, message).await?;
    }
    for receipt in &backup.receipts {
        tx.execute(
            "INSERT INTO outbox_receipt (
                tenant_id, idempotency_key, message_id, processed_unix, receipt_evidence
             ) VALUES ($1,$2,$3,$4,$5)",
            &[
                &tenant_id,
                &receipt.idempotency_key,
                &receipt.message_id,
                &receipt.processed_unix,
                &receipt.receipt_evidence,
            ],
        )
        .await
        .map_err(|error| format!("control plane restore outbox_receipt failed: {error}"))?;
    }
    tx.commit()
        .await
        .map_err(|error| format!("control plane restore commit failed: {error}"))?;
    Ok(())
}

async fn insert_restored_outbox(
    tx: &Transaction<'_>,
    tenant_id: &str,
    message: &OutboxMessage,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO outbox_message (
            tenant_id, message_id, aggregate_id, aggregate_version, event_type,
            schema_version, created_unix, payload_json, payload_hash, idempotency_key,
            message_status, lease_owner, lease_expires_unix, attempt_count,
            first_attempt_unix, last_attempt_unix, next_available_unix, terminal_reason
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        &[
            &tenant_id,
            &message.message_id,
            &message.aggregate_id,
            &message.aggregate_version,
            &message.event_type,
            &message.schema_version,
            &message.created_unix,
            &message.payload_json,
            &message.payload_hash,
            &message.idempotency_key,
            &message.message_status,
            &message.lease_owner,
            &message.lease_expires_unix,
            &message.attempt_count,
            &message.first_attempt_unix,
            &message.last_attempt_unix,
            &message.next_available_unix,
            &message.terminal_reason,
        ],
    )
    .await
    .map_err(|error| format!("control plane restore outbox_message failed: {error}"))?;
    Ok(())
}

async fn drop_tenant(client: &mut Client, tenant_id: &str) -> Result<(), String> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| format!("control plane drop-tenant transaction failed: {error}"))?;
    tx.execute(
        "SELECT set_config('wardnet.tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .map_err(|error| format!("control plane tenant context failed: {error}"))?;
    for table in [
        "outbox_receipt",
        "outbox_message",
        "threat_feed",
        "audit_record",
        "security_event",
        "dnsbl_entry",
        "threat_indicator",
        "route_config",
        "tenant_profile",
        "tenant_account",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE tenant_id = $1"),
            &[&tenant_id],
        )
        .await
        .map_err(|error| format!("control plane drop {table} failed: {error}"))?;
    }
    tx.commit()
        .await
        .map_err(|error| format!("control plane drop-tenant commit failed: {error}"))?;
    Ok(())
}

fn unix_now_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
    fn database_url_rejects_non_postgres_and_ambiguous_sslmode() {
        parse_database_url("").unwrap_err();
        parse_database_url("mysql://x").unwrap_err();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet?sslmode=prefer").unwrap_err();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet?sslmode=allow").unwrap_err();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet?sslmode=require").unwrap();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet?sslmode=verify-full").unwrap();
        parse_database_url("postgres://wardnet@127.0.0.1/wardnet").unwrap();
        parse_database_url("postgresql://wardnet@127.0.0.1/wardnet?sslmode=disable").unwrap();
        assert_eq!(
            ssl_mode("postgres://wardnet@127.0.0.1/wardnet").unwrap(),
            SslMode::Disable
        );
        assert_eq!(
            ssl_mode("postgres://wardnet@127.0.0.1/wardnet?sslmode=require").unwrap(),
            SslMode::Require
        );
        assert_eq!(
            ssl_mode("postgres://wardnet@127.0.0.1/wardnet?sslmode=verify-full").unwrap(),
            SslMode::Require
        );
        assert_eq!(
            rewrite_sslmode_for_tokio(
                "postgres://wardnet:sslmode=verify-full@127.0.0.1/wardnet?sslmode=verify-full"
            ),
            "postgres://wardnet:sslmode=verify-full@127.0.0.1/wardnet?sslmode=require"
        );
        assert_eq!(
            rewrite_sslmode_for_tokio(
                "postgres://wardnet@127.0.0.1/wardnet?sslmode=verify-ca&connect_timeout=5"
            ),
            "postgres://wardnet@127.0.0.1/wardnet?sslmode=require&connect_timeout=5"
        );
        use std::str::FromStr;
        tokio_postgres::Config::from_str(
            "postgres://wardnet@127.0.0.1/wardnet?sslmode=verify-full",
        )
        .expect_err("tokio-postgres 0.7 rejects verify-full");
        tokio_postgres::Config::from_str(&rewrite_sslmode_for_tokio(
            "postgres://wardnet@127.0.0.1/wardnet?sslmode=verify-full",
        ))
        .expect("rewritten verify-full must parse as require");
    }

    #[tokio::test]
    async fn require_tls_fails_closed_against_plaintext_postgres() {
        let Ok(url) = std::env::var("CONTROL_PLANE_TEST_DATABASE_URL") else {
            return;
        };
        if url.trim().is_empty() {
            return;
        }
        let separator = if url.contains('?') { '&' } else { '?' };
        for mode in ["require", "verify-ca", "verify-full"] {
            let tls_url = format!("{url}{separator}sslmode={mode}");
            let error = match PostgresPlane::connect(&tls_url).await {
                Ok(_) => panic!("plaintext CI postgres must not satisfy rustls ({mode})"),
                Err(error) => error,
            };
            assert!(
                !error.to_ascii_lowercase().contains("invalid value"),
                "{mode} must not fail as a tokio-postgres config parse: {error}"
            );
            assert!(
                error.contains("TLS") || error.contains("ssl") || error.contains("certificate"),
                "operator must see a TLS failure for {mode}, not a silent plaintext fallback: {error}"
            );
        }
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
            "outbox_message",
            "outbox_receipt",
            "schema_migration",
        ] {
            assert!(MIGRATION_SQL.contains(table), "missing table {table}");
        }
        assert!(MIGRATION_SQL.contains("FORCE ROW LEVEL SECURITY"));
        assert!(MIGRATION_SQL.contains("wardnet.tenant_id"));
        assert!(MIGRATION_SQL.contains("wardnet_runtime"));
        assert!(MIGRATION_SQL.contains("NOBYPASSRLS"));
        assert!(MIGRATION_SQL.contains("PRIMARY KEY (tenant_id, route_id)"));
        assert!(MIGRATION_SQL.contains("REFERENCES tenant_account"));
        assert!(MIGRATION_SQL.contains("UNIQUE (tenant_id, idempotency_key)"));
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
        let tenant = unique_tenant("roundtrip");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
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
        assert_eq!(loaded.commercial.tenant_id, tenant);
        let messages = plane
            .list_outbox_limited(LIST_LIMIT)
            .await
            .expect("list snapshot outbox");
        assert!(
            messages
                .iter()
                .any(|message| message.event_type == EVENT_SNAPSHOT_REPLACED),
            "snapshot persist must enqueue an outbox row"
        );
    }

    fn test_database_url() -> Option<String> {
        std::env::var("CONTROL_PLANE_TEST_DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
    }

    fn unique_tenant(label: &str) -> String {
        format!(
            "{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        )
    }

    fn sample_event(id: u64, path: &str) -> SecurityEvent {
        SecurityEvent {
            id,
            timestamp_unix: 1_700_000_000,
            client_ip: Some("198.51.100.20".parse().expect("documentation IP")),
            route_id: Some("demo".into()),
            action: "blocked".into(),
            reason: "fixture".into(),
            score: 80,
            path: path.into(),
        }
    }

    #[tokio::test]
    async fn postgres_appends_event_and_outbox_atomically() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("outbox-append");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("test database must accept the control plane");
        plane
            .save(&AppData::seeded())
            .await
            .expect("seed tenant snapshot");
        let setup_now = unix_now_i64().saturating_add(60);
        let _ = plane
            .drain_once("setup", setup_now, |_| Ok("setup".into()))
            .await
            .expect("ack snapshot outbox");
        let event = sample_event(7, "/gateway/login");
        plane
            .append_security_event(&event, 1_000)
            .await
            .expect("append event + outbox");
        let loaded = plane.load().await.expect("load").expect("tenant exists");
        assert!(
            loaded
                .events
                .iter()
                .any(|row| row.id == 7 && row.path == "/gateway/login"),
            "event must round-trip unmasked"
        );
        assert_eq!(loaded.next_event_id, 8);
        let messages = plane
            .list_outbox_limited(LIST_LIMIT)
            .await
            .expect("list outbox");
        let recorded = messages
            .iter()
            .find(|message| message.event_type == EVENT_SECURITY_RECORDED)
            .expect("security event outbox row");
        assert!(recorded.payload_json.contains("198.51.100.20"));
        assert!(recorded.payload_json.contains("/gateway/login"));
        assert_eq!(recorded.message_status, STATUS_PENDING);
        plane
            .append_security_event(&event, 1_000)
            .await
            .expect("idempotent retry of same event id");
        let again = plane
            .list_outbox_limited(LIST_LIMIT)
            .await
            .expect("list after retry");
        assert_eq!(
            again
                .iter()
                .filter(|message| message.event_type == EVENT_SECURITY_RECORDED)
                .count(),
            1,
            "duplicate event id must not enqueue a second outbox row"
        );
    }

    #[tokio::test]
    async fn postgres_outbox_worker_is_idempotent_and_dead_letters() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("outbox-worker");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("test database");
        plane.save(&AppData::seeded()).await.expect("seed");
        let now = unix_now_i64().saturating_add(60);
        let _ = plane
            .drain_once("setup", now, |_| Ok("setup".into()))
            .await
            .expect("ack snapshot outbox");
        plane
            .append_security_event(&sample_event(1, "/one"), 100)
            .await
            .expect("enqueue");

        let dispatched = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = dispatched.clone();
        let processed = plane
            .drain_once("worker-a", now, move |message| {
                seen.lock()
                    .expect("dispatcher lock")
                    .push(message.message_id.clone());
                Ok(format!("ack:{}", message.payload_hash))
            })
            .await
            .expect("first drain");
        assert_eq!(processed, 1);
        assert_eq!(dispatched.lock().expect("dispatcher lock").len(), 1);

        let processed_again = plane
            .drain_once("worker-a", now.saturating_add(30), |_| {
                panic!("processed messages must not be claimed again")
            })
            .await
            .expect("second drain");
        assert_eq!(processed_again, 0);

        plane
            .append_security_event(&sample_event(2, "/poison"), 100)
            .await
            .expect("poison enqueue");
        let _ = plane
            .drain_once("worker-a", now.saturating_add(60), |_| {
                Err(crate::outbox::DispatchError::Permanent("malformed".into()))
            })
            .await
            .expect("dead-letter drain");
        let health = plane
            .outbox_health(now.saturating_add(60))
            .await
            .expect("health");
        assert_eq!(health.status, "ready");
        assert_eq!(health.dead_letter, 1);

        let dead = plane
            .list_outbox_limited(LIST_LIMIT)
            .await
            .expect("list")
            .into_iter()
            .find(|message| message.message_status == STATUS_DEAD_LETTER)
            .expect("dead letter row");
        plane
            .replay_dead_letter(&dead.message_id, now.saturating_add(90))
            .await
            .expect("authorized replay");
        let replayed = plane
            .drain_once(
                "worker-b",
                now.saturating_add(90),
                |_| Ok("replayed".into()),
            )
            .await
            .expect("replay drain");
        assert_eq!(replayed, 1);
    }

    #[tokio::test]
    async fn postgres_expired_lease_is_reclaimed_and_skip_locked_is_exclusive() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("outbox-lease");
        let plane_a = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("plane a");
        let plane_b = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("plane b");
        plane_a.save(&AppData::seeded()).await.expect("seed");
        let now = unix_now_i64().saturating_add(60);
        let _ = plane_a
            .drain_once("setup", now, |_| Ok("setup".into()))
            .await
            .expect("ack snapshot outbox");
        plane_a
            .append_security_event(&sample_event(3, "/lease"), 100)
            .await
            .expect("enqueue");

        let first = plane_a
            .drain_once("worker-a", now, |_| {
                Err(crate::outbox::DispatchError::Transient("timeout".into()))
            })
            .await
            .expect("lease then fail transient");
        assert_eq!(first, 0);
        let listed = plane_a
            .list_outbox_limited(LIST_LIMIT)
            .await
            .expect("list after fail");
        let pending = listed
            .iter()
            .find(|message| message.event_type == EVENT_SECURITY_RECORDED)
            .expect("event still queued");
        assert_eq!(pending.message_status, STATUS_PENDING);
        assert!(pending.next_available_unix > now);

        let later = pending.next_available_unix;
        let reclaimed = plane_b
            .drain_once("worker-b", later, |_| Ok("reclaimed".into()))
            .await
            .expect("expired/next-available reclaim");
        assert_eq!(reclaimed, 1);
    }

    #[tokio::test]
    async fn postgres_parallel_connect_does_not_race_grants() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("parallel-grant");
        let (first, second) = tokio::join!(
            PostgresPlane::connect_tenant(&url, &tenant),
            PostgresPlane::connect_tenant(&url, &tenant),
        );
        first.expect("first parallel connect");
        second.expect("second parallel connect");
    }

    #[tokio::test]
    async fn postgres_outbox_list_is_bounded_and_prunes_processed() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("outbox-bound");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("test database");
        plane.save(&AppData::seeded()).await.expect("seed");
        let now = unix_now_i64().saturating_add(60);
        let _ = plane
            .drain_once("setup", now, |_| Ok("setup".into()))
            .await
            .expect("ack snapshot outbox");
        for id in 1..=5 {
            plane
                .append_security_event(&sample_event(id, "/bound"), 3)
                .await
                .expect("enqueue");
        }
        let processed = plane
            .drain_once("worker-bound", now.saturating_add(30), |_| Ok("ack".into()))
            .await
            .expect("drain pending");
        assert_eq!(processed, 5);
        plane
            .append_security_event(&sample_event(6, "/bound-tail"), 3)
            .await
            .expect("append that prunes processed");
        let listed = plane
            .list_outbox_limited(100)
            .await
            .expect("list after prune");
        assert_eq!(
            listed
                .iter()
                .filter(|message| message.message_status == STATUS_PROCESSED)
                .count(),
            3,
            "processed outbox rows must be retained like EVENT_LIMIT"
        );
        assert_eq!(
            listed
                .iter()
                .filter(|message| message.message_status == STATUS_PENDING)
                .count(),
            1
        );
        let bounded = plane.list_outbox_limited(2).await.expect("bounded list");
        assert_eq!(bounded.len(), 2);
        assert_eq!(bounded[0].message_status, STATUS_PENDING);
        let _ = plane
            .drain_once("worker-bound", now.saturating_add(60), |_| {
                Err(crate::outbox::DispatchError::Permanent("malformed".into()))
            })
            .await
            .expect("dead-letter the tail");
        let health = plane
            .outbox_health(now.saturating_add(60))
            .await
            .expect("health after poison");
        assert_eq!(health.dead_letter, 1);
        for id in 7..=10 {
            plane
                .append_security_event(&sample_event(id, "/bound-more"), 3)
                .await
                .expect("more events after dead letter");
            let _ = plane
                .drain_once("worker-bound", now.saturating_add(90 + id as i64), |_| {
                    Ok("ack".into())
                })
                .await
                .expect("drain extra");
        }
        let after = plane
            .list_outbox_limited(100)
            .await
            .expect("list dead letter");
        assert!(
            after
                .iter()
                .any(|message| message.message_status == STATUS_DEAD_LETTER),
            "dead letters must not be pruned"
        );
    }

    #[tokio::test]
    async fn postgres_ack_and_save_prune_to_configured_event_limit() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("outbox-ack-limit");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("test database")
            .with_event_limit(2);
        plane.save(&AppData::seeded()).await.expect("seed");
        let now = unix_now_i64().saturating_add(60);
        let _ = plane
            .drain_once("setup", now, |_| Ok("setup".into()))
            .await
            .expect("ack snapshot outbox");
        for id in 1..=4 {
            plane
                .append_security_event(&sample_event(id, "/ack-limit"), 1_000)
                .await
                .expect("enqueue pending");
        }
        let processed = plane
            .drain_once("worker-ack-limit", now.saturating_add(30), |_| {
                Ok("ack".into())
            })
            .await
            .expect("drain pending");
        assert_eq!(processed, 4);
        let listed = plane
            .list_outbox_limited(100)
            .await
            .expect("list after ack prune");
        assert_eq!(
            listed
                .iter()
                .filter(|message| message.message_status == STATUS_PROCESSED)
                .count(),
            2,
            "ack must prune processed rows to the configured EVENT_LIMIT, not LIST_LIMIT"
        );
        let current = plane
            .load()
            .await
            .expect("load for prune save")
            .expect("tenant exists");
        plane
            .save(&current)
            .await
            .expect("save must use the same retention cap");
        let after_save = plane
            .list_outbox_limited(100)
            .await
            .expect("list after save prune");
        assert_eq!(
            after_save
                .iter()
                .filter(|message| message.message_status == STATUS_PROCESSED)
                .count(),
            2,
            "save_snapshot must prune processed rows to EVENT_LIMIT"
        );
    }

    #[test]
    fn backup_verify_fails_closed_on_schema_and_hash() {
        let backup = ControlPlaneBackup {
            schema_version: MIGRATION_VERSION,
            tenant_id: "local-lab".into(),
            created_unix: 1,
            snapshot: AppData::seeded(),
            outbox: Vec::new(),
            receipts: Vec::new(),
            payload_hash: String::new(),
        }
        .seal()
        .expect("seal");
        assert!(backup.verify().is_ok());

        let mut prior = backup.clone();
        prior.schema_version = MIN_RESTORABLE_SCHEMA_VERSION;
        let prior = prior.seal().expect("re-seal compatible prior schema");
        assert!(
            prior.verify().is_ok(),
            "role-only schema 3 must restore schema-{MIN_RESTORABLE_SCHEMA_VERSION} logical backups"
        );

        let mut too_old = backup.clone();
        too_old.schema_version = MIN_RESTORABLE_SCHEMA_VERSION - 1;
        assert!(
            too_old
                .verify()
                .expect_err("older than restorable window")
                .contains("unsupported")
        );

        let mut bad_schema = backup.clone();
        bad_schema.schema_version = MIGRATION_VERSION + 1;
        assert!(
            bad_schema
                .verify()
                .expect_err("future schema")
                .contains("unsupported")
        );

        let mut bad_hash = backup.clone();
        bad_hash.payload_hash = "deadbeef".into();
        assert!(
            bad_hash
                .verify()
                .expect_err("tamper")
                .contains("payload_hash")
        );
    }

    #[tokio::test]
    async fn postgres_backup_restore_drill_preserves_unmasked_invariants() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("backup-drill");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("test database")
            .with_event_limit(10);
        let mut seeded = AppData::seeded();
        seeded.events.push(sample_event(1, "/backup-restore"));
        seeded.next_event_id = 2;
        plane.save(&seeded).await.expect("seed with unmasked event");
        let now = unix_now_i64().saturating_add(60);
        plane
            .append_security_event(&sample_event(2, "/backup-path"), 10)
            .await
            .expect("enqueue");
        let _ = plane
            .drain_once("backup-worker", now, |_| Ok("backup-ack".into()))
            .await
            .expect("process one");
        let backup = plane.logical_backup().await.expect("export backup");
        backup.verify().expect("self-hash");
        assert!(
            backup
                .snapshot
                .events
                .iter()
                .any(|event| event.path == "/backup-restore"
                    && event.client_ip.map(|ip| ip.to_string()) == Some("198.51.100.20".into())),
            "backup must keep client IPs and paths unmasked"
        );
        assert!(
            backup
                .outbox
                .iter()
                .any(|message| message.payload_json.contains("198.51.100.20")),
            "outbox payloads must keep client IPs unmasked"
        );

        let isolated = unique_tenant("backup-restore-target");
        let target = PostgresPlane::connect_tenant(&url, &isolated)
            .await
            .expect("isolated restore tenant");
        target
            .restore_logical_backup(&backup)
            .await
            .expect("restore into isolated tenant");
        let restored = target.logical_backup().await.expect("re-export restored");
        assert_eq!(restored.snapshot.routes, backup.snapshot.routes);
        assert_eq!(restored.snapshot.events, backup.snapshot.events);
        assert_eq!(restored.outbox.len(), backup.outbox.len());
        assert_eq!(restored.receipts.len(), backup.receipts.len());
        assert_eq!(
            restored.semantic_hash().expect("restored hash"),
            backup.semantic_hash().expect("source hash")
        );

        let report = plane.restore_drill().await.expect("isolated drill");
        assert!(report.passed, "drill must match source and restored hashes");
        assert!(
            report.duration_ms <= BACKUP_RTO_BUDGET_MS,
            "drill duration {}ms exceeds declared RTO {}ms",
            report.duration_ms,
            BACKUP_RTO_BUDGET_MS
        );
        assert_eq!(report.rpo, BACKUP_RPO);
        assert!(
            plane
                .load()
                .await
                .expect("source tenant still loads")
                .is_some(),
            "drill must not drop the production tenant"
        );
    }

    #[tokio::test]
    async fn postgres_runtime_role_is_not_superuser_and_rls_default_denies() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant_a = unique_tenant("runtime-a");
        let tenant_b = unique_tenant("runtime-b");
        let plane_a = PostgresPlane::connect_tenant(&url, &tenant_a)
            .await
            .expect("plane a");
        let (role, superuser) = plane_a.runtime_identity().await.expect("runtime identity");
        assert_eq!(role, RUNTIME_ROLE);
        assert!(!superuser, "runtime role must not be a superuser");
        assert!(
            plane_a.runtime_ddl_is_denied().await.expect("ddl probe"),
            "runtime role must not DROP TABLE or DISABLE ROW LEVEL SECURITY"
        );
        plane_a
            .save(&AppData::seeded())
            .await
            .expect("save tenant a");
        assert_eq!(
            plane_a
                .unscoped_route_count()
                .await
                .expect("unscoped count"),
            0,
            "missing wardnet.tenant_id must yield no rows under FORCE RLS"
        );
        let plane_b = PostgresPlane::connect_tenant(&url, &tenant_b)
            .await
            .expect("plane b");
        assert!(
            plane_b.load().await.expect("load tenant b").is_none(),
            "tenant b must not observe tenant a rows"
        );
        let loaded_a = plane_a
            .load()
            .await
            .expect("load tenant a")
            .expect("tenant a rows");
        assert!(!loaded_a.routes.is_empty());
    }

    #[test]
    fn hash_partition_parent_rejects_injection() {
        assert!(hash_partition_sql_for("security_event").is_ok());
        assert!(hash_partition_sql_for("event_hash_probe").is_ok());
        assert!(hash_partition_sql_for("event;drop").is_err());
        assert!(hash_partition_sql_for("Event").is_err());
        assert!(hash_partition_sql_for("").is_err());
        let sql = hash_partition_sql_for("security_event").expect("sql");
        assert!(sql.contains("PARTITION BY HASH (tenant_id)"));
        assert!(sql.contains(&format!("MODULUS {EVENT_PARTITION_MODULUS}")));
    }

    async fn owner_client(url: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .expect("owner connect");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }

    #[tokio::test]
    async fn postgres_security_event_is_hash_partitioned() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("event-hash");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("plane");
        assert_eq!(
            plane
                .event_partition_count()
                .await
                .expect("partition count"),
            i64::from(EVENT_PARTITION_MODULUS)
        );
        let mut seeded = AppData::seeded();
        seeded.events.push(sample_event(1, "/hash-path"));
        seeded.next_event_id = 2;
        plane.save(&seeded).await.expect("seed with unmasked event");
        let loaded = plane.load().await.expect("load").expect("snapshot");
        assert!(
            loaded.events.iter().any(|event| event.path == "/hash-path"
                && event.client_ip.map(|ip| ip.to_string()) == Some("198.51.100.20".into())),
            "HASH partitions must keep client IPs and paths unmasked"
        );
        let tableoid = plane
            .security_event_tableoid()
            .await
            .expect("child tableoid");
        assert!(
            tableoid.starts_with("security_event_p"),
            "row must land in a HASH child, got {tableoid}"
        );
    }

    #[tokio::test]
    async fn postgres_hash_partition_convert_preserves_unmasked_probe_rows() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("hash-probe");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("plane so tenant_account and role exist");
        plane.save(&AppData::seeded()).await.expect("seed tenant");

        let client = owner_client(&url).await;
        client
            .batch_execute(
                "DROP TABLE IF EXISTS event_hash_probe CASCADE;
                 CREATE TABLE event_hash_probe (
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
                 );",
            )
            .await
            .expect("unpartitioned probe");
        client
            .execute(
                "INSERT INTO event_hash_probe (
                    tenant_id, event_id, timestamp_unix, client_address, route_id,
                    action_name, event_reason, event_score, request_path
                 ) VALUES ($1, 1, 1700000000, '198.51.100.20', 'demo', 'blocked', 'fixture', 80, '/probe-path')",
                &[&tenant],
            )
            .await
            .expect("probe row");
        let sql = hash_partition_sql_for("event_hash_probe").expect("probe sql");
        client
            .batch_execute(&sql)
            .await
            .expect("convert unpartitioned probe");
        let kind: String = client
            .query_one(
                "SELECT relkind::text FROM pg_class WHERE relname = 'event_hash_probe'",
                &[],
            )
            .await
            .expect("kind")
            .get(0);
        assert_eq!(kind, "p");
        let children: i64 = client
            .query_one(
                "SELECT COUNT(*)::bigint FROM pg_partition_tree('event_hash_probe'::regclass) WHERE level = 1",
                &[],
            )
            .await
            .expect("children")
            .get(0);
        assert_eq!(children, i64::from(EVENT_PARTITION_MODULUS));
        let row = client
            .query_one(
                "SELECT client_address, request_path, tableoid::regclass::text
                 FROM event_hash_probe WHERE event_id = 1",
                &[],
            )
            .await
            .expect("converted row");
        let ip: String = row.get(0);
        let path: String = row.get(1);
        let tableoid: String = row.get(2);
        assert_eq!(ip, "198.51.100.20");
        assert_eq!(path, "/probe-path");
        assert!(
            tableoid.starts_with("event_hash_probe_p"),
            "converted row must land in a HASH child, got {tableoid}"
        );
        client
            .batch_execute("DROP TABLE IF EXISTS event_hash_probe CASCADE")
            .await
            .expect("drop probe");
    }

    #[tokio::test]
    async fn postgres_stale_snapshot_save_conflicts() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("occ");
        let plane_a = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("plane a");
        let plane_b = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("plane b");
        plane_a.save(&AppData::seeded()).await.expect("first save");
        let mut loaded_a = plane_a.load().await.expect("load a").expect("tenant a");
        let loaded_b = plane_b.load().await.expect("load b").expect("tenant b");
        assert_eq!(loaded_a.snapshot_version, loaded_b.snapshot_version);
        loaded_a.routes[0].path_prefix = "/occ-a".into();
        plane_a.save(&loaded_a).await.expect("winner save");
        let mut stale = loaded_b;
        stale.routes[0].path_prefix = "/occ-b".into();
        let error = plane_b
            .save(&stale)
            .await
            .expect_err("stale snapshot must conflict");
        assert!(
            error.contains("snapshot conflict"),
            "operator must see a snapshot conflict: {error}"
        );
        let winner = plane_a.load().await.expect("reload").expect("tenant");
        assert_eq!(winner.routes[0].path_prefix, "/occ-a");
        assert!(winner.snapshot_version > loaded_a.snapshot_version);
    }

    #[tokio::test]
    async fn postgres_enqueues_external_effect_and_async_drain_records_receipt() {
        let Some(url) = test_database_url() else {
            return;
        };
        let tenant = unique_tenant("outbox-effect");
        let plane = PostgresPlane::connect_tenant(&url, &tenant)
            .await
            .expect("test database");
        plane.save(&AppData::seeded()).await.expect("seed");
        let now = unix_now_i64().saturating_add(60);
        let _ = plane
            .drain_once("setup", now, |_| Ok("setup".into()))
            .await
            .expect("ack snapshot");
        let payload = serde_json::json!({
            "objects_url": "https://taxii.example/api1/collections/c/objects/",
            "feed_id": "taxii-lab",
            "path": "/gateway/login",
            "client_ip": "198.51.100.20"
        })
        .to_string();
        let message_id = plane
            .enqueue_effect(crate::outbox::EVENT_TAXII_POLLED, "taxii-lab", payload)
            .await
            .expect("enqueue taxii poll");
        let processed = plane
            .drain_due_async(
                "effect-worker",
                now.saturating_add(30),
                |message| async move {
                    assert_eq!(message.event_type, crate::outbox::EVENT_TAXII_POLLED);
                    assert!(message.payload_json.contains("198.51.100.20"));
                    assert!(message.payload_json.contains("/gateway/login"));
                    Ok("taxii-ack:unmasked".into())
                },
            )
            .await
            .expect("async drain");
        assert_eq!(processed, 1);
        let (message, evidence) = plane
            .get_outbox_item(&message_id)
            .await
            .expect("get item")
            .expect("enqueued");
        assert_eq!(message.message_status, STATUS_PROCESSED);
        assert_eq!(evidence.as_deref(), Some("taxii-ack:unmasked"));
    }
}
