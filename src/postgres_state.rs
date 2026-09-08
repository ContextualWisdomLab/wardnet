//! PostgreSQL session and repository boundary for tenant-scoped reputation state work.
//!
//! Runtime selection remains in `runtime_config`, credential sourcing remains in
//! `CredentialRegistry`, and enabling PostgreSQL as an application authority is
//! deferred until the wider repository/readiness slice is complete. This module
//! owns transaction-local tenant binding and bounded typed calls into Wardnet's
//! canonical PostgreSQL reputation-state functions; it does not expose raw SQL as
//! an application repository API.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{Client, Config, NoTls, Socket};

const MAX_TENANT_ID_BYTES: usize = 256;
const PUBLICATION_CONFLICT_SQLSTATE: &str = "40001";
const PUBLICATION_CONFLICT_MESSAGE: &str = "reputation_source_publication_conflict";

/// Error returned by Wardnet's PostgreSQL session and repository boundary.
#[derive(Debug)]
pub enum PostgresStateError {
    /// Tenant identity is empty or exceeds the bounded application contract.
    InvalidTenantId(&'static str),
    /// A typed publication command violates Wardnet's application contract.
    InvalidPublication(&'static str),
    /// The publication conflicts with immutable history or current-head ordering.
    PublicationConflict,
    /// The canonical publication function returned an undocumented outcome.
    InvalidPublicationOutcome,
    /// A connection pool with no connections cannot fail closed.
    InvalidPoolSize,
    /// The plaintext integration constructor was requested outside loopback.
    InvalidLoopbackFixture(&'static str),
    /// PostgreSQL rejected a connection, transaction, or query operation.
    Postgres(tokio_postgres::Error),
}

impl fmt::Display for PostgresStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTenantId(reason) => write!(formatter, "invalid tenant identity: {reason}"),
            Self::InvalidPublication(reason) => {
                write!(formatter, "invalid reputation source publication: {reason}")
            }
            Self::PublicationConflict => {
                formatter.write_str("reputation source publication conflicts with durable state")
            }
            Self::InvalidPublicationOutcome => formatter
                .write_str("PostgreSQL publication function returned an unsupported outcome"),
            Self::InvalidPoolSize => {
                formatter.write_str("PostgreSQL pool size must be greater than zero")
            }
            Self::InvalidLoopbackFixture(reason) => {
                write!(formatter, "invalid loopback PostgreSQL fixture: {reason}")
            }
            Self::Postgres(error) => write!(formatter, "PostgreSQL operation failed: {error}"),
        }
    }
}

impl std::error::Error for PostgresStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Postgres(error) => Some(error),
            _ => None,
        }
    }
}

impl From<tokio_postgres::Error> for PostgresStateError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Postgres(error)
    }
}

/// Result type for PostgreSQL tenant-session and repository operations.
pub type PostgresStateResult<T> = Result<T, PostgresStateError>;

/// Validated tenant identity passed to PostgreSQL only as parameter data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Parse a bounded tenant identity without interpreting its characters as SQL.
    pub fn parse(raw: impl AsRef<str>) -> PostgresStateResult<Self> {
        let raw = raw.as_ref();
        if raw.trim().is_empty() {
            return Err(PostgresStateError::InvalidTenantId("value is blank"));
        }
        if raw.len() > MAX_TENANT_ID_BYTES {
            return Err(PostgresStateError::InvalidTenantId(
                "value exceeds 256 UTF-8 bytes",
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    /// Return the opaque tenant identity exactly as supplied by the caller.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable command for one tenant-scoped reputation-source publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationSourcePublication {
    source_id: String,
    expected_prior_generation: Option<String>,
    source_generation: String,
    source_generation_ordinal: i64,
    completed_at_unix: i64,
    provenance_ref: String,
    evidence_snapshot_ref: String,
    completeness_ref: String,
    producer_lifecycle_ref: String,
}

impl ReputationSourcePublication {
    /// Build a publication command that matches the canonical PostgreSQL function contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_id: impl AsRef<str>,
        expected_prior_generation: Option<&str>,
        source_generation: impl AsRef<str>,
        source_generation_ordinal: i64,
        completed_at_unix: i64,
        provenance_ref: impl AsRef<str>,
        evidence_snapshot_ref: impl AsRef<str>,
        completeness_ref: impl AsRef<str>,
        producer_lifecycle_ref: impl AsRef<str>,
    ) -> PostgresStateResult<Self> {
        if source_generation_ordinal < 0 {
            return Err(PostgresStateError::InvalidPublication(
                "source generation ordinal must be nonnegative",
            ));
        }
        if completed_at_unix < 0 {
            return Err(PostgresStateError::InvalidPublication(
                "completion time must be nonnegative",
            ));
        }

        Ok(Self {
            source_id: validate_publication_text(source_id.as_ref())?,
            expected_prior_generation: expected_prior_generation
                .map(validate_publication_text)
                .transpose()?,
            source_generation: validate_publication_text(source_generation.as_ref())?,
            source_generation_ordinal,
            completed_at_unix,
            provenance_ref: validate_publication_text(provenance_ref.as_ref())?,
            evidence_snapshot_ref: validate_publication_text(evidence_snapshot_ref.as_ref())?,
            completeness_ref: validate_publication_text(completeness_ref.as_ref())?,
            producer_lifecycle_ref: validate_publication_text(producer_lifecycle_ref.as_ref())?,
        })
    }
}

/// Stable application outcome returned by the typed publication repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOutcome {
    /// A new immutable publication and last-known-good head were committed.
    Committed,
    /// The exact immutable publication was already committed and was replayed idempotently.
    Replay,
}

/// Safe diagnostic proving that a checked-out pooled connection has no tenant authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundContextProbe {
    backend_pid: i64,
    tenant_id: Option<String>,
}

impl UnboundContextProbe {
    /// PostgreSQL backend PID, used only to prove physical connection reuse in tests/diagnostics.
    pub fn backend_pid(&self) -> i64 {
        self.backend_pid
    }

    /// Tenant context visible outside a transaction; healthy pooled connections return `None`.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
}

struct PoolInner {
    connections: Vec<Arc<Mutex<Client>>>,
    next_connection: AtomicUsize,
}

/// Small async PostgreSQL connection pool with transaction-local tenant binding.
#[derive(Clone)]
pub struct PostgresTenantPool {
    inner: Arc<PoolInner>,
}

/// Borrowed transaction surface. Callers can execute only repository-owned fixed SQL here;
/// tenant identity binding itself is always parameterized by [`PostgresTenantPool`].
pub struct TenantTransaction<'client> {
    client: &'client Client,
}

/// Boxed operation future used to keep the tenant transaction borrow scoped to one checkout.
pub type TenantTransactionFuture<'client, T> =
    Pin<Box<dyn Future<Output = PostgresStateResult<T>> + Send + 'client>>;

impl<'client> TenantTransaction<'client> {
    /// Execute fixed repository SQL that returns one `BIGINT` scalar.
    pub async fn query_scalar_i64(&self, sql: &str) -> PostgresStateResult<i64> {
        let row = self.client.query_one(sql, &[]).await?;
        Ok(row.try_get(0)?)
    }

    /// Execute fixed repository SQL that returns one non-null text scalar.
    pub async fn query_scalar_text(&self, sql: &str) -> PostgresStateResult<String> {
        let row = self.client.query_one(sql, &[]).await?;
        Ok(row.try_get(0)?)
    }

    async fn publish_reputation_source(
        &self,
        tenant_id: String,
        publication: ReputationSourcePublication,
    ) -> PostgresStateResult<PublicationOutcome> {
        let row = self
            .client
            .query_one(
                "SELECT public.wardnet_publish_reputation_source_generation($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &tenant_id,
                    &publication.source_id,
                    &publication.expected_prior_generation,
                    &publication.source_generation,
                    &publication.source_generation_ordinal,
                    &publication.completed_at_unix,
                    &publication.provenance_ref,
                    &publication.evidence_snapshot_ref,
                    &publication.completeness_ref,
                    &publication.producer_lifecycle_ref,
                ],
            )
            .await
            .map_err(map_publication_error)?;
        let outcome: String = row.try_get(0)?;
        parse_publication_outcome(&outcome)
    }
}

impl PostgresTenantPool {
    /// Connect a fixed-size pool with a caller-supplied TLS implementation.
    ///
    /// The DSN is intentionally an argument rather than environment authority; callers must
    /// obtain secret material through Wardnet's credential boundary. Passing [`NoTls`] here is
    /// not a production policy decision; the only Wardnet convenience that does so is the
    /// loopback-only integration fixture constructor.
    pub(crate) async fn connect_with_tls<T>(
        dsn: &str,
        pool_size: usize,
        tls: T,
    ) -> PostgresStateResult<Self>
    where
        T: MakeTlsConnect<Socket> + Clone + Send + 'static,
        T::TlsConnect: Send,
        T::Stream: Send + 'static,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        if pool_size == 0 {
            return Err(PostgresStateError::InvalidPoolSize);
        }

        let mut connections = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let (client, connection) = tokio_postgres::connect(dsn, tls.clone()).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            connections.push(Arc::new(Mutex::new(client)));
        }

        Ok(Self {
            inner: Arc::new(PoolInner {
                connections,
                next_connection: AtomicUsize::new(0),
            }),
        })
    }

    /// Connect a plaintext trust fixture only when the parsed DSN is explicitly loopback-only.
    ///
    /// This constructor exists for real PostgreSQL integration tests. It rejects Unix sockets,
    /// remote host names, remote `hostaddr` network targets, implicit hosts, and any SSL mode
    /// other than `disable` so it cannot silently become a production plaintext path.
    pub async fn connect_loopback_test(dsn: &str, pool_size: usize) -> PostgresStateResult<Self> {
        let config = dsn.parse::<Config>()?;
        if config.get_ssl_mode() != SslMode::Disable {
            return Err(PostgresStateError::InvalidLoopbackFixture(
                "sslmode must be disable for the explicit loopback fixture",
            ));
        }
        let hosts = config.get_hosts();
        if hosts.is_empty() || !hosts.iter().all(loopback_host) {
            return Err(PostgresStateError::InvalidLoopbackFixture(
                "every host must resolve syntactically to localhost or a loopback IP",
            ));
        }
        if !config
            .get_hostaddrs()
            .iter()
            .all(|address| address.is_loopback())
        {
            return Err(PostgresStateError::InvalidLoopbackFixture(
                "every hostaddr network target must be a loopback IP",
            ));
        }
        Self::connect_with_tls(dsn, pool_size, NoTls).await
    }

    /// Run one operation inside a transaction whose tenant identity is local to that transaction.
    ///
    /// The connection stays locked from `BEGIN` through `COMMIT`/`ROLLBACK`. Cancellation drops
    /// the scope, which transfers the owned checkout into a rollback task; the mutex therefore
    /// cannot be reacquired until rollback has completed.
    pub async fn with_tenant_transaction<T, F>(
        &self,
        tenant_id: &TenantId,
        operation: F,
    ) -> PostgresStateResult<T>
    where
        T: Send,
        F: for<'client> FnOnce(TenantTransaction<'client>) -> TenantTransactionFuture<'client, T>,
    {
        let connection = self.next_connection();
        let guard = connection.lock_owned().await;
        let scope = ActiveTransaction::begin(guard).await?;
        let tenant_value = tenant_id.as_str();
        scope
            .client()
            .query_one(
                "SELECT set_config('wardnet.tenant_id', $1, true)",
                &[&tenant_value],
            )
            .await?;

        let outcome = {
            let transaction = TenantTransaction {
                client: scope.client(),
            };
            operation(transaction).await
        };

        match outcome {
            Ok(value) => {
                scope.commit().await?;
                Ok(value)
            }
            Err(error) => {
                scope.rollback().await?;
                Err(error)
            }
        }
    }

    /// Atomically publish one reputation-source generation through Wardnet's canonical function.
    ///
    /// The operation is always executed inside a transaction-local tenant context. Callers receive
    /// stable application outcomes rather than PostgreSQL function strings or SQLSTATE details.
    pub async fn publish_reputation_source(
        &self,
        tenant_id: &TenantId,
        publication: &ReputationSourcePublication,
    ) -> PostgresStateResult<PublicationOutcome> {
        let tenant_value = tenant_id.as_str().to_owned();
        let publication = publication.clone();
        self.with_tenant_transaction(tenant_id, move |transaction| {
            Box::pin(async move {
                transaction
                    .publish_reputation_source(tenant_value, publication)
                    .await
            })
        })
        .await
    }

    /// Inspect only backend identity and tenant context outside a transaction.
    ///
    /// This is deliberately not a general raw-query escape hatch. It exists to prove pooled
    /// connection hygiene without granting unbound application state reads.
    pub async fn probe_unbound_context(&self) -> PostgresStateResult<UnboundContextProbe> {
        let connection = self.next_connection();
        let client = connection.lock_owned().await;
        let row = client
            .query_one(
                "SELECT pg_backend_pid()::bigint, NULLIF(current_setting('wardnet.tenant_id', true), '')",
                &[],
            )
            .await?;
        Ok(UnboundContextProbe {
            backend_pid: row.try_get(0)?,
            tenant_id: row.try_get(1)?,
        })
    }

    fn next_connection(&self) -> Arc<Mutex<Client>> {
        let index = self.inner.next_connection.fetch_add(1, Ordering::Relaxed)
            % self.inner.connections.len();
        Arc::clone(&self.inner.connections[index])
    }
}

fn validate_publication_text(raw: &str) -> PostgresStateResult<String> {
    if raw.is_empty() {
        return Err(PostgresStateError::InvalidPublication(
            "text values must be nonempty",
        ));
    }
    if raw != raw.trim() {
        return Err(PostgresStateError::InvalidPublication(
            "text values must not contain leading or trailing whitespace",
        ));
    }
    Ok(raw.to_owned())
}

fn parse_publication_outcome(raw: &str) -> PostgresStateResult<PublicationOutcome> {
    match raw {
        "committed" => Ok(PublicationOutcome::Committed),
        "replay" => Ok(PublicationOutcome::Replay),
        _ => Err(PostgresStateError::InvalidPublicationOutcome),
    }
}

fn map_publication_error(error: tokio_postgres::Error) -> PostgresStateError {
    if error.as_db_error().is_some_and(|database_error| {
        database_error.code().code() == PUBLICATION_CONFLICT_SQLSTATE
            && database_error.message() == PUBLICATION_CONFLICT_MESSAGE
    }) {
        PostgresStateError::PublicationConflict
    } else {
        PostgresStateError::Postgres(error)
    }
}

fn loopback_host(host: &Host) -> bool {
    match host {
        Host::Tcp(host) if host.eq_ignore_ascii_case("localhost") => true,
        Host::Tcp(host) => host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        #[cfg(unix)]
        Host::Unix(_) => false,
    }
}

struct ActiveTransaction {
    client: Option<OwnedMutexGuard<Client>>,
    active: bool,
}

impl ActiveTransaction {
    async fn begin(client: OwnedMutexGuard<Client>) -> PostgresStateResult<Self> {
        client.batch_execute("BEGIN").await?;
        Ok(Self {
            client: Some(client),
            active: true,
        })
    }

    fn client(&self) -> &Client {
        self.client
            .as_deref()
            .expect("active PostgreSQL transaction must own its checkout")
    }

    async fn commit(mut self) -> PostgresStateResult<()> {
        self.client().batch_execute("COMMIT").await?;
        self.active = false;
        self.client.take();
        Ok(())
    }

    async fn rollback(mut self) -> PostgresStateResult<()> {
        self.client().batch_execute("ROLLBACK").await?;
        self.active = false;
        self.client.take();
        Ok(())
    }
}

impl Drop for ActiveTransaction {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let Some(client) = self.client.take() else {
            return;
        };
        tokio::spawn(async move {
            let _ = client.batch_execute("ROLLBACK").await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_publication() -> PostgresStateResult<ReputationSourcePublication> {
        ReputationSourcePublication::new(
            "urlhaus",
            Some("generation-8"),
            "generation-9",
            9,
            1_700_000_009,
            "provenance-generation-9",
            "snapshot-generation-9",
            "complete-generation-9",
            "lifecycle-generation-9",
        )
    }

    #[test]
    fn publication_command_accepts_canonical_values() {
        assert!(valid_publication().is_ok());
    }

    #[test]
    fn publication_command_rejects_untrimmed_or_empty_text() {
        assert!(matches!(
            ReputationSourcePublication::new(
                " urlhaus",
                None,
                "generation-9",
                9,
                1,
                "provenance",
                "snapshot",
                "complete",
                "lifecycle",
            ),
            Err(PostgresStateError::InvalidPublication(_))
        ));
        assert!(matches!(
            ReputationSourcePublication::new(
                "urlhaus",
                Some(""),
                "generation-9",
                9,
                1,
                "provenance",
                "snapshot",
                "complete",
                "lifecycle",
            ),
            Err(PostgresStateError::InvalidPublication(_))
        ));
    }

    #[test]
    fn publication_command_rejects_negative_ordinals_and_times() {
        assert!(matches!(
            ReputationSourcePublication::new(
                "urlhaus",
                None,
                "generation-9",
                -1,
                1,
                "provenance",
                "snapshot",
                "complete",
                "lifecycle",
            ),
            Err(PostgresStateError::InvalidPublication(_))
        ));
        assert!(matches!(
            ReputationSourcePublication::new(
                "urlhaus",
                None,
                "generation-9",
                9,
                -1,
                "provenance",
                "snapshot",
                "complete",
                "lifecycle",
            ),
            Err(PostgresStateError::InvalidPublication(_))
        ));
    }

    #[test]
    fn publication_outcomes_fail_closed() {
        assert_eq!(
            parse_publication_outcome("committed").expect("committed outcome must parse"),
            PublicationOutcome::Committed
        );
        assert_eq!(
            parse_publication_outcome("replay").expect("replay outcome must parse"),
            PublicationOutcome::Replay
        );
        assert!(matches!(
            parse_publication_outcome("unexpected"),
            Err(PostgresStateError::InvalidPublicationOutcome)
        ));
    }
}
