use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waf_ids_ai_soc::postgres_state::{PostgresStateResult, PostgresTenantPool, TenantId};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const ROLE_INSTALLER_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const PRINCIPAL_MAPPER_PATH: &str = "deploy/postgresql/reputation_state_runtime_principal.sql";
const RUNTIME_PRINCIPAL: &str = "wardnet_app";
static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PostgresContainer {
    name: String,
    host_port: u16,
}

impl Drop for PostgresContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn require_docker_or_skip() -> bool {
    if docker_available() {
        return true;
    }
    if std::env::var_os("CI").is_some() {
        panic!("Docker is required for PostgreSQL integration tests in CI");
    }
    eprintln!("skipping PostgreSQL integration test because Docker is unavailable");
    false
}

fn run_docker(args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new("docker");
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("docker command must start");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("docker stdin must be available")
            .write_all(input.as_bytes())
            .expect("docker stdin must accept SQL");
    }
    child
        .wait_with_output()
        .expect("docker command must finish")
}

fn assert_success(output: Output, context: &str) -> String {
    if !output.status.success() {
        panic!(
            "{context} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("command output must be UTF-8")
}

fn psql(container: &PostgresContainer, sql: &str) -> Output {
    run_docker(
        &[
            "exec",
            "-i",
            &container.name,
            "psql",
            "-X",
            "-q",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "postgres",
        ],
        Some(sql),
    )
}

fn psql_with_runtime_principal(container: &PostgresContainer, sql: &str) -> Output {
    run_docker(
        &[
            "exec",
            "-i",
            &container.name,
            "psql",
            "-X",
            "-q",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            &format!("wardnet_runtime_principal={RUNTIME_PRINCIPAL}"),
            "-U",
            "postgres",
            "-d",
            "postgres",
        ],
        Some(sql),
    )
}

fn published_port(name: &str) -> u16 {
    let output = run_docker(&["port", name, "5432/tcp"], None);
    let rendered = assert_success(output, "resolve published PostgreSQL port");
    rendered
        .trim()
        .rsplit(':')
        .next()
        .expect("docker port output must contain a port")
        .parse()
        .expect("published PostgreSQL port must be numeric")
}

fn start_postgres() -> PostgresContainer {
    let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "wardnet-postgres-tenant-context-{}-{sequence}",
        std::process::id()
    );
    let output = run_docker(
        &[
            "run",
            "--rm",
            "-d",
            "--name",
            &name,
            "-p",
            "127.0.0.1::5432",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            POSTGRES_IMAGE,
        ],
        None,
    );
    assert_success(output, "start PostgreSQL 18.4 container");

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = Command::new("docker")
            .args([
                "exec",
                &name,
                "pg_isready",
                "-U",
                "postgres",
                "-d",
                "postgres",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("pg_isready command must start");
        if status.success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL 18.4 container did not become ready within 60 seconds"
        );
        thread::sleep(Duration::from_millis(500));
    }

    let host_port = published_port(&name);
    PostgresContainer { name, host_port }
}

fn prepare_database() -> Option<PostgresContainer> {
    if !require_docker_or_skip() {
        return None;
    }

    let generation = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("generation migration must exist");
    let admission = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("generation admission migration must exist");
    let publication = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("publication migration must exist");
    let roles = std::fs::read_to_string(ROLE_INSTALLER_PATH)
        .expect("least-privilege role installer must exist");
    let principal_mapper = std::fs::read_to_string(PRINCIPAL_MAPPER_PATH)
        .expect("runtime principal mapper must exist");

    let container = start_postgres();
    assert_success(psql(&container, &generation), "apply generation migration");
    assert_success(psql(&container, &admission), "apply admission migration");
    assert_success(
        psql(&container, &publication),
        "apply publication migration",
    );
    assert_success(psql(&container, &roles), "install capability roles");
    assert_success(
        psql(
            &container,
            &format!(
                "CREATE ROLE {RUNTIME_PRINCIPAL} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;"
            ),
        ),
        "create externally managed ordinary LOGIN fixture",
    );
    assert_success(
        psql_with_runtime_principal(&container, &principal_mapper),
        "map external LOGIN to wardnet_runtime",
    );

    assert_success(
        psql(
            &container,
            "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'generation-a1', 1, 100, 'receipt-a1'), ('tenant-b', 'urlhaus', 'generation-b1', 1, 100, 'receipt-b1');",
        ),
        "seed two tenant generation rows under setup authority",
    );

    Some(container)
}

#[test]
fn tenant_identity_is_bounded_before_database_work() {
    assert!(TenantId::parse("").is_err());
    assert!(TenantId::parse(" \t\n").is_err());
    assert!(TenantId::parse("x".repeat(257)).is_err());

    let hostile = "tenant-a'; RESET ALL; SELECT pg_sleep(30); --";
    assert_eq!(
        TenantId::parse(hostile)
            .expect("SQL metacharacters are opaque tenant identity data")
            .as_str(),
        hostile
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pooled_tenant_context_is_transaction_local_and_cross_tenant_fail_closed() {
    let Some(container) = prepare_database() else {
        return;
    };
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        container.host_port
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 1)
        .await
        .expect("loopback trust fixture must connect");

    let initial = pool
        .probe_unbound_context()
        .await
        .expect("an unbound checkout must be inspectable without exposing raw state queries");
    assert_eq!(initial.tenant_id(), None);

    let tenant_a = TenantId::parse("tenant-a").expect("tenant-a must validate");
    let committed = pool
        .with_tenant_transaction(&tenant_a, |tx| {
            Box::pin(async move {
                let pid = tx.query_scalar_i64("SELECT pg_backend_pid()::bigint").await?;
                let current = tx
                    .query_scalar_text("SELECT current_setting('wardnet.tenant_id', true)")
                    .await?;
                let own_rows = tx
                    .query_scalar_i64("SELECT count(*)::bigint FROM reputation_source_generation")
                    .await?;
                let other_rows = tx
                    .query_scalar_i64(
                        "SELECT count(*)::bigint FROM reputation_source_generation WHERE tenant_id = 'tenant-b'",
                    )
                    .await?;
                let publication = tx
                    .query_scalar_text(
                        "SELECT wardnet_publish_reputation_source_generation('tenant-a', 'urlhaus', NULL, 'generation-a1', 1, 100, 'receipt-a1', 'snapshot-a1', 'complete-a1', 'lifecycle-a1')",
                    )
                    .await?;
                Ok((pid, current, own_rows, other_rows, publication))
            })
        })
        .await
        .expect("tenant-a transaction must commit");
    assert_eq!(committed.1, "tenant-a");
    assert_eq!(committed.2, 1);
    assert_eq!(committed.3, 0);
    assert_eq!(committed.4, "committed");

    let after_commit = pool
        .probe_unbound_context()
        .await
        .expect("same pooled connection must be safe after commit");
    assert_eq!(after_commit.backend_pid(), committed.0);
    assert_eq!(after_commit.tenant_id(), None);

    let cross_tenant = pool
        .with_tenant_transaction(&tenant_a, |tx| {
            Box::pin(async move {
                tx.query_scalar_text(
                    "SELECT wardnet_publish_reputation_source_generation('tenant-b', 'urlhaus', NULL, 'generation-b1', 1, 100, 'receipt-b1', 'snapshot-b1', 'complete-b1', 'lifecycle-b1')",
                )
                .await
            })
        })
        .await;
    assert!(
        cross_tenant.is_err(),
        "tenant-a transaction must not publish tenant-b state"
    );

    let after_denied_operation = pool
        .probe_unbound_context()
        .await
        .expect("failed operation must roll back before pool return");
    assert_eq!(after_denied_operation.backend_pid(), committed.0);
    assert_eq!(after_denied_operation.tenant_id(), None);

    let injected_error = pool
        .with_tenant_transaction(&tenant_a, |tx| {
            Box::pin(async move {
                tx.query_scalar_i64("SELECT 1 / 0::bigint").await?;
                Ok(())
            })
        })
        .await;
    assert!(
        injected_error.is_err(),
        "operation error must abort the transaction"
    );

    let after_error = pool
        .probe_unbound_context()
        .await
        .expect("errored transaction must not leak tenant authority");
    assert_eq!(after_error.backend_pid(), committed.0);
    assert_eq!(after_error.tenant_id(), None);

    let tenant_b = TenantId::parse("tenant-b").expect("tenant-b must validate");
    let tenant_b_result = pool
        .with_tenant_transaction(&tenant_b, |tx| {
            Box::pin(async move {
                Ok((
                    tx.query_scalar_i64("SELECT pg_backend_pid()::bigint")
                        .await?,
                    tx.query_scalar_text("SELECT current_setting('wardnet.tenant_id', true)")
                        .await?,
                    tx.query_scalar_i64(
                        "SELECT count(*)::bigint FROM reputation_source_generation",
                    )
                    .await?,
                ))
            })
        })
        .await
        .expect("tenant-b must bind independently after connection reuse");
    assert_eq!(tenant_b_result.0, committed.0);
    assert_eq!(tenant_b_result.1, "tenant-b");
    assert_eq!(tenant_b_result.2, 1);

    let hostile = TenantId::parse("tenant-a'; RESET ALL; --")
        .expect("metacharacters must remain opaque identity data");
    let hostile_result = pool
        .with_tenant_transaction(&hostile, |tx| {
            Box::pin(async move {
                Ok((
                    tx.query_scalar_text("SELECT current_setting('wardnet.tenant_id', true)")
                        .await?,
                    tx.query_scalar_i64(
                        "SELECT count(*)::bigint FROM reputation_source_generation",
                    )
                    .await?,
                ))
            })
        })
        .await
        .expect("parameter-bound hostile identity must not become SQL");
    assert_eq!(hostile_result.0, hostile.as_str());
    assert_eq!(hostile_result.1, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_transaction_rolls_back_before_connection_reuse() {
    let Some(container) = prepare_database() else {
        return;
    };
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        container.host_port
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 1)
        .await
        .expect("loopback trust fixture must connect");
    let tenant_a = TenantId::parse("tenant-a").expect("tenant-a must validate");
    let task_pool = pool.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();

    let task = tokio::spawn(async move {
        task_pool
            .with_tenant_transaction(&tenant_a, |tx| {
                Box::pin(async move {
                    let pid = tx
                        .query_scalar_i64("SELECT pg_backend_pid()::bigint")
                        .await?;
                    let _ = started_tx.send(pid);
                    std::future::pending::<PostgresStateResult<()>>().await
                })
            })
            .await
    });

    let active_pid = started_rx
        .await
        .expect("transaction must bind before cancellation");
    task.abort();
    let cancelled = task
        .await
        .expect_err("aborted transaction task must not complete");
    assert!(cancelled.is_cancelled());

    let after_cancel = pool
        .probe_unbound_context()
        .await
        .expect("cancelled transaction must roll back before the checkout is reused");
    assert_eq!(after_cancel.backend_pid(), active_pid);
    assert_eq!(after_cancel.tenant_id(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_pooled_transactions_keep_tenant_context_independent() {
    let Some(container) = prepare_database() else {
        return;
    };
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        container.host_port
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 2)
        .await
        .expect("two-connection loopback pool must connect");
    let tenant_a = TenantId::parse("tenant-a").expect("tenant-a must validate");
    let tenant_b = TenantId::parse("tenant-b").expect("tenant-b must validate");

    let a_pool = pool.clone();
    let b_pool = pool.clone();
    let a = async move {
        a_pool
            .with_tenant_transaction(&tenant_a, |tx| {
                Box::pin(async move {
                    Ok((
                        tx.query_scalar_text("SELECT current_setting('wardnet.tenant_id', true)")
                            .await?,
                        tx.query_scalar_i64(
                            "SELECT count(*)::bigint FROM reputation_source_generation",
                        )
                        .await?,
                    ))
                })
            })
            .await
    };
    let b = async move {
        b_pool
            .with_tenant_transaction(&tenant_b, |tx| {
                Box::pin(async move {
                    Ok((
                        tx.query_scalar_text("SELECT current_setting('wardnet.tenant_id', true)")
                            .await?,
                        tx.query_scalar_i64(
                            "SELECT count(*)::bigint FROM reputation_source_generation",
                        )
                        .await?,
                    ))
                })
            })
            .await
    };

    let (a, b) = tokio::join!(a, b);
    let a = a.expect("tenant-a concurrent transaction must succeed");
    let b = b.expect("tenant-b concurrent transaction must succeed");
    assert_eq!(a, ("tenant-a".to_owned(), 1));
    assert_eq!(b, ("tenant-b".to_owned(), 1));
}
