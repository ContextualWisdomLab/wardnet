use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::Barrier;
use tokio_postgres::{Client, NoTls};
use waf_ids_ai_soc::postgres_state::{
    PostgresStateError, PostgresTenantPool, PublicationAuditContext, PublicationOutcome,
    ReputationSourcePublication, TenantId,
};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const VERSION_MIGRATION_PATH: &str = "migrations/0004_reputation_state_schema_version.sql";
const AUDIT_MIGRATION_PATH: &str = "migrations/0005_reputation_source_publication_audit.sql";
const ROLE_INSTALLER_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const PRINCIPAL_MAPPER_PATH: &str = "deploy/postgresql/reputation_state_runtime_principal.sql";
const RUNTIME_PRINCIPAL: &str = "wardnet_divergent_writer_app";
const FINAL_STARTUP_MARKER: &str = "PostgreSQL init process complete; ready for start up.";
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

fn start_postgres() -> Option<PostgresContainer> {
    if !Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        if std::env::var_os("CI").is_some() {
            panic!("Docker is required for PostgreSQL integration tests in CI");
        }
        eprintln!("skipping PostgreSQL integration test because Docker is unavailable");
        return None;
    }

    let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "wardnet-postgres-divergent-writers-{}-{sequence}",
        std::process::id()
    );
    assert_success(
        run_docker(
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
        ),
        "start PostgreSQL 18.4 container",
    );

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
        let logs = run_docker(&["logs", &name], None);
        let final_server_started = logs.status.success()
            && (String::from_utf8_lossy(&logs.stdout).contains(FINAL_STARTUP_MARKER)
                || String::from_utf8_lossy(&logs.stderr).contains(FINAL_STARTUP_MARKER));
        if status.success() && final_server_started {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL 18.4 final server did not become ready within 60 seconds"
        );
        thread::sleep(Duration::from_millis(500));
    }

    let rendered = assert_success(
        run_docker(&["port", &name, "5432/tcp"], None),
        "resolve port",
    );
    let host_port = rendered
        .trim()
        .rsplit(':')
        .next()
        .expect("docker port output must contain a port")
        .parse()
        .expect("published PostgreSQL port must be numeric");
    Some(PostgresContainer { name, host_port })
}

fn prepare_database() -> Option<PostgresContainer> {
    let container = start_postgres()?;
    for (path, context) in [
        (GENERATION_MIGRATION_PATH, "apply generation migration"),
        (ADMISSION_MIGRATION_PATH, "apply admission migration"),
        (PUBLICATION_MIGRATION_PATH, "apply publication migration"),
        (VERSION_MIGRATION_PATH, "apply schema-version migration"),
        (AUDIT_MIGRATION_PATH, "apply publication-audit migration"),
        (ROLE_INSTALLER_PATH, "install capability roles"),
    ] {
        let sql = std::fs::read_to_string(path).expect("PostgreSQL fixture SQL must exist");
        assert_success(psql(&container, &sql), context);
    }
    assert_success(
        psql(
            &container,
            &format!(
                "CREATE ROLE {RUNTIME_PRINCIPAL} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;"
            ),
        ),
        "create externally managed runtime LOGIN",
    );
    let mapper = std::fs::read_to_string(PRINCIPAL_MAPPER_PATH)
        .expect("runtime principal mapper must exist");
    assert_success(
        psql_with_runtime_principal(&container, &mapper),
        "map external LOGIN to bounded runtime capability",
    );
    Some(container)
}

async fn connect_admin(container: &PostgresContainer) -> Client {
    let dsn = format!(
        "host=127.0.0.1 port={} user=postgres dbname=postgres sslmode=disable",
        container.host_port
    );
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("setup authority must connect");
    tokio::spawn(async move {
        connection
            .await
            .expect("setup authority connection must remain healthy");
    });
    client
}

fn publication(
    source_id: &str,
    expected_prior: Option<&str>,
    generation: &str,
    ordinal: i64,
    evidence_marker: &str,
    actor: &str,
    decision: &str,
) -> ReputationSourcePublication {
    ReputationSourcePublication::new(
        source_id,
        expected_prior,
        generation,
        ordinal,
        1_700_000_000 + ordinal,
        format!("provenance-{evidence_marker}"),
        format!("snapshot-{evidence_marker}"),
        format!("complete-{evidence_marker}"),
        format!("lifecycle-{evidence_marker}"),
    )
    .expect("fixture publication must validate")
    .with_audit_context(
        PublicationAuditContext::new(actor, decision).expect("fixture audit context must validate"),
    )
}

async fn publish_baseline(pool: &PostgresTenantPool, tenant: &TenantId, source_id: &str) {
    let baseline = publication(
        source_id,
        None,
        "generation-8",
        8,
        &format!("{source_id}-baseline"),
        "subject:baseline",
        &format!("decision:{source_id}-baseline"),
    );
    assert_eq!(
        pool.publish_reputation_source(tenant, &baseline)
            .await
            .expect("baseline publication must commit"),
        PublicationOutcome::Committed
    );
}

async fn acquire_chain_lock(admin: &Client, tenant: &TenantId, source_id: &str) {
    admin
        .batch_execute("BEGIN")
        .await
        .expect("setup authority must begin synchronization transaction");
    let tenant_id = tenant.as_str();
    admin
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))",
            &[&tenant_id, &source_id],
        )
        .await
        .expect("setup authority must hold the canonical tenant/source publication lock");
}

async fn wait_for_advisory_waiters(admin: &Client, minimum: i64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let row = admin
                .query_one(
                    "SELECT count(*)::bigint FROM pg_stat_activity WHERE usename = $1 AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
                    &[&RUNTIME_PRINCIPAL],
                )
                .await
                .expect("setup authority must inspect PostgreSQL lock waiters");
            let count: i64 = row.get(0);
            if count >= minimum {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime writers must reach the held PostgreSQL advisory lock without sleep-based synchronization");
}

async fn release_chain_lock(admin: &Client) {
    admin
        .batch_execute("COMMIT")
        .await
        .expect("setup authority must release synchronization lock");
}

async fn race_publications(
    admin: &Client,
    pool: &PostgresTenantPool,
    tenant: &TenantId,
    source_id: &str,
    left: ReputationSourcePublication,
    right: ReputationSourcePublication,
) -> (
    Result<PublicationOutcome, PostgresStateError>,
    Result<PublicationOutcome, PostgresStateError>,
) {
    acquire_chain_lock(admin, tenant, source_id).await;

    let barrier = Arc::new(Barrier::new(3));
    let left_task = {
        let pool = pool.clone();
        let tenant = tenant.clone();
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            pool.publish_reputation_source(&tenant, &left).await
        })
    };
    let right_task = {
        let pool = pool.clone();
        let tenant = tenant.clone();
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            pool.publish_reputation_source(&tenant, &right).await
        })
    };

    barrier.wait().await;
    wait_for_advisory_waiters(admin, 2).await;
    release_chain_lock(admin).await;

    (
        left_task.await.expect("left writer task must join"),
        right_task.await.expect("right writer task must join"),
    )
}

fn assert_one_commit_one_conflict(
    left: &Result<PublicationOutcome, PostgresStateError>,
    right: &Result<PublicationOutcome, PostgresStateError>,
) {
    let committed = [left, right]
        .into_iter()
        .filter(|outcome| matches!(outcome, Ok(PublicationOutcome::Committed)))
        .count();
    let conflicts = [left, right]
        .into_iter()
        .filter(|outcome| matches!(outcome, Err(PostgresStateError::PublicationConflict)))
        .count();
    assert_eq!(
        (committed, conflicts),
        (1, 1),
        "divergent writers must settle as exactly one commit and one stable conflict: left={left:?}, right={right:?}"
    );
}

fn assert_one_commit_one_replay(
    left: &Result<PublicationOutcome, PostgresStateError>,
    right: &Result<PublicationOutcome, PostgresStateError>,
) {
    let committed = [left, right]
        .into_iter()
        .filter(|outcome| matches!(outcome, Ok(PublicationOutcome::Committed)))
        .count();
    let replays = [left, right]
        .into_iter()
        .filter(|outcome| matches!(outcome, Ok(PublicationOutcome::Replay)))
        .count();
    assert_eq!(
        (committed, replays),
        (1, 1),
        "byte-identical concurrent writers must settle as one commit and one replay: left={left:?}, right={right:?}"
    );
}

async fn assert_single_candidate_residue(admin: &Client, tenant: &TenantId, source_id: &str) {
    let tenant_id = tenant.as_str();
    let row = admin
        .query_one(
            "SELECT (SELECT count(*)::bigint FROM public.reputation_source_generation WHERE tenant_id = $1 AND source_id = $2 AND source_generation <> 'generation-8'), (SELECT count(*)::bigint FROM public.reputation_source_publication WHERE tenant_id = $1 AND source_id = $2 AND source_generation <> 'generation-8'), (SELECT count(*)::bigint FROM public.reputation_source_publication_audit WHERE tenant_id = $1 AND source_id = $2 AND source_generation <> 'generation-8'), (SELECT count(*)::bigint FROM public.reputation_source_publication_head WHERE tenant_id = $1 AND source_id = $2)",
            &[&tenant_id, &source_id],
        )
        .await
        .expect("setup authority must inspect durable publication residue");
    let generation_count: i64 = row.get(0);
    let publication_count: i64 = row.get(1);
    let audit_count: i64 = row.get(2);
    let head_count: i64 = row.get(3);
    assert_eq!(
        (generation_count, publication_count, audit_count, head_count),
        (1, 1, 1, 1),
        "one candidate transition must leave exactly one generation/publication/audit/head authority tuple"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn divergent_runtime_writers_serialize_one_authoritative_publication_without_global_locking() {
    let Some(container) = prepare_database() else {
        return;
    };
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        container.host_port
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 2)
        .await
        .expect("loopback integration pool must connect");
    let admin = connect_admin(&container).await;
    let tenant_a = TenantId::parse("tenant-a").expect("tenant A must validate");
    let tenant_b = TenantId::parse("tenant-b").expect("tenant B must validate");

    let first = pool
        .probe_unbound_context()
        .await
        .expect("first pooled runtime connection must be observable");
    let second = pool
        .probe_unbound_context()
        .await
        .expect("second pooled runtime connection must be observable");
    assert_ne!(
        first.backend_pid(),
        second.backend_pid(),
        "hostile acceptance requires at least two established physical runtime sessions"
    );
    assert!(first.tenant_id().is_none() && second.tenant_id().is_none());

    let source_same_ordinal = "race-same-ordinal";
    publish_baseline(&pool, &tenant_a, source_same_ordinal).await;
    let left = publication(
        source_same_ordinal,
        Some("generation-8"),
        "generation-9-left",
        9,
        "same-ordinal-left",
        "subject:left",
        "decision:same-ordinal-left",
    );
    let right = publication(
        source_same_ordinal,
        Some("generation-8"),
        "generation-9-right",
        9,
        "same-ordinal-right",
        "subject:right",
        "decision:same-ordinal-right",
    );
    let (left_result, right_result) = race_publications(
        &admin,
        &pool,
        &tenant_a,
        source_same_ordinal,
        left.clone(),
        right.clone(),
    )
    .await;
    assert_one_commit_one_conflict(&left_result, &right_result);
    assert_single_candidate_residue(&admin, &tenant_a, source_same_ordinal).await;
    let current = pool
        .current_reputation_source_publication(&tenant_a, source_same_ordinal)
        .await
        .expect("current publication read must succeed")
        .expect("winning publication must be present");
    let loser = if current.source_generation() == "generation-9-left" {
        &right
    } else {
        assert_eq!(current.source_generation(), "generation-9-right");
        &left
    };
    let loser_retry = pool.publish_reputation_source(&tenant_a, loser).await;
    assert!(
        matches!(loser_retry, Err(PostgresStateError::PublicationConflict)),
        "losing divergent command must remain a stable conflict on explicit retry: {loser_retry:?}"
    );

    let source_same_token = "race-same-token";
    publish_baseline(&pool, &tenant_a, source_same_token).await;
    let left = publication(
        source_same_token,
        Some("generation-8"),
        "generation-9",
        9,
        "same-token-left",
        "subject:left",
        "decision:same-token-left",
    );
    let right = publication(
        source_same_token,
        Some("generation-8"),
        "generation-9",
        9,
        "same-token-right",
        "subject:right",
        "decision:same-token-right",
    );
    let (left_result, right_result) = race_publications(
        &admin,
        &pool,
        &tenant_a,
        source_same_token,
        left.clone(),
        right.clone(),
    )
    .await;
    assert_one_commit_one_conflict(&left_result, &right_result);
    assert_single_candidate_residue(&admin, &tenant_a, source_same_token).await;
    let current = pool
        .current_reputation_source_publication(&tenant_a, source_same_token)
        .await
        .expect("current publication read must succeed")
        .expect("winning publication must be present");
    let loser = if current.provenance_ref() == "provenance-same-token-left" {
        assert_eq!(current.actor_subject_id(), "subject:left");
        &right
    } else {
        assert_eq!(current.provenance_ref(), "provenance-same-token-right");
        assert_eq!(current.actor_subject_id(), "subject:right");
        &left
    };
    let loser_retry = pool.publish_reputation_source(&tenant_a, loser).await;
    assert!(
        matches!(loser_retry, Err(PostgresStateError::PublicationConflict)),
        "losing evidence/attribution variant must not overwrite the winner: {loser_retry:?}"
    );

    let source_different_ordinals = "race-different-ordinals";
    publish_baseline(&pool, &tenant_a, source_different_ordinals).await;
    let left = publication(
        source_different_ordinals,
        Some("generation-8"),
        "generation-9",
        9,
        "different-ordinal-nine",
        "subject:nine",
        "decision:different-ordinal-nine",
    );
    let right = publication(
        source_different_ordinals,
        Some("generation-8"),
        "generation-10",
        10,
        "different-ordinal-ten",
        "subject:ten",
        "decision:different-ordinal-ten",
    );
    let (left_result, right_result) = race_publications(
        &admin,
        &pool,
        &tenant_a,
        source_different_ordinals,
        left.clone(),
        right.clone(),
    )
    .await;
    assert_one_commit_one_conflict(&left_result, &right_result);
    assert_single_candidate_residue(&admin, &tenant_a, source_different_ordinals).await;
    let current = pool
        .current_reputation_source_publication(&tenant_a, source_different_ordinals)
        .await
        .expect("current publication read must succeed")
        .expect("winning publication must be present");
    let loser = if current.source_generation() == "generation-9" {
        &right
    } else {
        assert_eq!(current.source_generation(), "generation-10");
        &left
    };
    let loser_retry = pool.publish_reputation_source(&tenant_a, loser).await;
    assert!(
        matches!(loser_retry, Err(PostgresStateError::PublicationConflict)),
        "a stale divergent writer must remain conflict after the winning head commits: {loser_retry:?}"
    );

    let source_identical = "race-identical";
    publish_baseline(&pool, &tenant_a, source_identical).await;
    let identical = publication(
        source_identical,
        Some("generation-8"),
        "generation-9",
        9,
        "identical",
        "subject:identical",
        "decision:identical",
    );
    let (left_result, right_result) = race_publications(
        &admin,
        &pool,
        &tenant_a,
        source_identical,
        identical.clone(),
        identical,
    )
    .await;
    assert_one_commit_one_replay(&left_result, &right_result);
    assert_single_candidate_residue(&admin, &tenant_a, source_identical).await;

    let source_parallel = "race-tenant-parallel";
    publish_baseline(&pool, &tenant_a, source_parallel).await;
    publish_baseline(&pool, &tenant_b, source_parallel).await;
    acquire_chain_lock(&admin, &tenant_a, source_parallel).await;
    let barrier = Arc::new(Barrier::new(2));
    let tenant_a_task = {
        let pool = pool.clone();
        let tenant = tenant_a.clone();
        let barrier = Arc::clone(&barrier);
        let candidate = publication(
            source_parallel,
            Some("generation-8"),
            "generation-9",
            9,
            "tenant-a",
            "subject:tenant-a",
            "decision:tenant-a",
        );
        tokio::spawn(async move {
            barrier.wait().await;
            pool.publish_reputation_source(&tenant, &candidate).await
        })
    };
    barrier.wait().await;
    wait_for_advisory_waiters(&admin, 1).await;

    let tenant_b_candidate = publication(
        source_parallel,
        Some("generation-8"),
        "generation-9",
        9,
        "tenant-b",
        "subject:tenant-b",
        "decision:tenant-b",
    );
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(5),
            pool.publish_reputation_source(&tenant_b, &tenant_b_candidate),
        )
        .await
        .expect("tenant B must not be globally blocked by tenant A's held chain lock")
        .expect("tenant B publication must succeed"),
        PublicationOutcome::Committed
    );
    release_chain_lock(&admin).await;
    assert_eq!(
        tenant_a_task
            .await
            .expect("tenant A writer task must join")
            .expect("tenant A publication must succeed after its chain lock releases"),
        PublicationOutcome::Committed
    );
    assert_single_candidate_residue(&admin, &tenant_a, source_parallel).await;
    assert_single_candidate_residue(&admin, &tenant_b, source_parallel).await;

    let unbound_a = pool
        .probe_unbound_context()
        .await
        .expect("pooled connection must remain usable after races");
    let unbound_b = pool
        .probe_unbound_context()
        .await
        .expect("second pooled connection must remain usable after races");
    assert!(
        unbound_a.tenant_id().is_none() && unbound_b.tenant_id().is_none(),
        "concurrent publication must not leak tenant context onto reusable runtime sessions"
    );
}
