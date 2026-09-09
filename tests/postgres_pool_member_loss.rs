use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waf_ids_ai_soc::postgres_state::{
    PostgresTenantPool, PublicationAuditContext, PublicationOutcome, ReputationSourcePublication,
    TenantId,
};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const VERSION_MIGRATION_PATH: &str = "migrations/0004_reputation_state_schema_version.sql";
const AUDIT_MIGRATION_PATH: &str = "migrations/0005_reputation_source_publication_audit.sql";
const ROLE_INSTALLER_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const PRINCIPAL_MAPPER_PATH: &str = "deploy/postgresql/reputation_state_runtime_principal.sql";
const RUNTIME_PRINCIPAL: &str = "wardnet_pool_loss_app";
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
        "wardnet-postgres-pool-loss-{}-{sequence}",
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

fn publication() -> ReputationSourcePublication {
    ReputationSourcePublication::new(
        "urlhaus",
        None,
        "generation-8",
        8,
        1_700_000_008,
        "provenance-generation-8",
        "snapshot-generation-8",
        "complete-generation-8",
        "lifecycle-generation-8",
    )
    .expect("publication fixture must validate")
    .with_audit_context(
        PublicationAuditContext::new("subject:pool-loss", "decision:publish-generation-8")
            .expect("audit fixture must validate"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_repository_uses_surviving_pool_member_after_one_backend_is_lost() {
    let Some(container) = prepare_database() else {
        return;
    };
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        container.host_port
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 2)
        .await
        .expect("two-member loopback pool must connect");

    let first_pid = pool
        .probe_unbound_context()
        .await
        .expect("first pool member must be reachable")
        .backend_pid();
    let second_pid = pool
        .probe_unbound_context()
        .await
        .expect("second pool member must be reachable")
        .backend_pid();
    assert_ne!(
        first_pid, second_pid,
        "fixture requires two physical backends"
    );

    let terminated = assert_success(
        psql(
            &container,
            &format!("SELECT pg_terminate_backend({first_pid});"),
        ),
        "terminate one pooled backend",
    );
    assert_eq!(terminated.trim(), "t");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let tenant = TenantId::parse("tenant-a").expect("tenant identity must validate");
    let outcome = pool
        .publish_reputation_source(&tenant, &publication())
        .await
        .expect(
            "one lost pool member must not make the typed repository unavailable while another member is healthy",
        );
    assert_eq!(outcome, PublicationOutcome::Committed);

    let current = pool
        .current_reputation_source_publication(&tenant, "urlhaus")
        .await
        .expect("the surviving member must read the committed aggregate")
        .expect("the committed aggregate must exist");
    assert_eq!(current.source_generation(), "generation-8");
    assert_eq!(current.actor_subject_id(), "subject:pool-loss");
    assert_eq!(current.decision_id(), "decision:publish-generation-8");

    let counts = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT count(*) FROM public.reputation_source_generation), (SELECT count(*) FROM public.reputation_source_publication), (SELECT count(*) FROM public.reputation_source_publication_head), (SELECT count(*) FROM public.reputation_source_publication_audit));",
        ),
        "inspect publication residue after degraded-pool write",
    );
    assert_eq!(
        counts.trim(),
        "1:1:1:1",
        "healthy-member failover must expose exactly one complete attributable publication"
    );
}
