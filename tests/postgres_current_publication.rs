use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waf_ids_ai_soc::postgres_state::{
    PostgresStateError, PostgresTenantPool, PublicationAuditContext, PublicationOutcome,
    ReputationSourcePublication, TenantId,
};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const RUNTIME_PRINCIPAL: &str = "wardnet_current_read_app";
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
        "wardnet-postgres-current-publication-{}-{sequence}",
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
        "resolve PostgreSQL port",
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
        (
            "migrations/0001_reputation_source_generation.sql",
            "apply generation migration",
        ),
        (
            "migrations/0002_reputation_source_generation_admission.sql",
            "apply admission migration",
        ),
        (
            "migrations/0003_reputation_source_publication.sql",
            "apply publication migration",
        ),
        (
            "migrations/0004_reputation_state_schema_version.sql",
            "apply schema-version migration",
        ),
        (
            "migrations/0005_reputation_source_publication_audit.sql",
            "apply publication-audit migration",
        ),
        (
            "deploy/postgresql/reputation_state_roles.sql",
            "install capability roles",
        ),
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
    let mapper =
        std::fs::read_to_string("deploy/postgresql/reputation_state_runtime_principal.sql")
            .expect("runtime principal mapper must exist");
    assert_success(
        psql_with_runtime_principal(&container, &mapper),
        "map external LOGIN to bounded runtime capability",
    );
    Some(container)
}

fn publication(
    expected_prior: Option<&str>,
    generation: &str,
    ordinal: i64,
) -> ReputationSourcePublication {
    ReputationSourcePublication::new(
        "urlhaus",
        expected_prior,
        generation,
        ordinal,
        1_700_000_000 + ordinal,
        format!("provenance-{generation}"),
        format!("snapshot-{generation}"),
        format!("complete-{generation}"),
        format!("lifecycle-{generation}"),
    )
    .expect("fixture publication must validate")
    .with_audit_context(
        PublicationAuditContext::new(
            "subject:current-publication-test",
            format!("decision:{generation}"),
        )
        .expect("fixture audit context must validate"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_read_returns_only_complete_last_known_good_publication() {
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
    let tenant_a = TenantId::parse("tenant-a").expect("tenant A must validate");
    let tenant_b = TenantId::parse("tenant-b").expect("tenant B must validate");

    assert_eq!(
        pool.publish_reputation_source(&tenant_a, &publication(None, "generation-8", 8))
            .await
            .expect("generation 8 must publish"),
        PublicationOutcome::Committed
    );
    assert_eq!(
        pool.publish_reputation_source(
            &tenant_a,
            &publication(Some("generation-8"), "generation-9", 9),
        )
        .await
        .expect("generation 9 must publish"),
        PublicationOutcome::Committed
    );

    assert_success(
        psql(
            &container,
            "BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-a', true); SELECT public.wardnet_admit_reputation_source_generation('tenant-a', 'urlhaus', 'generation-10', 10, 1700000010, 'provenance-generation-10'); COMMIT;",
        ),
        "admit generation 10 without publishing it",
    );

    let current = pool
        .current_reputation_source_publication(&tenant_a, "urlhaus")
        .await
        .expect("complete current publication must be readable")
        .expect("tenant A must have a current publication");
    assert_eq!(current.source_id(), "urlhaus");
    assert_eq!(current.prior_source_generation(), Some("generation-8"));
    assert_eq!(current.source_generation(), "generation-9");
    assert_eq!(current.source_generation_ordinal(), 9);
    assert_eq!(current.completed_at_unix(), 1_700_000_009);
    assert_eq!(current.provenance_ref(), "provenance-generation-9");
    assert_eq!(current.evidence_snapshot_ref(), "snapshot-generation-9");
    assert_eq!(current.completeness_ref(), "complete-generation-9");
    assert_eq!(current.producer_lifecycle_ref(), "lifecycle-generation-9");
    assert_eq!(
        current.actor_subject_id(),
        "subject:current-publication-test"
    );
    assert_eq!(current.decision_id(), "decision:generation-9");

    assert!(
        pool.current_reputation_source_publication(&tenant_b, "urlhaus")
            .await
            .expect("cross-tenant read must fail closed as absence")
            .is_none(),
        "tenant B must not observe tenant A publication state"
    );
    assert!(
        pool.current_reputation_source_publication(&tenant_a, "never-published")
            .await
            .expect("missing source must return typed absence")
            .is_none()
    );

    let blank = pool
        .current_reputation_source_publication(&tenant_a, " \t")
        .await;
    assert!(
        matches!(blank, Err(PostgresStateError::InvalidPublication(_))),
        "blank source identity must fail before state work: {blank:?}"
    );

    assert_success(
        psql(
            &container,
            "DELETE FROM public.reputation_source_publication_audit WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus' AND source_generation = 'generation-9';",
        ),
        "simulate missing audit evidence under setup authority",
    );
    let incomplete = pool
        .current_reputation_source_publication(&tenant_a, "urlhaus")
        .await;
    assert!(
        matches!(incomplete, Err(PostgresStateError::IncompletePublication)),
        "head without complete publication/audit evidence must fail closed: {incomplete:?}"
    );
}
