use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const PUBLICATION_ROLLBACK_PATH: &str = "migrations/0003_reputation_source_publication.down.sql";
const ROLE_INSTALLER_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const RECOVERY_PATH: &str = "deploy/postgresql/reputation_state_recovery.sql";
const FINAL_STARTUP_MARKER: &str = "PostgreSQL init process complete; ready for start up.";
static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PostgresContainer {
    name: String,
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

fn psql_file(container: &PostgresContainer, path: &str) -> Output {
    run_docker(
        &[
            "exec",
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
            "-f",
            path,
        ],
        None,
    )
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

fn final_startup_announced(container: &PostgresContainer) -> bool {
    let logs = run_docker(&["logs", &container.name], None);
    logs.status.success()
        && (String::from_utf8_lossy(&logs.stdout).contains(FINAL_STARTUP_MARKER)
            || String::from_utf8_lossy(&logs.stderr).contains(FINAL_STARTUP_MARKER))
}

fn start_postgres() -> Option<PostgresContainer> {
    if !docker_available() {
        if std::env::var_os("CI").is_some() {
            panic!("Docker is required for PostgreSQL integration tests in CI");
        }
        eprintln!("skipping PostgreSQL integration test because Docker is unavailable");
        return None;
    }

    let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "wardnet-postgres-publication-recovery-{}-{sequence}",
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
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                POSTGRES_IMAGE,
            ],
            None,
        ),
        "start PostgreSQL 18.4 container",
    );
    let container = PostgresContainer { name };

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = Command::new("docker")
            .args([
                "exec",
                &container.name,
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
        if final_startup_announced(&container) && status.success() {
            return Some(container);
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL 18.4 final server did not become ready within 60 seconds"
        );
        thread::sleep(Duration::from_millis(500));
    }
}

fn publish_as_runtime(
    container: &PostgresContainer,
    expected_prior: Option<&str>,
    generation: &str,
    ordinal: i64,
) -> Output {
    let prior = expected_prior
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "NULL".to_string());
    let sql = format!(
        "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-a', true); SELECT public.wardnet_publish_reputation_source_generation('tenant-a', 'feed-a', {prior}, '{generation}', {ordinal}, {ordinal}, 'provenance-{ordinal}', 'evidence-{ordinal}', 'complete-{ordinal}', 'lifecycle-{ordinal}'); COMMIT; RESET ROLE;"
    );
    psql(container, &sql)
}

#[test]
fn publication_recovery_reconverges_the_existing_least_privilege_role_installer() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let publication_migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("source-publication migration must exist");
    let publication_rollback = std::fs::read_to_string(PUBLICATION_ROLLBACK_PATH)
        .expect("source-publication rollback migration must exist");
    let role_installer = std::fs::read_to_string(ROLE_INSTALLER_PATH)
        .expect("reputation state role installer must exist");
    let Some(container) = start_postgres() else {
        return;
    };

    for (migration, label) in [
        (&generation_migration, "apply migration 0001"),
        (&admission_migration, "apply migration 0002"),
        (&publication_migration, "apply migration 0003"),
        (&role_installer, "install least-privilege reputation roles"),
    ] {
        assert_success(psql(&container, migration), label);
    }
    assert_success(
        publish_as_runtime(&container, None, "generation-1", 1),
        "publish generation one through runtime capability",
    );

    assert_success(
        psql(&container, &publication_rollback),
        "roll publication migration back",
    );
    assert_success(
        psql(&container, &publication_migration),
        "reapply publication migration before role recovery",
    );

    let unrecovered = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT r.rolname = 'wardnet_state_owner' FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid = p.proowner WHERE n.nspname = 'public' AND p.proname = 'wardnet_publish_reputation_source_generation'), has_function_privilege('wardnet_runtime', 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'), (SELECT count(*) = 1 FROM public.reputation_source_generation WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a' AND source_generation = 'generation-1'));",
        ),
        "inspect publication authority immediately after schema reapply",
    );
    assert_eq!(
        unrecovered.trim(),
        "f:f:t",
        "schema reapply must preserve generation history but must not masquerade as restored least-privilege runtime authority"
    );
    assert!(
        !publish_as_runtime(&container, Some("generation-1"), "generation-2", 2)
            .status
            .success(),
        "runtime publication must remain unavailable before role reconvergence"
    );

    let owner_transfer_marker = "ALTER FUNCTION public.wardnet_publish_reputation_source_generation(";
    assert!(
        role_installer.contains(owner_transfer_marker),
        "failure injection marker must track the publication owner transfer"
    );
    let failing_role_recovery = role_installer.replacen(
        owner_transfer_marker,
        "SELECT 1 / 0;\n\nALTER FUNCTION public.wardnet_publish_reputation_source_generation(",
        1,
    );
    let failed_recovery = psql(&container, &failing_role_recovery);
    assert!(
        !failed_recovery.status.success()
            && String::from_utf8_lossy(&failed_recovery.stderr).contains("division by zero"),
        "mid-recovery failure must be the injected semantic failure"
    );
    let still_unrecovered = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT r.rolname <> 'wardnet_state_owner' FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid = p.proowner WHERE n.nspname = 'public' AND p.proname = 'wardnet_publish_reputation_source_generation'), NOT has_function_privilege('wardnet_runtime', 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'));",
        ),
        "inspect authority after failed role recovery",
    );
    assert_eq!(
        still_unrecovered.trim(),
        "t:t",
        "failed role reconvergence must not be reportable as recovered authority"
    );

    assert_success(
        run_docker(&["exec", &container.name, "mkdir", "-p", "/tmp/wardnet-recovery"], None),
        "create recovery staging directory",
    );
    let installer_target = format!(
        "{}:/tmp/wardnet-recovery/reputation_state_roles.sql",
        container.name
    );
    assert_success(
        run_docker(&["cp", ROLE_INSTALLER_PATH, &installer_target], None),
        "stage canonical reputation role installer",
    );
    let recovery_target = format!(
        "{}:/tmp/wardnet-recovery/reputation_state_recovery.sql",
        container.name
    );
    assert_success(
        run_docker(&["cp", RECOVERY_PATH, &recovery_target], None),
        "stage executable publication recovery boundary",
    );

    assert_success(
        psql_file(
            &container,
            "/tmp/wardnet-recovery/reputation_state_recovery.sql",
        ),
        "reconverge publication authority after migration recovery",
    );

    let recovered = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT r.rolname = 'wardnet_state_owner' FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid = p.proowner WHERE n.nspname = 'public' AND p.proname = 'wardnet_publish_reputation_source_generation'), (SELECT p.prosecdef FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname = 'wardnet_publish_reputation_source_generation'), has_function_privilege('wardnet_runtime', 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'), NOT has_function_privilege('wardnet_runtime', 'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)', 'EXECUTE'), NOT has_table_privilege('wardnet_runtime', 'public.reputation_source_generation', 'INSERT'), NOT has_table_privilege('wardnet_runtime', 'public.reputation_source_publication', 'INSERT'), NOT has_table_privilege('wardnet_runtime', 'public.reputation_source_publication_head', 'UPDATE'), NOT has_schema_privilege('wardnet_state_owner', 'public', 'CREATE'));",
        ),
        "inspect restored least-privilege publication capability",
    );
    assert_eq!(
        recovered.trim(),
        "t:t:t:t:t:t:t:t",
        "recovery must restore only the bounded outer publication capability"
    );

    assert_success(
        publish_as_runtime(&container, Some("generation-1"), "generation-2", 2),
        "publish generation two through restored runtime capability",
    );
    assert_success(
        psql_file(
            &container,
            "/tmp/wardnet-recovery/reputation_state_recovery.sql",
        ),
        "replay role recovery idempotently",
    );
    let final_state = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT count(*) = 2 FROM public.reputation_source_generation WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a'), (SELECT count(*) = 1 FROM public.reputation_source_generation WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a' AND source_generation = 'generation-1' AND source_generation_ordinal = 1), (SELECT source_generation = 'generation-2' AND source_generation_ordinal = 2 FROM public.reputation_source_publication_head WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a'));",
        ),
        "inspect preserved history after idempotent recovery replay",
    );
    assert_eq!(
        final_state.trim(),
        "t:t:t",
        "recovery must preserve original generation identity and advance last-known-good only through the outer capability"
    );
}
