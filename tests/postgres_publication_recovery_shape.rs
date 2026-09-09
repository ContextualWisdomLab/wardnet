use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const AUDIT_ROLLBACK_PATH: &str = "migrations/0005_reputation_source_publication_audit.down.sql";
const VERSION_ROLLBACK_PATH: &str = "migrations/0004_reputation_state_schema_version.down.sql";
const PUBLICATION_ROLLBACK_PATH: &str = "migrations/0003_reputation_source_publication.down.sql";
const RECOVERY_PATH_IN_CONTAINER: &str = "/wardnet/deploy/postgresql/reputation_state_recovery.sql";
const FINAL_STARTUP_MARKER: &str = "PostgreSQL init process complete; ready for start up.";

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

fn start_postgres() -> Option<PostgresContainer> {
    let available = Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !available {
        if std::env::var_os("CI").is_some() {
            panic!("Docker is required for PostgreSQL integration tests in CI");
        }
        eprintln!("skipping PostgreSQL integration test because Docker is unavailable");
        return None;
    }

    let name = format!("wardnet-postgres-recovery-shape-{}", std::process::id());
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
        let ready = Command::new("docker")
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
            .is_ok_and(|status| status.success());
        let logs = run_docker(&["logs", &container.name], None);
        let started = logs.status.success()
            && (String::from_utf8_lossy(&logs.stdout).contains(FINAL_STARTUP_MARKER)
                || String::from_utf8_lossy(&logs.stderr).contains(FINAL_STARTUP_MARKER));
        if ready && started {
            return Some(container);
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL 18.4 final server did not become ready within 60 seconds"
        );
        thread::sleep(Duration::from_millis(500));
    }
}

fn stage_recovery_tree(container: &PostgresContainer) {
    assert_success(
        run_docker(&["exec", &container.name, "mkdir", "-p", "/wardnet"], None),
        "create recovery fixture root",
    );
    let destination = format!("{}:/wardnet/", container.name);
    assert_success(
        run_docker(&["cp", "migrations", &destination], None),
        "stage migrations for recovery",
    );
    assert_success(
        run_docker(&["cp", "deploy", &destination], None),
        "stage deployment recovery assets",
    );
}

#[test]
fn recovery_accepts_only_complete_supported_schema_shapes_and_is_restartable() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("generation migration must exist");
    let admission_migration =
        std::fs::read_to_string(ADMISSION_MIGRATION_PATH).expect("admission migration must exist");
    let audit_rollback =
        std::fs::read_to_string(AUDIT_ROLLBACK_PATH).expect("audit rollback must exist");
    let version_rollback =
        std::fs::read_to_string(VERSION_ROLLBACK_PATH).expect("version rollback must exist");
    let publication_rollback = std::fs::read_to_string(PUBLICATION_ROLLBACK_PATH)
        .expect("publication rollback must exist");
    let Some(container) = start_postgres() else {
        return;
    };

    assert_success(
        psql(&container, &generation_migration),
        "apply migration 0001",
    );
    assert_success(
        psql(&container, &admission_migration),
        "apply migration 0002",
    );
    stage_recovery_tree(&container);

    assert_success(
        psql_file(&container, RECOVERY_PATH_IN_CONTAINER),
        "recover from the complete 0002 boundary",
    );
    let recovered_from_0002 = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.reputation_source_publication') IS NOT NULL, to_regclass('public.reputation_source_publication_head') IS NOT NULL, to_regprocedure('public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)') IS NOT NULL, to_regclass('public.reputation_source_publication_audit') IS NOT NULL, (SELECT schema_version = 5 FROM public.wardnet_schema_version WHERE component = 'reputation_state'), (SELECT r.rolname = 'wardnet_state_owner' FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid = p.proowner WHERE p.oid = 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'::regprocedure), has_function_privilege('wardnet_runtime', 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'));",
        ),
        "inspect recovered current boundary",
    );
    assert_eq!(recovered_from_0002.trim(), "t:t:t:t:t:t:t");

    assert_success(
        psql_file(&container, RECOVERY_PATH_IN_CONTAINER),
        "replay recovery from an already complete current boundary",
    );

    assert_success(psql(&container, &audit_rollback), "roll version 5 back to version 4");
    assert_success(
        psql(&container, &version_rollback),
        "roll version 4 back to complete 0003",
    );
    assert_success(
        psql(&container, &publication_rollback),
        "return to the supported 0002 schema boundary",
    );
    assert_success(
        psql(
            &container,
            "CREATE TABLE public.reputation_source_publication (partial_marker bigint PRIMARY KEY);",
        ),
        "inject an unsupported partial 0003 shape",
    );

    let partial = psql_file(&container, RECOVERY_PATH_IN_CONTAINER);
    assert!(
        !partial.status.success(),
        "recovery must refuse a partial publication schema rather than speculatively normalizing it"
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&partial.stdout),
        String::from_utf8_lossy(&partial.stderr)
    );
    assert!(
        diagnostic.contains("partial publication schema requires diagnosis"),
        "partial-shape refusal must give an actionable recovery diagnostic"
    );
    let partial_preserved = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.reputation_source_publication') IS NOT NULL, to_regclass('public.reputation_source_publication_head') IS NULL, to_regprocedure('public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)') IS NULL);",
        ),
        "inspect refused partial recovery state",
    );
    assert_eq!(
        partial_preserved.trim(),
        "t:t:t",
        "refusal must leave the unsupported partial schema untouched for diagnosis"
    );
}
