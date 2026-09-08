use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
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
    if !logs.status.success() {
        return false;
    }
    String::from_utf8_lossy(&logs.stdout).contains(FINAL_STARTUP_MARKER)
        || String::from_utf8_lossy(&logs.stderr).contains(FINAL_STARTUP_MARKER)
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
        "wardnet-postgres-foundation-atomicity-{}-{sequence}",
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

#[test]
fn failed_generation_forward_migration_leaves_no_partial_schema() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let failure_marker = "REVOKE ALL ON TABLE reputation_source_generation FROM PUBLIC;";
    assert!(
        generation_migration.contains(failure_marker),
        "failure injection marker must track the generation table / privilege boundary"
    );
    let failing_generation_migration = generation_migration.replacen(
        failure_marker,
        "SELECT 1 / 0;\n\nREVOKE ALL ON TABLE reputation_source_generation FROM PUBLIC;",
        1,
    );
    let Some(container) = start_postgres() else {
        return;
    };

    let failed_attempt = psql(&container, &failing_generation_migration);
    assert!(
        !failed_attempt.status.success(),
        "injected generation migration failure must abort the forward attempt"
    );
    assert!(
        String::from_utf8_lossy(&failed_attempt.stderr).contains("division by zero"),
        "generation-migration RED must be the injected semantic failure"
    );

    let post_failure_state = assert_success(
        psql(
            &container,
            "SELECT to_regclass('public.reputation_source_generation') IS NULL;",
        ),
        "inspect state after failed migration 0001",
    );
    assert_eq!(
        post_failure_state.trim(),
        "t",
        "failed migration 0001 must roll back the generation table instead of stranding partial schema"
    );

    assert_success(
        psql(&container, &generation_migration),
        "replay migration 0001 cleanly after injected failure",
    );
}

#[test]
fn failed_admission_forward_migration_preserves_generation_schema_without_partial_function() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let failure_marker =
        "REVOKE ALL ON FUNCTION public.wardnet_admit_reputation_source_generation(";
    assert!(
        admission_migration.contains(failure_marker),
        "failure injection marker must track the admission function / privilege boundary"
    );
    let failing_admission_migration = admission_migration.replacen(
        failure_marker,
        "SELECT 1 / 0;\n\nREVOKE ALL ON FUNCTION public.wardnet_admit_reputation_source_generation(",
        1,
    );
    let Some(container) = start_postgres() else {
        return;
    };

    assert_success(
        psql(&container, &generation_migration),
        "apply migration 0001 before admission failure-atomicity test",
    );
    let failed_attempt = psql(&container, &failing_admission_migration);
    assert!(
        !failed_attempt.status.success(),
        "injected admission migration failure must abort the forward attempt"
    );
    assert!(
        String::from_utf8_lossy(&failed_attempt.stderr).contains("division by zero"),
        "admission-migration RED must be the injected semantic failure"
    );

    let post_failure_state = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.reputation_source_generation') IS NOT NULL, to_regprocedure('public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)') IS NULL);",
        ),
        "inspect state after failed migration 0002",
    );
    assert_eq!(
        post_failure_state.trim(),
        "t:t",
        "failed migration 0002 must preserve 0001 while rolling back the partial admission function"
    );

    assert_success(
        psql(&container, &admission_migration),
        "replay migration 0002 cleanly after injected failure",
    );
}
