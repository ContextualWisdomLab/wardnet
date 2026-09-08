use std::io::Write;
use std::process::{Command, Output, Stdio};
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

    let name = format!("wardnet-postgres-recovery-gap-{}", std::process::id());
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

#[test]
fn recovery_does_not_expose_runtime_publication_while_old_evidence_is_missing() {
    let Some(container) = start_postgres() else {
        return;
    };
    for (path, label) in [
        (GENERATION_MIGRATION_PATH, "apply migration 0001"),
        (ADMISSION_MIGRATION_PATH, "apply migration 0002"),
        (PUBLICATION_MIGRATION_PATH, "apply migration 0003"),
        (ROLE_INSTALLER_PATH, "install publication capability roles"),
    ] {
        let sql = std::fs::read_to_string(path).expect("PostgreSQL fixture must exist");
        assert_success(psql(&container, &sql), label);
    }

    assert_success(
        psql(
            &container,
            "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-gap', true); SELECT public.wardnet_publish_reputation_source_generation('tenant-gap', 'source-a', NULL, 'generation-1', 1, 1, 'provenance-1', 'evidence-1', 'complete-1', 'lifecycle-1'); COMMIT; RESET ROLE;",
        ),
        "publish generation one before recovery",
    );
    let rollback = std::fs::read_to_string(PUBLICATION_ROLLBACK_PATH)
        .expect("publication rollback migration must exist");
    let migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("publication migration must exist");
    assert_success(
        psql(&container, &rollback),
        "roll publication boundary back",
    );
    assert_success(psql(&container, &migration), "reapply publication boundary");

    assert_success(
        run_docker(
            &[
                "exec",
                &container.name,
                "mkdir",
                "-p",
                "/tmp/wardnet-recovery-gap",
            ],
            None,
        ),
        "create recovery staging directory",
    );
    for path in [ROLE_INSTALLER_PATH, RECOVERY_PATH] {
        let destination = format!("{}:/tmp/wardnet-recovery-gap/", container.name);
        assert_success(
            run_docker(&["cp", path, &destination], None),
            "stage recovery asset",
        );
    }
    assert_success(
        psql_file(
            &container,
            "/tmp/wardnet-recovery-gap/reputation_state_recovery.sql",
        ),
        "run publication authority recovery",
    );

    let bypass = psql(
        &container,
        "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-gap', true); SELECT public.wardnet_publish_reputation_source_generation('tenant-gap', 'source-a', NULL, 'generation-2', 2, 2, 'provenance-2', 'evidence-2', 'complete-2', 'lifecycle-2'); COMMIT; RESET ROLE;",
    );
    assert!(
        !bypass.status.success(),
        "recovery must not expose runtime publication while rollback-removed publication evidence/head is still missing; otherwise NULL expected-prior can skip the lost last-known-good generation"
    );
}
