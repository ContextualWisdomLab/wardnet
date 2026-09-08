use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const ROLE_INSTALL_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
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
        "wardnet-postgres-deployment-atomicity-{}-{sequence}",
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
        let final_startup = final_startup_announced(&container);
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
        if final_startup && status.success() {
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
fn deployment_role_install_rolls_back_all_privileges_on_midflight_failure() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let publication_migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("source-publication migration must exist");
    let role_install = std::fs::read_to_string(ROLE_INSTALL_PATH)
        .expect("production PostgreSQL role-install contract must exist");
    let Some(container) = start_postgres() else {
        return;
    };

    assert_success(
        psql(&container, &generation_migration),
        "apply generation schema migration",
    );
    assert_success(
        psql(&container, &admission_migration),
        "apply generation admission migration",
    );
    assert_success(
        psql(&container, &publication_migration),
        "apply publication migration",
    );

    assert_success(
        psql(
            &container,
            "CREATE FUNCTION public.wardnet_fail_role_install() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF tg_tag = 'ALTER FUNCTION' THEN RAISE EXCEPTION 'wardnet_injected_role_install_failure'; END IF; END; $$; CREATE EVENT TRIGGER wardnet_fail_role_install ON ddl_command_start WHEN TAG IN ('ALTER FUNCTION') EXECUTE FUNCTION public.wardnet_fail_role_install();",
        ),
        "install deterministic mid-flight role-install failure",
    );

    let failed_install = psql(&container, &role_install);
    assert!(
        !failed_install.status.success(),
        "injected ALTER FUNCTION failure must abort role installation"
    );
    assert!(
        String::from_utf8_lossy(&failed_install.stderr)
            .contains("wardnet_injected_role_install_failure"),
        "role installation must fail at the injected ownership-transfer boundary"
    );

    assert_success(
        psql(
            &container,
            "DROP EVENT TRIGGER wardnet_fail_role_install; DROP FUNCTION public.wardnet_fail_role_install();",
        ),
        "remove deterministic failure injection",
    );

    let residual_authority = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_state_owner'), CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_state_owner') THEN has_schema_privilege('wardnet_state_owner', 'public', 'CREATE') ELSE false END, EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wardnet_runtime'));",
        ),
        "inspect authority after failed role installation",
    );
    assert_eq!(
        residual_authority.trim(),
        "f:f:f",
        "a failed installer must not strand capability roles or temporary schema CREATE authority"
    );
}
