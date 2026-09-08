use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";

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

fn assert_failure(output: Output, context: &str) -> String {
    assert!(
        !output.status.success(),
        "{context} unexpectedly succeeded\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8(output.stderr).expect("command stderr must be UTF-8")
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

fn start_postgres() -> PostgresContainer {
    let name = format!("wardnet-postgres-generation-{}", std::process::id());
    let output = run_docker(
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
    );
    assert_success(output, "start PostgreSQL 18.4 container");
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
        if status.success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL 18.4 container did not become ready within 60 seconds"
        );
        thread::sleep(Duration::from_millis(500));
    }
    container
}

fn tenant_sql(tenant_id: &str, statement: &str) -> String {
    format!(
        "SET ROLE wardnet_runtime_test; BEGIN; SET LOCAL wardnet.tenant_id = '{tenant_id}'; {statement}; COMMIT;"
    )
}

#[test]
fn source_generation_history_is_tenant_scoped_and_replay_safe() {
    let migration = std::fs::read_to_string(MIGRATION_PATH).expect(
        "PostgreSQL source-generation migration must exist before production authority is enabled",
    );
    if !require_docker_or_skip() {
        return;
    }

    let container = start_postgres();
    assert_success(
        psql(
            &container,
            "CREATE ROLE wardnet_runtime_test NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;",
        ),
        "create non-owner runtime role",
    );
    assert_success(
        psql(&container, &migration),
        "apply source-generation migration",
    );
    assert_success(
        psql(
            &container,
            "GRANT SELECT, INSERT, UPDATE, DELETE ON reputation_source_generation TO wardnet_runtime_test;",
        ),
        "grant bounded runtime table privileges",
    );

    assert_failure(
        psql(
            &container,
            "SET ROLE wardnet_runtime_test; INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'generation-8', 8, 100, 'receipt-8');",
        ),
        "missing tenant context must fail closed below the HTTP layer",
    );

    assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'generation-8', 8, 100, 'receipt-8')",
            ),
        ),
        "admit generation 8 at ordinal 8",
    );
    assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'generation-9', 9, 200, 'receipt-9')",
            ),
        ),
        "admit generation 9 at ordinal 9",
    );

    let replay_error = assert_failure(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'generation-8', 10, 300, 'receipt-replay')",
            ),
        ),
        "historically consumed generation token must not bind to a newer ordinal",
    );
    assert!(
        replay_error.contains("reputation_source_generation_token_key"),
        "ABA replay must fail on the generation-token uniqueness invariant, got: {replay_error}"
    );

    let ordinal_error = assert_failure(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'other-token', 9, 300, 'receipt-collision')",
            ),
        ),
        "one ordinal must not bind to two generation tokens",
    );
    assert!(
        ordinal_error.contains("reputation_source_generation_ordinal_key"),
        "ordinal collision must fail on the ordinal uniqueness invariant, got: {ordinal_error}"
    );

    let cross_tenant_error = assert_failure(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-b', 'urlhaus', 'generation-8', 8, 100, 'receipt-b')",
            ),
        ),
        "runtime role must not write another tenant",
    );
    assert!(
        cross_tenant_error.contains("row-level security"),
        "cross-tenant write must be rejected by PostgreSQL RLS, got: {cross_tenant_error}"
    );

    assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-b",
                "INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-b', 'urlhaus', 'generation-8', 8, 100, 'receipt-b')",
            ),
        ),
        "same source generation identity may exist in a different tenant",
    );

    let tenant_a_count = assert_success(
        psql(
            &container,
            "SET ROLE wardnet_runtime_test; BEGIN; SET LOCAL wardnet.tenant_id = 'tenant-a'; SELECT count(*) FROM reputation_source_generation; COMMIT;",
        ),
        "read tenant-a rows through RLS",
    );
    assert_eq!(tenant_a_count.trim(), "2");

    let tenant_b_count = assert_success(
        psql(
            &container,
            "SET ROLE wardnet_runtime_test; BEGIN; SET LOCAL wardnet.tenant_id = 'tenant-b'; SELECT count(*) FROM reputation_source_generation; COMMIT;",
        ),
        "read tenant-b rows through RLS",
    );
    assert_eq!(tenant_b_count.trim(), "1");

    assert_failure(
        psql(
            &container,
            "SET ROLE wardnet_runtime_test; BEGIN; SET LOCAL wardnet.tenant_id = 'tenant-a'; SELECT count(*) FROM reputation_source_generation; COMMIT; INSERT INTO reputation_source_generation (tenant_id, source_id, source_generation, source_generation_ordinal, completed_at_unix, provenance_ref) VALUES ('tenant-a', 'urlhaus', 'generation-10', 10, 400, 'receipt-10');",
        ),
        "transaction-local tenant context must clear before connection reuse",
    );
}
