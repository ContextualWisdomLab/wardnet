use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
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
    let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "wardnet-postgres-publication-{}-{sequence}",
        std::process::id()
    );
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

fn publish_sql(
    expected_prior: Option<&str>,
    generation: &str,
    ordinal: i64,
    completed_at: i64,
    provenance_ref: &str,
    evidence_snapshot_ref: &str,
    completeness_ref: &str,
    producer_lifecycle_ref: &str,
) -> String {
    let expected_prior = expected_prior
        .map(|value| format!("'{value}'"))
        .unwrap_or_else(|| "NULL".to_owned());
    format!(
        "SELECT wardnet_publish_reputation_source_generation('tenant-a', 'urlhaus', {expected_prior}, '{generation}', {ordinal}, {completed_at}, '{provenance_ref}', '{evidence_snapshot_ref}', '{completeness_ref}', '{producer_lifecycle_ref}')"
    )
}

fn prepare_publication_database() -> Option<PostgresContainer> {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let publication_migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH).expect(
        "atomic source-publication migration must exist before PostgreSQL authority is enabled",
    );
    if !require_docker_or_skip() {
        return None;
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
        psql(&container, &generation_migration),
        "apply generation schema migration",
    );
    assert_success(
        psql(&container, &admission_migration),
        "apply generation admission migration",
    );
    assert_success(
        psql(&container, &publication_migration),
        "apply atomic publication migration",
    );
    assert_success(
        psql(
            &container,
            "GRANT SELECT, INSERT ON reputation_source_generation TO wardnet_runtime_test; GRANT EXECUTE ON FUNCTION wardnet_admit_reputation_source_generation(text, text, text, bigint, bigint, text) TO wardnet_runtime_test; GRANT SELECT, INSERT ON reputation_source_publication TO wardnet_runtime_test; GRANT SELECT, INSERT, UPDATE ON reputation_source_publication_head TO wardnet_runtime_test; GRANT EXECUTE ON FUNCTION wardnet_publish_reputation_source_generation(text, text, text, text, bigint, bigint, text, text, text, text) TO wardnet_runtime_test;",
        ),
        "grant bounded publication privileges",
    );
    Some(container)
}

#[test]
fn source_generation_publication_is_atomic_idempotent_and_cas_bound() {
    let Some(container) = prepare_publication_database() else {
        return;
    };

    let first = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    None,
                    "generation-8",
                    8,
                    100,
                    "receipt-8",
                    "snapshot-8",
                    "complete-8",
                    "lifecycle-8",
                ),
            ),
        ),
        "first complete source publication must commit",
    );
    assert_eq!(first.trim(), "committed");

    let replay = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    None,
                    "generation-8",
                    8,
                    100,
                    "receipt-8",
                    "snapshot-8",
                    "complete-8",
                    "lifecycle-8",
                ),
            ),
        ),
        "exact committed publication must replay idempotently",
    );
    assert_eq!(replay.trim(), "replay");

    let second = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    Some("generation-8"),
                    "generation-9",
                    9,
                    200,
                    "receipt-9",
                    "snapshot-9",
                    "complete-9",
                    "lifecycle-9",
                ),
            ),
        ),
        "CAS-bound successor publication must commit",
    );
    assert_eq!(second.trim(), "committed");

    let head = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT source_generation FROM reputation_source_publication_head WHERE source_id = 'urlhaus'",
            ),
        ),
        "read current last-known-good publication",
    );
    assert_eq!(head.trim(), "generation-9");

    let injected_failure = assert_failure(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    Some("generation-9"),
                    "generation-10",
                    10,
                    300,
                    "receipt-10",
                    "snapshot-10",
                    "",
                    "lifecycle-10",
                ),
            ),
        ),
        "invalid completeness proof must roll back binding and publication together",
    );
    assert!(
        injected_failure.contains("completeness_ref"),
        "failed publication must identify the invalid non-secret field, got: {injected_failure}"
    );

    let failed_binding_count = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT count(*) FROM reputation_source_generation WHERE source_id = 'urlhaus' AND source_generation = 'generation-10'",
            ),
        ),
        "failed publication must not leave a generation binding",
    );
    assert_eq!(failed_binding_count.trim(), "0");

    let preserved_head = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT source_generation FROM reputation_source_publication_head WHERE source_id = 'urlhaus'",
            ),
        ),
        "failed publication must preserve last-known-good head",
    );
    assert_eq!(preserved_head.trim(), "generation-9");

    let stale_cas = assert_failure(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    Some("generation-8"),
                    "generation-10",
                    10,
                    300,
                    "receipt-10",
                    "snapshot-10",
                    "complete-10",
                    "lifecycle-10",
                ),
            ),
        ),
        "stale prior generation must fail before changing authoritative state",
    );
    assert!(
        stale_cas.contains("reputation_source_publication_conflict"),
        "stale CAS must use the stable publication conflict class, got: {stale_cas}"
    );

    let (writer_a, writer_b) = thread::scope(|scope| {
        let writer_a = scope.spawn(|| {
            psql(
                &container,
                &tenant_sql(
                    "tenant-a",
                    &publish_sql(
                        Some("generation-9"),
                        "generation-10-a",
                        10,
                        400,
                        "receipt-10-a",
                        "snapshot-10-a",
                        "complete-10-a",
                        "lifecycle-10-a",
                    ),
                ),
            )
        });
        let writer_b = scope.spawn(|| {
            psql(
                &container,
                &tenant_sql(
                    "tenant-a",
                    &publish_sql(
                        Some("generation-9"),
                        "generation-10-b",
                        11,
                        401,
                        "receipt-10-b",
                        "snapshot-10-b",
                        "complete-10-b",
                        "lifecycle-10-b",
                    ),
                ),
            )
        });
        (
            writer_a.join().expect("writer A thread must finish"),
            writer_b.join().expect("writer B thread must finish"),
        )
    });

    let outcomes = [writer_a, writer_b];
    let successes = outcomes
        .iter()
        .filter(|output| output.status.success())
        .count();
    let conflicts = outcomes
        .iter()
        .filter(|output| {
            !output.status.success()
                && String::from_utf8_lossy(&output.stderr)
                    .contains("reputation_source_publication_conflict")
        })
        .count();
    assert_eq!(
        successes, 1,
        "exactly one competing publication must commit"
    );
    assert_eq!(
        conflicts, 1,
        "exactly one competing publication must fail with the stable CAS conflict"
    );

    let generation_count = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT count(*) FROM reputation_source_generation WHERE source_id = 'urlhaus'",
            ),
        ),
        "losing writer must not leave a generation binding",
    );
    assert_eq!(generation_count.trim(), "3");

    let publication_count = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT count(*) FROM reputation_source_publication WHERE source_id = 'urlhaus'",
            ),
        ),
        "losing writer must not leave a publication record",
    );
    assert_eq!(publication_count.trim(), "3");
}

#[test]
fn source_publication_rejects_unused_but_regressive_ordinal() {
    let Some(container) = prepare_publication_database() else {
        return;
    };

    let first = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    None,
                    "generation-9",
                    9,
                    200,
                    "receipt-9",
                    "snapshot-9",
                    "complete-9",
                    "lifecycle-9",
                ),
            ),
        ),
        "initial publication must commit",
    );
    assert_eq!(first.trim(), "committed");

    let regression = assert_failure(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                &publish_sql(
                    Some("generation-9"),
                    "generation-10",
                    8,
                    300,
                    "receipt-10",
                    "snapshot-10",
                    "complete-10",
                    "lifecycle-10",
                ),
            ),
        ),
        "unused but regressive ordinal must not advance publication authority",
    );
    assert!(
        regression.contains("reputation_source_publication_conflict"),
        "ordinal regression must use the stable publication conflict class, got: {regression}"
    );

    let head = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT source_generation || ':' || source_generation_ordinal FROM reputation_source_publication_head WHERE source_id = 'urlhaus'",
            ),
        ),
        "regressive publication must preserve last-known-good head",
    );
    assert_eq!(head.trim(), "generation-9:9");

    let rejected_binding = assert_success(
        psql(
            &container,
            &tenant_sql(
                "tenant-a",
                "SELECT count(*) FROM reputation_source_generation WHERE source_id = 'urlhaus' AND source_generation = 'generation-10'",
            ),
        ),
        "regressive publication must not leave a generation binding",
    );
    assert_eq!(rejected_binding.trim(), "0");
}
