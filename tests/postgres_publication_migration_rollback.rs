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
        "wardnet-postgres-publication-rollback-{}-{sequence}",
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

fn publish_generation_one(container: &PostgresContainer) {
    let result = assert_success(
        psql(
            container,
            "BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-a', true); SELECT public.wardnet_publish_reputation_source_generation('tenant-a', 'feed-a', NULL, 'generation-1', 1, 1, 'provenance-1', 'evidence-1', 'complete-1', 'lifecycle-1'); COMMIT;",
        ),
        "publish source generation through migration 0003",
    );
    assert!(
        result.lines().any(|line| line.trim() == "committed"),
        "publication must commit through the restored migration boundary"
    );
}

#[test]
fn publication_migration_can_roll_back_to_admission_and_reapply_without_losing_generation_history() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let publication_migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("source-publication migration must exist");
    let publication_rollback = std::fs::read_to_string(PUBLICATION_ROLLBACK_PATH)
        .expect("source-publication rollback migration must exist");
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
    assert_success(
        psql(&container, &publication_migration),
        "apply migration 0003",
    );
    publish_generation_one(&container);

    assert_success(
        psql(&container, &publication_rollback),
        "roll migration 0003 back to admission schema",
    );

    let rollback_state = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.reputation_source_generation') IS NOT NULL, to_regclass('public.reputation_source_publication') IS NULL, to_regclass('public.reputation_source_publication_head') IS NULL, to_regprocedure('public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)') IS NULL, to_regprocedure('public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)') IS NOT NULL, (SELECT count(*) = 1 FROM public.reputation_source_generation WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a' AND source_generation = 'generation-1' AND source_generation_ordinal = 1));",
        ),
        "inspect rolled-back publication schema",
    );
    assert_eq!(
        rollback_state.trim(),
        "t:t:t:t:t:t",
        "rollback must remove only publication-owned schema while preserving admitted generation history"
    );

    assert_success(
        psql(&container, &publication_rollback),
        "replay publication rollback safely",
    );
    assert_success(
        psql(&container, &publication_migration),
        "reapply migration 0003 after rollback",
    );
    publish_generation_one(&container);

    let restored_state = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.reputation_source_publication') IS NOT NULL, to_regclass('public.reputation_source_publication_head') IS NOT NULL, to_regprocedure('public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)') IS NOT NULL, (SELECT count(*) = 1 FROM public.reputation_source_generation WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a'), (SELECT count(*) = 1 FROM public.reputation_source_publication WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a'), (SELECT count(*) = 1 FROM public.reputation_source_publication_head WHERE tenant_id = 'tenant-a' AND source_id = 'feed-a'));",
        ),
        "inspect reapplied publication schema",
    );
    assert_eq!(
        restored_state.trim(),
        "t:t:t:t:t:t",
        "reapply must restore publication authority without duplicating preserved generation history"
    );
}
