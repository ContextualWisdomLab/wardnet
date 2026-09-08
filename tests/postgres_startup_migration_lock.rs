use std::io::Write;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const MIGRATION_ENTRYPOINT_PATH: &str = "deploy/postgresql/reputation_state_migrate.sql";
const MIGRATION_ENTRYPOINT_IN_CONTAINER: &str =
    "/wardnet/deploy/postgresql/reputation_state_migrate.sql";
const VERSION_ROLLBACK_IN_CONTAINER: &str =
    "/wardnet/migrations/0004_reputation_state_schema_version.down.sql";
const MIGRATION_LOCK_KEY: &str = "wardnet.reputation_state.schema_migration";
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

    let name = format!("wardnet-postgres-startup-migration-{}", std::process::id());
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

fn stage_migration_tree(container: &PostgresContainer) {
    assert_success(
        run_docker(&["exec", &container.name, "mkdir", "-p", "/wardnet"], None),
        "create migration fixture root",
    );
    let destination = format!("{}:/wardnet/", container.name);
    assert_success(
        run_docker(&["cp", "migrations", &destination], None),
        "stage canonical migrations",
    );
    assert_success(
        run_docker(&["cp", "deploy", &destination], None),
        "stage deployment migration assets",
    );
}

fn spawn_lock_holder(container: &PostgresContainer) -> Child {
    let sql = format!(
        "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended('{MIGRATION_LOCK_KEY}', 0)); SELECT pg_catalog.pg_sleep(3);"
    );
    Command::new("docker")
        .args([
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
            "-c",
            &sql,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("migration-lock holder must start")
}

fn wait_for_advisory_lock(container: &PostgresContainer) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let locks = assert_success(
            psql(
                container,
                "SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND granted;",
            ),
            "inspect advisory migration lock",
        );
        if locks.trim().parse::<u64>().unwrap_or_default() > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "migration advisory lock was not acquired within 10 seconds"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn startup_migration_serializes_and_fails_closed_on_future_schema() {
    std::fs::read_to_string(MIGRATION_ENTRYPOINT_PATH)
        .expect("canonical PostgreSQL startup migration entrypoint must exist");
    let Some(container) = start_postgres() else {
        return;
    };
    stage_migration_tree(&container);

    let mut holder = spawn_lock_holder(&container);
    wait_for_advisory_lock(&container);
    let contended = psql(
        &container,
        &format!("SET lock_timeout = '250ms';\n\\ir {MIGRATION_ENTRYPOINT_IN_CONTAINER}\n"),
    );
    assert!(
        !contended.status.success(),
        "a competing startup migrator must wait on the canonical advisory lock before schema mutation"
    );
    let contended_diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&contended.stdout),
        String::from_utf8_lossy(&contended.stderr)
    );
    assert!(
        contended_diagnostic.contains("lock timeout"),
        "contended migration must fail at the injected advisory-lock timeout"
    );
    let empty_after_contention = assert_success(
        psql(
            &container,
            "SELECT to_regclass('public.reputation_source_generation') IS NULL;",
        ),
        "inspect schema after contended startup",
    );
    assert_eq!(empty_after_contention.trim(), "t");
    assert!(
        holder.wait().expect("lock holder must finish").success(),
        "migration lock holder must exit cleanly"
    );

    assert_success(
        psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER),
        "migrate empty database to current supported schema",
    );
    let current = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.reputation_source_generation') IS NOT NULL, to_regprocedure('public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)') IS NOT NULL, to_regclass('public.reputation_source_publication') IS NOT NULL, to_regclass('public.reputation_source_publication_head') IS NOT NULL, to_regprocedure('public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)') IS NOT NULL, (SELECT schema_version = 4 FROM public.wardnet_schema_version WHERE component = 'reputation_state'));",
        ),
        "inspect current migrated schema",
    );
    assert_eq!(current.trim(), "t:t:t:t:t:t");

    assert_success(
        psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER),
        "replay startup migration at current version",
    );

    assert_success(
        psql_file(&container, VERSION_ROLLBACK_IN_CONTAINER),
        "roll schema-version layer back to supported 0003 boundary",
    );
    let previous = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', to_regclass('public.wardnet_schema_version') IS NULL, to_regclass('public.reputation_source_publication') IS NOT NULL, to_regprocedure('public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)') IS NOT NULL);",
        ),
        "inspect supported previous schema boundary",
    );
    assert_eq!(previous.trim(), "t:t:t");
    assert_success(
        psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER),
        "upgrade supported 0003 boundary to current version",
    );

    assert_success(
        psql(
            &container,
            "UPDATE public.wardnet_schema_version SET schema_version = 5 WHERE component = 'reputation_state';",
        ),
        "inject incompatible future schema version",
    );
    let future = psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER);
    assert!(
        !future.status.success(),
        "startup must fail closed on a durable schema version newer than this binary supports"
    );
    let future_diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&future.stdout),
        String::from_utf8_lossy(&future.stderr)
    );
    assert!(
        future_diagnostic.contains("newer than supported Wardnet schema version"),
        "future-schema refusal must identify the compatibility boundary"
    );
    let future_preserved = assert_success(
        psql(
            &container,
            "SELECT schema_version FROM public.wardnet_schema_version WHERE component = 'reputation_state';",
        ),
        "inspect refused future schema version",
    );
    assert_eq!(future_preserved.trim(), "5");
}
