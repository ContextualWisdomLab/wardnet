use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const MIGRATION_ENTRYPOINT_IN_CONTAINER: &str =
    "/wardnet/deploy/postgresql/reputation_state_migrate.sql";
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

fn run_docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
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
    run_docker(&[
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
        sql,
    ])
}

fn psql_file(container: &PostgresContainer, path: &str) -> Output {
    run_docker(&[
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
    ])
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

    let name = format!("wardnet-postgres-startup-rls-{}", std::process::id());
    assert_success(
        run_docker(&[
            "run",
            "--rm",
            "-d",
            "--name",
            &name,
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            POSTGRES_IMAGE,
        ]),
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
        let logs = run_docker(&["logs", &container.name]);
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
        run_docker(&["exec", &container.name, "mkdir", "-p", "/wardnet"]),
        "create migration fixture root",
    );
    let destination = format!("{}:/wardnet/", container.name);
    assert_success(
        run_docker(&["cp", "migrations", &destination]),
        "stage canonical migrations",
    );
    assert_success(
        run_docker(&["cp", "deploy", &destination]),
        "stage deployment migration assets",
    );
}

#[test]
fn startup_migration_rejects_current_version_without_forced_rls() {
    let Some(container) = start_postgres() else {
        return;
    };
    stage_migration_tree(&container);

    assert_success(
        psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER),
        "migrate empty database to current supported schema",
    );
    assert_success(
        psql(
            &container,
            "ALTER TABLE public.reputation_source_generation NO FORCE ROW LEVEL SECURITY;",
        ),
        "inject current-version forced-RLS drift",
    );
    let injected = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', relrowsecurity, relforcerowsecurity, (SELECT schema_version = 5 FROM public.wardnet_schema_version WHERE component = 'reputation_state')) FROM pg_catalog.pg_class WHERE oid = 'public.reputation_source_generation'::regclass;",
        ),
        "inspect injected forced-RLS drift",
    );
    assert_eq!(injected.trim(), "t:f:t");

    let refused = psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER);
    assert!(
        !refused.status.success(),
        "startup must fail closed when a migration-owned tenant table loses FORCE ROW LEVEL SECURITY"
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        diagnostic.contains("partial reputation-state schema"),
        "forced-RLS drift must be classified as partial schema requiring diagnosis"
    );
    let preserved = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', relrowsecurity, relforcerowsecurity, (SELECT schema_version = 5 FROM public.wardnet_schema_version WHERE component = 'reputation_state')) FROM pg_catalog.pg_class WHERE oid = 'public.reputation_source_generation'::regclass;",
        ),
        "inspect refused forced-RLS drift",
    );
    assert_eq!(preserved.trim(), "t:f:t");
}
