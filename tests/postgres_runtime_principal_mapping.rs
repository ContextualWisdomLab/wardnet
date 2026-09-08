use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const MIGRATION_ENTRYPOINT_IN_CONTAINER: &str =
    "/wardnet/deploy/postgresql/reputation_state_migrate.sql";
const ROLE_INSTALLER_IN_CONTAINER: &str =
    "/wardnet/deploy/postgresql/reputation_state_roles.sql";
const PRINCIPAL_MAPPER_IN_CONTAINER: &str =
    "/wardnet/deploy/postgresql/reputation_state_runtime_principal.sql";
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

fn map_runtime_principal(container: &PostgresContainer, principal: &str) -> Output {
    let variable = format!("wardnet_runtime_principal={principal}");
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
        "-v",
        &variable,
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-f",
        PRINCIPAL_MAPPER_IN_CONTAINER,
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

    let name = format!("wardnet-postgres-runtime-principal-{}", std::process::id());
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

fn stage_deployment_tree(container: &PostgresContainer) {
    assert_success(
        run_docker(&["exec", &container.name, "mkdir", "-p", "/wardnet"]),
        "create deployment fixture root",
    );
    let destination = format!("{}:/wardnet/", container.name);
    assert_success(
        run_docker(&["cp", "migrations", &destination]),
        "stage canonical migrations",
    );
    assert_success(
        run_docker(&["cp", "deploy", &destination]),
        "stage deployment artifacts",
    );
}

#[test]
fn runtime_principal_mapping_is_external_identity_least_privilege_and_injection_safe() {
    let Some(container) = start_postgres() else {
        return;
    };
    stage_deployment_tree(&container);
    assert_success(
        psql_file(&container, MIGRATION_ENTRYPOINT_IN_CONTAINER),
        "migrate empty database to current supported schema",
    );
    assert_success(
        psql_file(&container, ROLE_INSTALLER_IN_CONTAINER),
        "install Wardnet capability roles",
    );

    assert_success(
        psql(
            &container,
            "CREATE ROLE wardnet_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS NOREPLICATION;",
        ),
        "create externally managed synthetic application login",
    );
    let before = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', pg_has_role('wardnet_app', 'wardnet_runtime', 'member'), pg_has_role('wardnet_app', 'wardnet_state_owner', 'member'), has_table_privilege('wardnet_app', 'public.reputation_source_generation', 'SELECT'), has_table_privilege('wardnet_app', 'public.reputation_source_generation', 'INSERT'), has_function_privilege('wardnet_app', 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'), has_function_privilege('wardnet_app', 'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)', 'EXECUTE'));",
        ),
        "inspect unmapped application login",
    );
    assert_eq!(before.trim(), "f:f:f:f:f:f");

    assert_success(
        map_runtime_principal(&container, "wardnet_app"),
        "map externally managed application login to bounded runtime capability",
    );
    assert_success(
        map_runtime_principal(&container, "wardnet_app"),
        "replay application principal mapping idempotently",
    );
    let after = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', pg_has_role('wardnet_app', 'wardnet_runtime', 'member'), pg_has_role('wardnet_app', 'wardnet_state_owner', 'member'), has_table_privilege('wardnet_app', 'public.reputation_source_generation', 'SELECT'), has_table_privilege('wardnet_app', 'public.reputation_source_generation', 'INSERT'), has_function_privilege('wardnet_app', 'public.wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'), has_function_privilege('wardnet_app', 'public.wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)', 'EXECUTE'), (SELECT count(*) FROM pg_catalog.pg_auth_members membership JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member WHERE granted_role.rolname = 'wardnet_runtime' AND member_role.rolname = 'wardnet_app'));",
        ),
        "inspect mapped application login",
    );
    assert_eq!(after.trim(), "t:f:t:f:t:f:1");

    assert_success(
        psql(
            &container,
            "CREATE ROLE wardnet_privileged LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT BYPASSRLS NOREPLICATION;",
        ),
        "create privileged synthetic login",
    );
    let privileged = map_runtime_principal(&container, "wardnet_privileged");
    assert!(
        !privileged.status.success(),
        "BYPASSRLS principal must fail closed rather than inherit Wardnet runtime authority"
    );
    let privileged_membership = assert_success(
        psql(
            &container,
            "SELECT pg_has_role('wardnet_privileged', 'wardnet_runtime', 'member');",
        ),
        "inspect rejected privileged principal",
    );
    assert_eq!(privileged_membership.trim(), "f");

    let hostile = "wardnet_hostile; CREATE ROLE wardnet_injected";
    assert_success(
        psql(
            &container,
            "CREATE ROLE \"wardnet_hostile; CREATE ROLE wardnet_injected\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS NOREPLICATION;",
        ),
        "create synthetic hostile-name login",
    );
    assert_success(
        map_runtime_principal(&container, hostile),
        "map hostile-name principal without SQL injection",
    );
    let hostile_result = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', pg_has_role('wardnet_hostile; CREATE ROLE wardnet_injected', 'wardnet_runtime', 'member'), to_regrole('wardnet_injected') IS NULL);",
        ),
        "inspect hostile-name mapping",
    );
    assert_eq!(hostile_result.trim(), "t:t");
}
