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
const ROLE_INSTALL_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const RECOVERY_SCRIPT_PATH: &str = "deploy/postgresql/recover_reputation_state.psql";
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
        "wardnet-postgres-deployment-role-{}-{sequence}",
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

fn copy_recovery_assets(container: &PostgresContainer) {
    assert_success(
        run_docker(&["exec", &container.name, "mkdir", "-p", "/wardnet"], None),
        "create recovery fixture directory",
    );
    let destination = format!("{}:/wardnet/", container.name);
    assert_success(
        run_docker(&["cp", "migrations", &destination], None),
        "copy migrations into PostgreSQL recovery fixture",
    );
    assert_success(
        run_docker(&["cp", "deploy", &destination], None),
        "copy deployment recovery assets into PostgreSQL fixture",
    );
}

#[test]
fn deployment_installs_idempotent_least_privilege_reputation_state_roles() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let publication_migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("source-publication migration must exist");
    let role_install = std::fs::read_to_string(ROLE_INSTALL_PATH)
        .expect("production PostgreSQL role-install contract must exist outside schema migrations");
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
        psql(&container, &role_install),
        "install PostgreSQL reputation-state capability roles",
    );
    assert_success(
        psql(&container, &role_install),
        "replay PostgreSQL reputation-state role installation",
    );

    let role_contract = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', state_owner.rolcanlogin, state_owner.rolsuper, state_owner.rolcreatedb, state_owner.rolcreaterole, state_owner.rolinherit, state_owner.rolbypassrls, has_schema_privilege('wardnet_state_owner', 'public', 'CREATE'), runtime.rolcanlogin, runtime.rolsuper, runtime.rolcreatedb, runtime.rolcreaterole, runtime.rolbypassrls, has_table_privilege('wardnet_runtime', 'reputation_source_generation', 'INSERT'), has_table_privilege('wardnet_runtime', 'reputation_source_publication', 'INSERT'), has_table_privilege('wardnet_runtime', 'reputation_source_publication_head', 'UPDATE'), has_function_privilege('wardnet_runtime', 'wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)', 'EXECUTE'), has_function_privilege('wardnet_runtime', 'wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'), publication.prosecdef, publication.proowner = state_owner.oid) FROM pg_roles state_owner CROSS JOIN pg_roles runtime CROSS JOIN pg_proc publication WHERE state_owner.rolname = 'wardnet_state_owner' AND runtime.rolname = 'wardnet_runtime' AND publication.oid = 'wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'::regprocedure;",
        ),
        "verify deployed role attributes and grants",
    );
    assert_eq!(
        role_contract.trim(),
        "f:f:f:f:f:f:f:f:f:f:f:f:f:f:f:f:t:t:t",
        "deployment must leave a NOLOGIN/NOSUPERUSER/NOBYPASSRLS state owner without schema CREATE and a NOLOGIN runtime capability without direct mutation or inner-admission authority"
    );

    let mediated_publication = assert_success(
        psql(
            &container,
            "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-deploy', true); SELECT wardnet_publish_reputation_source_generation('tenant-deploy', 'source-a', NULL, 'generation-1', 1, 1000, 'evidence:v1', 'completeness:v1', 'lifecycle:v1', 'producer:v1'); COMMIT; RESET ROLE;",
        ),
        "publish through deployed runtime capability",
    );
    assert!(
        mediated_publication
            .lines()
            .any(|line| line.trim() == "committed"),
        "runtime capability must retain function-mediated publication"
    );

    let direct_head_update = psql(
        &container,
        "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-deploy', true); UPDATE reputation_source_publication_head SET source_generation_ordinal = 0 WHERE tenant_id = 'tenant-deploy' AND source_id = 'source-a'; COMMIT;",
    );
    assert!(
        !direct_head_update.status.success(),
        "runtime capability must not receive direct last-known-good mutation authority"
    );
    assert!(
        String::from_utf8_lossy(&direct_head_update.stderr).contains("permission denied"),
        "direct runtime mutation must fail because the underlying privilege is absent"
    );

    let owner_schema_create = psql(
        &container,
        "SET ROLE wardnet_state_owner; CREATE TABLE public.wardnet_state_owner_must_not_create_objects(id integer);",
    );
    assert!(
        !owner_schema_create.status.success(),
        "state owner must not retain schema CREATE after function ownership transfer"
    );
    assert!(
        String::from_utf8_lossy(&owner_schema_create.stderr).contains("permission denied"),
        "state-owner schema DDL must fail because temporary ownership-transfer CREATE privilege was revoked"
    );

    let persisted = assert_success(
        psql(
            &container,
            "BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-deploy', true); SELECT source_generation || ':' || source_generation_ordinal FROM reputation_source_publication_head WHERE tenant_id = 'tenant-deploy' AND source_id = 'source-a'; COMMIT;",
        ),
        "read last-known-good state after denied direct mutations",
    );
    assert!(
        persisted
            .lines()
            .any(|line| line.trim() == "generation-1:1"),
        "denied direct mutations must leave the function-mediated last-known-good head unchanged"
    );
}

#[test]
fn recovery_reconverges_publication_capability_after_schema_rollback_and_reapply() {
    let generation_migration = std::fs::read_to_string(GENERATION_MIGRATION_PATH)
        .expect("source-generation schema migration must exist");
    let admission_migration = std::fs::read_to_string(ADMISSION_MIGRATION_PATH)
        .expect("source-generation admission migration must exist");
    let publication_migration = std::fs::read_to_string(PUBLICATION_MIGRATION_PATH)
        .expect("source-publication migration must exist");
    let publication_rollback = std::fs::read_to_string(PUBLICATION_ROLLBACK_PATH)
        .expect("source-publication rollback migration must exist");
    let role_install = std::fs::read_to_string(ROLE_INSTALL_PATH)
        .expect("production PostgreSQL role-install contract must exist");
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
    assert_success(
        psql(&container, &role_install),
        "install least-privilege roles",
    );

    let initial_publication = assert_success(
        psql(
            &container,
            "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-recovery', true); SELECT wardnet_publish_reputation_source_generation('tenant-recovery', 'source-a', NULL, 'generation-1', 1, 1000, 'evidence:v1', 'completeness:v1', 'lifecycle:v1', 'producer:v1'); COMMIT; RESET ROLE;",
        ),
        "publish before recovery rehearsal",
    );
    assert!(
        initial_publication
            .lines()
            .any(|line| line.trim() == "committed")
    );

    assert_success(
        psql(&container, &publication_rollback),
        "roll publication schema back",
    );
    assert_success(
        psql(&container, &publication_migration),
        "reapply publication schema without role reconvergence",
    );

    let unrecovered_authority = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', publication.proowner = state_owner.oid, has_function_privilege('wardnet_runtime', 'wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE')) FROM pg_roles state_owner CROSS JOIN pg_proc publication WHERE state_owner.rolname = 'wardnet_state_owner' AND publication.oid = 'wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'::regprocedure;",
        ),
        "prove schema reapply alone is not recovered runtime authority",
    );
    assert_eq!(
        unrecovered_authority.trim(),
        "f:f",
        "recreated schema must remain fail closed until deployment-role authority is reconverged"
    );

    assert_success(
        psql(&container, &publication_rollback),
        "return to the supported 0002 boundary before executable recovery",
    );
    assert!(
        std::path::Path::new(RECOVERY_SCRIPT_PATH).exists(),
        "production recovery must provide one executable sequencing boundary that reapplies 0003 and reuses the existing role installer"
    );
    copy_recovery_assets(&container);
    assert_success(
        psql_file(
            &container,
            "/wardnet/deploy/postgresql/recover_reputation_state.psql",
        ),
        "execute reputation-state recovery sequence",
    );
    assert_success(
        psql_file(
            &container,
            "/wardnet/deploy/postgresql/recover_reputation_state.psql",
        ),
        "replay reputation-state recovery sequence idempotently",
    );

    let recovered_authority = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', publication.proowner = state_owner.oid, publication.prosecdef, EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(publication.proacl, pg_catalog.acldefault('f', publication.proowner))) AS public_acl WHERE public_acl.grantee = 0 AND public_acl.privilege_type = 'EXECUTE'), has_function_privilege('wardnet_runtime', 'wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)', 'EXECUTE'), has_table_privilege('wardnet_runtime', 'reputation_source_generation', 'INSERT'), has_table_privilege('wardnet_runtime', 'reputation_source_publication', 'INSERT'), has_table_privilege('wardnet_runtime', 'reputation_source_publication_head', 'UPDATE'), has_function_privilege('wardnet_runtime', 'wardnet_admit_reputation_source_generation(text,text,text,bigint,bigint,text)', 'EXECUTE'), state_owner.rolcanlogin, state_owner.rolsuper, state_owner.rolbypassrls, state_owner.rolcreaterole, state_owner.rolcreatedb, state_owner.rolinherit, state_owner.rolreplication, has_schema_privilege('wardnet_state_owner', 'public', 'CREATE')) FROM pg_roles state_owner CROSS JOIN pg_proc publication WHERE state_owner.rolname = 'wardnet_state_owner' AND publication.oid = 'wardnet_publish_reputation_source_generation(text,text,text,text,bigint,bigint,text,text,text,text)'::regprocedure;",
        ),
        "verify recovered least-privilege publication authority",
    );
    assert_eq!(
        recovered_authority.trim(),
        "t:t:f:t:f:f:f:f:f:f:f:f:f:f:f:f",
        "recovery must restore only the bounded outer capability and hardened state-owner contract"
    );

    let preserved_generation = assert_success(
        psql(
            &container,
            "SELECT count(*) = 1 FROM reputation_source_generation WHERE tenant_id = 'tenant-recovery' AND source_id = 'source-a' AND source_generation = 'generation-1' AND source_generation_ordinal = 1;",
        ),
        "verify recovery preserved immutable generation history",
    );
    assert_eq!(preserved_generation.trim(), "t");

    let recovered_publication = assert_success(
        psql(
            &container,
            "SET ROLE wardnet_runtime; BEGIN; SELECT set_config('wardnet.tenant_id', 'tenant-recovery', true); SELECT wardnet_publish_reputation_source_generation('tenant-recovery', 'source-a', NULL, 'generation-2', 2, 2000, 'evidence:v2', 'completeness:v2', 'lifecycle:v2', 'producer:v2'); COMMIT; RESET ROLE;",
        ),
        "publish through recovered runtime capability",
    );
    assert!(
        recovered_publication
            .lines()
            .any(|line| line.trim() == "committed"),
        "recovered runtime authority must advance last-known-good state only through the outer capability"
    );
}
