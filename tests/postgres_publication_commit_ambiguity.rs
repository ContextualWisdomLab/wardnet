use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waf_ids_ai_soc::postgres_state::{
    PostgresTenantPool, PublicationAuditContext, PublicationOutcome, ReputationSourcePublication,
    TenantId,
};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const VERSION_MIGRATION_PATH: &str = "migrations/0004_reputation_state_schema_version.sql";
const AUDIT_MIGRATION_PATH: &str = "migrations/0005_reputation_source_publication_audit.sql";
const ROLE_INSTALLER_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const PRINCIPAL_MAPPER_PATH: &str = "deploy/postgresql/reputation_state_runtime_principal.sql";
const RUNTIME_PRINCIPAL: &str = "wardnet_commit_ambiguity_app";
const FINAL_STARTUP_MARKER: &str = "PostgreSQL init process complete; ready for start up.";
const EXPECTED_COMMIT_UNKNOWN: &str = "reputation source publication commit outcome is unknown";
static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PostgresContainer {
    name: String,
    host_port: u16,
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

/// Protocol-aware loopback fault proxy that can drop the first backend message
/// emitted after one forwarded simple-query COMMIT. Reading that backend frame
/// proves PostgreSQL executed the COMMIT far enough to generate its response;
/// the client intentionally never receives that response.
struct CommitAckDropProxy {
    address: SocketAddr,
    arm_drop: Arc<AtomicBool>,
    acknowledgement_dropped: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl CommitAckDropProxy {
    fn start(upstream_port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fault proxy must bind loopback");
        listener
            .set_nonblocking(true)
            .expect("fault proxy listener must become nonblocking");
        let address = listener
            .local_addr()
            .expect("fault proxy must expose its loopback address");
        let arm_drop = Arc::new(AtomicBool::new(false));
        let acknowledgement_dropped = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let accept_arm = Arc::clone(&arm_drop);
        let accept_dropped = Arc::clone(&acknowledgement_dropped);
        let accept_stop = Arc::clone(&stop);

        thread::spawn(move || {
            while !accept_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let upstream = TcpStream::connect(("127.0.0.1", upstream_port))
                            .expect("fault proxy must reach PostgreSQL");
                        let arm = Arc::clone(&accept_arm);
                        let dropped = Arc::clone(&accept_dropped);
                        thread::spawn(move || proxy_connection(client, upstream, arm, dropped));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fault proxy accept failed: {error}"),
                }
            }
        });

        Self {
            address,
            arm_drop,
            acknowledgement_dropped,
            stop,
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn arm_one_commit_ack_drop(&self) {
        self.acknowledgement_dropped.store(false, Ordering::Release);
        self.arm_drop.store(true, Ordering::Release);
    }

    fn acknowledgement_dropped(&self) -> bool {
        self.acknowledgement_dropped.load(Ordering::Acquire)
    }
}

impl Drop for CommitAckDropProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn proxy_connection(
    mut client: TcpStream,
    mut upstream: TcpStream,
    arm_drop: Arc<AtomicBool>,
    acknowledgement_dropped: Arc<AtomicBool>,
) {
    let mut frontend = client
        .try_clone()
        .expect("fault proxy client stream must clone");
    let mut backend_writer = upstream
        .try_clone()
        .expect("fault proxy upstream stream must clone");
    let drop_backend_response = Arc::new(AtomicBool::new(false));
    let frontend_drop = Arc::clone(&drop_backend_response);

    let frontend_thread = thread::spawn(move || {
        // PostgreSQL startup packet has no type byte. Relay it once, then every
        // frontend packet uses the normal type + int32 length framing.
        let mut startup_length = [0_u8; 4];
        if frontend.read_exact(&mut startup_length).is_err() {
            return;
        }
        let startup_size = u32::from_be_bytes(startup_length) as usize;
        if startup_size < 4 {
            return;
        }
        let mut startup_body = vec![0_u8; startup_size - 4];
        if frontend.read_exact(&mut startup_body).is_err() {
            return;
        }
        if backend_writer.write_all(&startup_length).is_err()
            || backend_writer.write_all(&startup_body).is_err()
            || backend_writer.flush().is_err()
        {
            return;
        }

        loop {
            let mut message_type = [0_u8; 1];
            if frontend.read_exact(&mut message_type).is_err() {
                break;
            }
            let mut length = [0_u8; 4];
            if frontend.read_exact(&mut length).is_err() {
                break;
            }
            let message_size = u32::from_be_bytes(length) as usize;
            if message_size < 4 {
                break;
            }
            let mut body = vec![0_u8; message_size - 4];
            if frontend.read_exact(&mut body).is_err() {
                break;
            }

            let is_commit = message_type[0] == b'Q' && body.as_slice() == b"COMMIT\0";
            if backend_writer.write_all(&message_type).is_err()
                || backend_writer.write_all(&length).is_err()
                || backend_writer.write_all(&body).is_err()
                || backend_writer.flush().is_err()
            {
                break;
            }

            if is_commit && arm_drop.swap(false, Ordering::AcqRel) {
                frontend_drop.store(true, Ordering::Release);
            }
        }
        let _ = backend_writer.shutdown(Shutdown::Both);
    });

    loop {
        let mut message_type = [0_u8; 1];
        if upstream.read_exact(&mut message_type).is_err() {
            break;
        }
        let mut length = [0_u8; 4];
        if upstream.read_exact(&mut length).is_err() {
            break;
        }
        let message_size = u32::from_be_bytes(length) as usize;
        if message_size < 4 {
            break;
        }
        let mut body = vec![0_u8; message_size - 4];
        if upstream.read_exact(&mut body).is_err() {
            break;
        }

        if drop_backend_response.swap(false, Ordering::AcqRel) {
            acknowledgement_dropped.store(true, Ordering::Release);
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            break;
        }

        if client.write_all(&message_type).is_err()
            || client.write_all(&length).is_err()
            || client.write_all(&body).is_err()
            || client.flush().is_err()
        {
            break;
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = frontend_thread.join();
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

fn psql_with_runtime_principal(container: &PostgresContainer, sql: &str) -> Output {
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
            "-v",
            &format!("wardnet_runtime_principal={RUNTIME_PRINCIPAL}"),
            "-U",
            "postgres",
            "-d",
            "postgres",
        ],
        Some(sql),
    )
}

fn start_postgres() -> Option<PostgresContainer> {
    if !Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        if std::env::var_os("CI").is_some() {
            panic!("Docker is required for PostgreSQL integration tests in CI");
        }
        eprintln!("skipping PostgreSQL integration test because Docker is unavailable");
        return None;
    }

    let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "wardnet-postgres-commit-ambiguity-{}-{sequence}",
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
                "-p",
                "127.0.0.1::5432",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                POSTGRES_IMAGE,
            ],
            None,
        ),
        "start PostgreSQL 18.4 container",
    );

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = Command::new("docker")
            .args([
                "exec",
                &name,
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
        let logs = run_docker(&["logs", &name], None);
        let final_server_started = logs.status.success()
            && (String::from_utf8_lossy(&logs.stdout).contains(FINAL_STARTUP_MARKER)
                || String::from_utf8_lossy(&logs.stderr).contains(FINAL_STARTUP_MARKER));
        if status.success() && final_server_started {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL 18.4 final server did not become ready within 60 seconds"
        );
        thread::sleep(Duration::from_millis(500));
    }

    let rendered = assert_success(
        run_docker(&["port", &name, "5432/tcp"], None),
        "resolve PostgreSQL port",
    );
    let host_port = rendered
        .trim()
        .rsplit(':')
        .next()
        .expect("docker port output must contain a port")
        .parse()
        .expect("published PostgreSQL port must be numeric");
    Some(PostgresContainer { name, host_port })
}

fn prepare_database() -> Option<PostgresContainer> {
    let container = start_postgres()?;
    for (path, context) in [
        (GENERATION_MIGRATION_PATH, "apply generation migration"),
        (ADMISSION_MIGRATION_PATH, "apply admission migration"),
        (PUBLICATION_MIGRATION_PATH, "apply publication migration"),
        (VERSION_MIGRATION_PATH, "apply schema-version migration"),
        (AUDIT_MIGRATION_PATH, "apply publication-audit migration"),
        (ROLE_INSTALLER_PATH, "install capability roles"),
    ] {
        let sql = std::fs::read_to_string(path).expect("PostgreSQL fixture SQL must exist");
        assert_success(psql(&container, &sql), context);
    }
    assert_success(
        psql(
            &container,
            &format!(
                "CREATE ROLE {RUNTIME_PRINCIPAL} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;"
            ),
        ),
        "create externally managed runtime LOGIN",
    );
    let mapper = std::fs::read_to_string(PRINCIPAL_MAPPER_PATH)
        .expect("runtime principal mapper must exist");
    assert_success(
        psql_with_runtime_principal(&container, &mapper),
        "map external LOGIN to bounded runtime capability",
    );
    Some(container)
}

fn publication(actor: &str, evidence: &str) -> ReputationSourcePublication {
    ReputationSourcePublication::new(
        "urlhaus",
        None,
        "generation-9",
        9,
        1_700_000_009,
        "provenance-generation-9",
        evidence,
        "complete-generation-9",
        "lifecycle-generation-9",
    )
    .expect("fixture publication must validate")
    .with_audit_context(
        PublicationAuditContext::new(actor, "decision:publish-generation-9")
            .expect("fixture audit context must validate"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_but_unacknowledged_publication_is_reconciled_without_automatic_replay() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = CommitAckDropProxy::start(container.host_port);
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        proxy.port()
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 1)
        .await
        .expect("one-member runtime pool must connect through the protocol fault proxy");
    let tenant = TenantId::parse("tenant-a").expect("tenant identity must validate");
    let exact = publication("subject:commit-ambiguity", "snapshot-generation-9");

    proxy.arm_one_commit_ack_drop();
    let first = pool.publish_reputation_source(&tenant, &exact).await;
    assert!(
        first.is_err(),
        "lost COMMIT acknowledgement must never claim success"
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    while !proxy.acknowledgement_dropped() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        proxy.acknowledgement_dropped(),
        "fixture must prove it dropped a backend frame only after forwarding COMMIT"
    );

    let residue = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT count(*) FROM public.reputation_source_publication WHERE tenant_id='tenant-a' AND source_id='urlhaus' AND source_generation='generation-9'), (SELECT count(*) FROM public.reputation_source_publication_audit WHERE tenant_id='tenant-a' AND source_id='urlhaus' AND source_generation='generation-9'), (SELECT count(*) FROM public.reputation_source_publication_head WHERE tenant_id='tenant-a' AND source_id='urlhaus' AND source_generation='generation-9'));",
        ),
        "inspect committed-but-unacknowledged publication residue",
    );
    assert_eq!(
        residue.trim(),
        "1:1:1",
        "server must have one durable publication, audit tuple, and current head before reconciliation"
    );

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        pool.publish_reputation_source(&tenant, &exact)
            .await
            .expect("explicit exact reconciliation must succeed after reconnect"),
        PublicationOutcome::Replay,
        "same immutable typed command must reconcile through durable replay rather than duplicate publication"
    );

    let divergent = pool
        .publish_reputation_source(
            &tenant,
            &publication("subject:different", "snapshot-generation-9-different"),
        )
        .await;
    assert!(
        divergent.is_err(),
        "divergent evidence or attribution must not become a recovery path: {divergent:?}"
    );
    let residue_after = assert_success(
        psql(
            &container,
            "SELECT concat_ws(':', (SELECT count(*) FROM public.reputation_source_publication WHERE tenant_id='tenant-a' AND source_id='urlhaus' AND source_generation='generation-9'), (SELECT count(*) FROM public.reputation_source_publication_audit WHERE tenant_id='tenant-a' AND source_id='urlhaus' AND source_generation='generation-9'), (SELECT count(*) FROM public.reputation_source_publication_head WHERE tenant_id='tenant-a' AND source_id='urlhaus' AND source_generation='generation-9'));",
        ),
        "inspect post-reconciliation publication residue",
    );
    assert_eq!(residue_after.trim(), "1:1:1");

    let first_error = first.expect_err("lost acknowledgement must remain an error");
    assert_eq!(
        first_error.to_string(),
        EXPECTED_COMMIT_UNKNOWN,
        "commit-stage transport loss needs a stable unknown-outcome classification rather than a generic PostgreSQL connection error"
    );
}
