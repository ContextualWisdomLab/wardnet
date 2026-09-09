use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waf_ids_ai_soc::postgres_state::{PostgresStateError, PostgresTenantPool};

const POSTGRES_IMAGE: &str = "postgres:18.4-bookworm";
const GENERATION_MIGRATION_PATH: &str = "migrations/0001_reputation_source_generation.sql";
const ADMISSION_MIGRATION_PATH: &str = "migrations/0002_reputation_source_generation_admission.sql";
const PUBLICATION_MIGRATION_PATH: &str = "migrations/0003_reputation_source_publication.sql";
const VERSION_MIGRATION_PATH: &str = "migrations/0004_reputation_state_schema_version.sql";
const AUDIT_MIGRATION_PATH: &str = "migrations/0005_reputation_source_publication_audit.sql";
const ROLE_INSTALLER_PATH: &str = "deploy/postgresql/reputation_state_roles.sql";
const PRINCIPAL_MAPPER_PATH: &str = "deploy/postgresql/reputation_state_runtime_principal.sql";
const RUNTIME_PRINCIPAL: &str = "wardnet_pool_hol_app";
const FINAL_STARTUP_MARKER: &str = "PostgreSQL init process complete; ready for start up.";
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

struct NewConnectionStallProxy {
    address: SocketAddr,
    stall_new_connections: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl NewConnectionStallProxy {
    fn start(upstream_port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fault proxy must bind loopback");
        listener
            .set_nonblocking(true)
            .expect("fault proxy listener must become nonblocking");
        let address = listener
            .local_addr()
            .expect("fault proxy must expose its loopback address");
        let stall_new_connections = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let accept_stall = Arc::clone(&stall_new_connections);
        let accept_stop = Arc::clone(&stop);

        thread::spawn(move || {
            while !accept_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let stall = Arc::clone(&accept_stall);
                        let stop = Arc::clone(&accept_stop);
                        thread::spawn(move || {
                            if stall.load(Ordering::Acquire) {
                                while stall.load(Ordering::Acquire) && !stop.load(Ordering::Acquire)
                                {
                                    thread::sleep(Duration::from_millis(10));
                                }
                                let _ = client.shutdown(Shutdown::Both);
                                return;
                            }

                            let upstream = TcpStream::connect(("127.0.0.1", upstream_port))
                                .expect("fault proxy must reach PostgreSQL");
                            proxy_bidirectionally(client, upstream);
                        });
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
            stall_new_connections,
            stop,
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn stall_new_connections(&self) {
        self.stall_new_connections.store(true, Ordering::Release);
    }

    fn release_new_connections(&self) {
        self.stall_new_connections.store(false, Ordering::Release);
    }
}

impl Drop for NewConnectionStallProxy {
    fn drop(&mut self) {
        self.stall_new_connections.store(false, Ordering::Release);
        self.stop.store(true, Ordering::Release);
    }
}

fn proxy_bidirectionally(mut client: TcpStream, mut upstream: TcpStream) {
    let mut client_reader = client
        .try_clone()
        .expect("fault proxy client stream must clone");
    let mut upstream_writer = upstream
        .try_clone()
        .expect("fault proxy upstream stream must clone");
    let client_to_upstream = thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = client_to_upstream.join();
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
        "wardnet-postgres-pool-hol-{}-{sequence}",
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_reconnect_does_not_block_an_unrelated_healthy_pool_member() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = NewConnectionStallProxy::start(container.host_port);
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        proxy.port()
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 2)
        .await
        .expect("two-member loopback pool must connect through the fault proxy");

    let first_pid = pool
        .probe_unbound_context()
        .await
        .expect("first original pool member must be reachable")
        .backend_pid();
    let second_pid = pool
        .probe_unbound_context()
        .await
        .expect("second original pool member must be reachable")
        .backend_pid();
    assert_ne!(
        first_pid, second_pid,
        "fixture requires two physical backends"
    );

    proxy.stall_new_connections();
    let terminated = assert_success(
        psql(
            &container,
            &format!("SELECT pg_terminate_backend({first_pid});"),
        ),
        "terminate the next round-robin pool member",
    );
    assert_eq!(terminated.trim(), "t");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result =
        tokio::time::timeout(Duration::from_millis(750), pool.probe_unbound_context()).await;
    proxy.release_new_connections();

    let probe = result
        .expect(
            "a stalled replacement for one closed slot must not head-of-line block an unrelated healthy member",
        )
        .expect("the unrelated established pool member must remain usable");
    assert_eq!(
        probe.backend_pid(),
        second_pid,
        "checkout must bypass the stalled dead-slot replacement and use the established healthy member",
    );
    assert_eq!(
        probe.tenant_id(),
        None,
        "healthy-member fallback must not expose tenant context before rebinding",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_closed_members_fail_closed_within_the_reconnect_readiness_bound() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = NewConnectionStallProxy::start(container.host_port);
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        proxy.port()
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 2)
        .await
        .expect("two-member loopback pool must connect through the fault proxy");

    let first_pid = pool
        .probe_unbound_context()
        .await
        .expect("first original pool member must be reachable")
        .backend_pid();
    let second_pid = pool
        .probe_unbound_context()
        .await
        .expect("second original pool member must be reachable")
        .backend_pid();
    assert_ne!(first_pid, second_pid, "fixture requires two physical backends");

    proxy.stall_new_connections();
    for backend_pid in [first_pid, second_pid] {
        let terminated = assert_success(
            psql(
                &container,
                &format!("SELECT pg_terminate_backend({backend_pid});"),
            ),
            "terminate an original pooled backend",
        );
        assert_eq!(terminated.trim(), "t");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result =
        tokio::time::timeout(Duration::from_millis(750), pool.probe_unbound_context()).await;
    proxy.release_new_connections();

    let unavailable = result.expect(
        "when no healthy member exists, Wardnet's own reconnect/readiness policy must terminate before the buyer-path bound rather than leave the caller responsible for cancellation",
    );
    assert!(
        matches!(unavailable, Err(PostgresStateError::PoolUnavailable)),
        "a bounded exhausted reconnect window must fail closed with stable PoolUnavailable",
    );
}
