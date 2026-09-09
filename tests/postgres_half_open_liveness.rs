use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
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
const RUNTIME_PRINCIPAL: &str = "wardnet_half_open_liveness_app";
const FINAL_STARTUP_MARKER: &str = "PostgreSQL init process complete; ready for start up.";
const BUYER_PATH_GUARD: Duration = Duration::from_millis(750);
const SLOW_VALID_DELAY_MS: u64 = 40;
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

struct BackendBlackholeProxy {
    address: SocketAddr,
    blackholed_connection: Arc<AtomicU64>,
    blackhole_all: Arc<AtomicBool>,
    backend_delay_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    connection_count: Arc<AtomicU64>,
}

impl BackendBlackholeProxy {
    fn start(upstream_port: u16) -> Self {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("blackhole proxy must bind loopback");
        listener
            .set_nonblocking(true)
            .expect("blackhole proxy listener must become nonblocking");
        let address = listener
            .local_addr()
            .expect("blackhole proxy must expose its loopback address");

        let blackholed_connection = Arc::new(AtomicU64::new(0));
        let blackhole_all = Arc::new(AtomicBool::new(false));
        let backend_delay_ms = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let connection_count = Arc::new(AtomicU64::new(0));

        let accept_blackholed_connection = Arc::clone(&blackholed_connection);
        let accept_blackhole_all = Arc::clone(&blackhole_all);
        let accept_backend_delay_ms = Arc::clone(&backend_delay_ms);
        let accept_stop = Arc::clone(&stop);
        let accept_connection_count = Arc::clone(&connection_count);

        thread::spawn(move || {
            while !accept_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let connection_id =
                            accept_connection_count.fetch_add(1, Ordering::AcqRel) + 1;
                        let upstream = TcpStream::connect(("127.0.0.1", upstream_port))
                            .expect("blackhole proxy must reach PostgreSQL");
                        let blackholed_connection = Arc::clone(&accept_blackholed_connection);
                        let blackhole_all = Arc::clone(&accept_blackhole_all);
                        let backend_delay_ms = Arc::clone(&accept_backend_delay_ms);
                        thread::spawn(move || {
                            proxy_connection(
                                client,
                                upstream,
                                connection_id,
                                blackholed_connection,
                                blackhole_all,
                                backend_delay_ms,
                            );
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("blackhole proxy accept failed: {error}"),
                }
            }
        });

        Self {
            address,
            blackholed_connection,
            blackhole_all,
            backend_delay_ms,
            stop,
            connection_count,
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn connection_count(&self) -> u64 {
        self.connection_count.load(Ordering::Acquire)
    }

    fn blackhole_connection(&self, connection_id: u64) {
        self.blackhole_all.store(false, Ordering::Release);
        self.blackholed_connection
            .store(connection_id, Ordering::Release);
    }

    fn blackhole_every_connection(&self) {
        self.blackholed_connection.store(0, Ordering::Release);
        self.blackhole_all.store(true, Ordering::Release);
    }

    fn clear_blackhole(&self) {
        self.blackhole_all.store(false, Ordering::Release);
        self.blackholed_connection.store(0, Ordering::Release);
    }

    fn set_backend_delay(&self, delay_ms: u64) {
        self.backend_delay_ms.store(delay_ms, Ordering::Release);
    }
}

impl Drop for BackendBlackholeProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn proxy_connection(
    client: TcpStream,
    upstream: TcpStream,
    connection_id: u64,
    blackholed_connection: Arc<AtomicU64>,
    blackhole_all: Arc<AtomicBool>,
    backend_delay_ms: Arc<AtomicU64>,
) {
    let mut frontend_reader = client
        .try_clone()
        .expect("proxy client stream must clone for frontend relay");
    let mut frontend_writer = upstream
        .try_clone()
        .expect("proxy upstream stream must clone for frontend relay");
    let frontend = thread::spawn(move || {
        let _ = io::copy(&mut frontend_reader, &mut frontend_writer);
    });

    let mut backend_reader = upstream;
    let mut backend_writer = client;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = match backend_reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        if blackhole_all.load(Ordering::Acquire)
            || blackholed_connection.load(Ordering::Acquire) == connection_id
        {
            continue;
        }
        let delay_ms = backend_delay_ms.load(Ordering::Acquire);
        if delay_ms > 0 {
            thread::sleep(Duration::from_millis(delay_ms));
        }
        if backend_writer.write_all(&buffer[..read]).is_err() {
            break;
        }
    }
    let _ = frontend.join();
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
    let name = format!("wardnet-postgres-half-open-{}-{sequence}", std::process::id());
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
        "resolve port",
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn established_half_open_session_cannot_stall_healthy_pool_capacity_or_all_dead_failure() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = BackendBlackholeProxy::start(container.host_port);
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        proxy.port()
    );
    let pool = PostgresTenantPool::connect_loopback_test(&dsn, 2)
        .await
        .expect("loopback integration pool must connect through the fault proxy");
    assert_eq!(
        proxy.connection_count(),
        2,
        "pool bootstrap must establish exactly two physical runtime sessions before fault injection"
    );

    let first = pool
        .probe_unbound_context()
        .await
        .expect("first runtime session must be healthy before fault injection");
    let second = pool
        .probe_unbound_context()
        .await
        .expect("second runtime session must be healthy before fault injection");
    assert_ne!(
        first.backend_pid(),
        second.backend_pid(),
        "hostile acceptance requires two distinct PostgreSQL backend sessions"
    );
    assert!(first.tenant_id().is_none() && second.tenant_id().is_none());

    proxy.set_backend_delay(SLOW_VALID_DELAY_MS);
    let slow_valid = tokio::time::timeout(BUYER_PATH_GUARD, pool.probe_unbound_context())
        .await
        .expect("bounded but valid PostgreSQL protocol delay must not be treated as dead")
        .expect("slow-valid runtime session must remain usable");
    assert!(
        slow_valid.backend_pid() == first.backend_pid()
            || slow_valid.backend_pid() == second.backend_pid()
    );
    assert!(slow_valid.tenant_id().is_none());
    proxy.set_backend_delay(0);

    proxy.blackhole_connection(1);
    let selective = tokio::time::timeout(BUYER_PATH_GUARD, pool.probe_unbound_context()).await;
    let selective = selective.expect(
        "an established driver-known-open session with no PostgreSQL protocol progress must not hang checkout beyond the buyer-path liveness bound",
    );
    let selective = selective.expect(
        "healthy established capacity must remain usable when one selected runtime session is blackholed before Wardnet state work begins",
    );
    assert_ne!(
        selective.backend_pid(),
        first.backend_pid(),
        "the blackholed first physical runtime session must not execute the Wardnet probe"
    );
    assert!(selective.tenant_id().is_none());

    proxy.blackhole_every_connection();
    let all_blackholed = tokio::time::timeout(BUYER_PATH_GUARD, pool.probe_unbound_context())
        .await
        .expect("all-blackholed runtime capacity must fail closed inside the repository liveness bound");
    assert!(
        matches!(all_blackholed, Err(PostgresStateError::PoolUnavailable)),
        "all established/replacement sessions without PostgreSQL protocol progress must report typed pool unavailability: {all_blackholed:?}"
    );

    proxy.clear_blackhole();
    let recovered = tokio::time::timeout(BUYER_PATH_GUARD, pool.probe_unbound_context())
        .await
        .expect("cleared network fault must allow bounded runtime recovery")
        .expect("runtime pool must recover without process restart");
    assert!(
        recovered.tenant_id().is_none(),
        "half-open detection/replacement must not leak transaction-local tenant authority"
    );
    assert!(
        proxy.connection_count() <= 4,
        "bounded liveness recovery must not create an unbounded reconnect storm; observed {} runtime streams",
        proxy.connection_count()
    );
}
