use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waf_ids_ai_soc::postgres_state::{
    PostgresStateError, PostgresTenantPool, PublicationAuditContext, PublicationOutcome,
    ReputationSourcePublication, TenantId,
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
const MAX_PROTOCOL_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const COMMIT_UNKNOWN_DISPLAY: &str = "PostgreSQL commit outcome is unknown after transport loss";
static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitFault {
    PassThrough = 0,
    DropBeforeCommit = 1,
    DropAfterCommit = 2,
}

impl CommitFault {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::DropBeforeCommit,
            2 => Self::DropAfterCommit,
            _ => Self::PassThrough,
        }
    }
}

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

struct CommitFaultProxy {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    commit_forwarded: Arc<AtomicBool>,
    commit_completed: Arc<AtomicBool>,
    precommit_withheld: Arc<AtomicBool>,
    connection_count: Arc<AtomicU64>,
}

impl CommitFaultProxy {
    fn start(upstream_port: u16) -> Self {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("commit fault proxy must bind loopback");
        listener
            .set_nonblocking(true)
            .expect("commit fault proxy listener must become nonblocking");
        let address = listener
            .local_addr()
            .expect("commit fault proxy must expose its loopback address");

        let mode = Arc::new(AtomicU8::new(CommitFault::PassThrough as u8));
        let stop = Arc::new(AtomicBool::new(false));
        let commit_forwarded = Arc::new(AtomicBool::new(false));
        let commit_completed = Arc::new(AtomicBool::new(false));
        let precommit_withheld = Arc::new(AtomicBool::new(false));
        let connection_count = Arc::new(AtomicU64::new(0));

        let accept_mode = Arc::clone(&mode);
        let accept_stop = Arc::clone(&stop);
        let accept_forwarded = Arc::clone(&commit_forwarded);
        let accept_completed = Arc::clone(&commit_completed);
        let accept_withheld = Arc::clone(&precommit_withheld);
        let accept_connections = Arc::clone(&connection_count);

        thread::spawn(move || {
            while !accept_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        accept_connections.fetch_add(1, Ordering::AcqRel);
                        let upstream = TcpStream::connect(("127.0.0.1", upstream_port))
                            .expect("commit fault proxy must reach PostgreSQL");
                        let mode = Arc::clone(&accept_mode);
                        let forwarded = Arc::clone(&accept_forwarded);
                        let completed = Arc::clone(&accept_completed);
                        let withheld = Arc::clone(&accept_withheld);
                        thread::spawn(move || {
                            proxy_connection(
                                client, upstream, mode, forwarded, completed, withheld,
                            );
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("commit fault proxy accept failed: {error}"),
                }
            }
        });

        Self {
            address,
            mode,
            stop,
            commit_forwarded,
            commit_completed,
            precommit_withheld,
            connection_count,
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn arm_drop_after_commit(&self) {
        self.commit_forwarded.store(false, Ordering::Release);
        self.commit_completed.store(false, Ordering::Release);
        self.precommit_withheld.store(false, Ordering::Release);
        self.mode
            .store(CommitFault::DropAfterCommit as u8, Ordering::Release);
    }

    fn arm_drop_before_commit(&self) {
        self.commit_forwarded.store(false, Ordering::Release);
        self.commit_completed.store(false, Ordering::Release);
        self.precommit_withheld.store(false, Ordering::Release);
        self.mode
            .store(CommitFault::DropBeforeCommit as u8, Ordering::Release);
    }

    fn commit_was_forwarded(&self) -> bool {
        self.commit_forwarded.load(Ordering::Acquire)
    }

    fn commit_completed_before_drop(&self) -> bool {
        self.commit_completed.load(Ordering::Acquire)
    }

    fn commit_was_withheld(&self) -> bool {
        self.precommit_withheld.load(Ordering::Acquire)
    }

    fn connection_count(&self) -> u64 {
        self.connection_count.load(Ordering::Acquire)
    }
}

impl Drop for CommitFaultProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn proxy_connection(
    client: TcpStream,
    upstream: TcpStream,
    mode: Arc<AtomicU8>,
    commit_forwarded: Arc<AtomicBool>,
    commit_completed: Arc<AtomicBool>,
    precommit_withheld: Arc<AtomicBool>,
) {
    let client_reader = client
        .try_clone()
        .expect("proxy client stream must clone for frontend relay");
    let upstream_writer = upstream
        .try_clone()
        .expect("proxy upstream stream must clone for frontend relay");
    let frontend_forwarded = Arc::clone(&commit_forwarded);
    let frontend_withheld = Arc::clone(&precommit_withheld);
    let drop_after_commit = Arc::new(AtomicBool::new(false));
    let frontend_drop_after_commit = Arc::clone(&drop_after_commit);

    let frontend = thread::spawn(move || {
        relay_frontend(
            client_reader,
            upstream_writer,
            mode,
            frontend_forwarded,
            frontend_withheld,
            frontend_drop_after_commit,
        )
    });

    relay_backend(upstream, client, drop_after_commit, commit_completed);
    let _ = frontend.join();
}

fn relay_frontend(
    mut client: TcpStream,
    mut upstream: TcpStream,
    mode: Arc<AtomicU8>,
    commit_forwarded: Arc<AtomicBool>,
    precommit_withheld: Arc<AtomicBool>,
    drop_after_commit: Arc<AtomicBool>,
) {
    let Some(startup) =
        read_startup_packet(&mut client).expect("frontend startup packet must parse")
    else {
        return;
    };
    if upstream.write_all(&startup).is_err() {
        return;
    }

    loop {
        let Some((message_type, frame, payload)) =
            read_typed_message(&mut client).expect("frontend PostgreSQL frame must parse")
        else {
            return;
        };

        if message_type == b'Q' && simple_query_is_commit(&payload) {
            let armed =
                CommitFault::from_raw(mode.swap(CommitFault::PassThrough as u8, Ordering::AcqRel));
            match armed {
                CommitFault::DropBeforeCommit => {
                    precommit_withheld.store(true, Ordering::Release);
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = upstream.shutdown(Shutdown::Both);
                    return;
                }
                CommitFault::DropAfterCommit => {
                    commit_forwarded.store(true, Ordering::Release);
                    drop_after_commit.store(true, Ordering::Release);
                    if upstream.write_all(&frame).is_err() {
                        return;
                    }
                    continue;
                }
                CommitFault::PassThrough => {}
            }
        }

        if upstream.write_all(&frame).is_err() {
            return;
        }
    }
}

fn relay_backend(
    mut upstream: TcpStream,
    mut client: TcpStream,
    drop_after_commit: Arc<AtomicBool>,
    commit_completed: Arc<AtomicBool>,
) {
    let mut commit_command_complete = false;
    loop {
        let Some((message_type, frame, _)) =
            read_typed_message(&mut upstream).expect("backend PostgreSQL frame must parse")
        else {
            let _ = client.shutdown(Shutdown::Both);
            return;
        };

        if drop_after_commit.load(Ordering::Acquire) {
            if message_type == b'C' {
                commit_command_complete = true;
            } else if message_type == b'Z' && commit_command_complete {
                commit_completed.store(true, Ordering::Release);
                let _ = client.shutdown(Shutdown::Both);
                let _ = upstream.shutdown(Shutdown::Both);
                return;
            }
        }

        if client.write_all(&frame).is_err() {
            let _ = upstream.shutdown(Shutdown::Both);
            return;
        }
    }
}

fn read_startup_packet(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0_u8; 4];
    if !read_exact_or_eof(stream, &mut length_bytes)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(length_bytes) as usize;
    validate_frame_length(length)?;
    let mut body = vec![0_u8; length - 4];
    stream.read_exact(&mut body)?;

    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&length_bytes);
    frame.extend_from_slice(&body);
    Ok(Some(frame))
}

type TypedMessage = (u8, Vec<u8>, Vec<u8>);

fn read_typed_message(stream: &mut TcpStream) -> io::Result<Option<TypedMessage>> {
    let mut message_type = [0_u8; 1];
    if !read_exact_or_eof(stream, &mut message_type)? {
        return Ok(None);
    }
    let mut length_bytes = [0_u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    validate_frame_length(length)?;
    let mut payload = vec![0_u8; length - 4];
    stream.read_exact(&mut payload)?;

    let mut frame = Vec::with_capacity(length + 1);
    frame.push(message_type[0]);
    frame.extend_from_slice(&length_bytes);
    frame.extend_from_slice(&payload);
    Ok(Some((message_type[0], frame, payload)))
}

fn validate_frame_length(length: usize) -> io::Result<()> {
    if !(4..=MAX_PROTOCOL_MESSAGE_BYTES).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PostgreSQL protocol frame length is outside the bounded fixture contract",
        ));
    }
    Ok(())
}

fn read_exact_or_eof(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<bool> {
    match stream.read_exact(buffer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

fn simple_query_is_commit(payload: &[u8]) -> bool {
    let query = payload.strip_suffix(&[0]).unwrap_or(payload);
    query.eq_ignore_ascii_case(b"COMMIT")
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

fn publication(
    expected_prior: Option<&str>,
    generation: &str,
    ordinal: i64,
) -> ReputationSourcePublication {
    publication_with(
        expected_prior,
        generation,
        ordinal,
        &format!("provenance-{generation}"),
        "subject:commit-fixture",
        &format!("decision:publish-{generation}-{ordinal}"),
    )
}

fn publication_with(
    expected_prior: Option<&str>,
    generation: &str,
    ordinal: i64,
    provenance_ref: &str,
    actor_subject_id: &str,
    decision_id: &str,
) -> ReputationSourcePublication {
    ReputationSourcePublication::new(
        "urlhaus",
        expected_prior,
        generation,
        ordinal,
        1_700_000_000 + ordinal,
        provenance_ref,
        format!("snapshot-{generation}"),
        format!("complete-{generation}"),
        format!("lifecycle-{generation}"),
    )
    .expect("fixture publication must validate")
    .with_audit_context(
        PublicationAuditContext::new(actor_subject_id, decision_id)
            .expect("fixture audit context must validate"),
    )
}

async fn connect_pool(
    _container: &PostgresContainer,
    proxy: &CommitFaultProxy,
) -> PostgresTenantPool {
    let dsn = format!(
        "host=127.0.0.1 port={} user={RUNTIME_PRINCIPAL} dbname=postgres sslmode=disable",
        proxy.port()
    );
    PostgresTenantPool::connect_loopback_test(&dsn, 1)
        .await
        .expect("loopback runtime pool must connect through the protocol fault proxy")
}

fn generation_9_residue(container: &PostgresContainer) -> String {
    assert_success(
        psql(
            container,
            "SELECT concat_ws(':', (SELECT count(*) FROM public.reputation_source_generation WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus' AND source_generation = 'generation-9'), (SELECT count(*) FROM public.reputation_source_publication WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus' AND source_generation = 'generation-9'), (SELECT count(*) FROM public.reputation_source_publication_audit WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus' AND source_generation = 'generation-9'), (SELECT count(*) FROM public.reputation_source_publication_head WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus' AND source_generation = 'generation-9'));",
        ),
        "inspect generation-9 durable residue",
    )
}

fn await_generation_9_absent(container: &PostgresContainer) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if generation_9_residue(container).trim() == "0:0:0:0" {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "pre-COMMIT transport loss must roll back staged generation-9 state"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn assert_commit_unknown(result: Result<PublicationOutcome, PostgresStateError>) {
    match result {
        Ok(outcome) => panic!(
            "a lost COMMIT acknowledgement must not be reported as a known publication outcome: {outcome:?}"
        ),
        Err(error) => assert_eq!(
            error.to_string(),
            COMMIT_UNKNOWN_DISPLAY,
            "commit-stage transport loss needs a stable typed ambiguity outcome instead of a generic PostgreSQL/pool error"
        ),
    }
}

fn assert_conflict(result: Result<PublicationOutcome, PostgresStateError>, context: &str) {
    assert!(
        matches!(result, Err(PostgresStateError::PublicationConflict)),
        "{context}: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_but_ack_lost_reconciles_only_the_byte_identical_publication() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = CommitFaultProxy::start(container.host_port);
    let pool = connect_pool(&container, &proxy).await;
    let tenant = TenantId::parse("tenant-a").expect("tenant identity must validate");
    let other_tenant = TenantId::parse("tenant-b").expect("tenant identity must validate");

    assert_eq!(
        pool.publish_reputation_source(&tenant, &publication(None, "generation-8", 8))
            .await
            .expect("baseline publication must commit"),
        PublicationOutcome::Committed
    );

    let generation_9 = publication(Some("generation-8"), "generation-9", 9);
    proxy.arm_drop_after_commit();
    let ambiguous = pool.publish_reputation_source(&tenant, &generation_9).await;
    assert_commit_unknown(ambiguous);
    assert!(
        proxy.commit_was_forwarded(),
        "fault fixture must prove that the generation-9 COMMIT reached PostgreSQL"
    );
    assert!(
        proxy.commit_completed_before_drop(),
        "fault fixture must observe PostgreSQL CommandComplete plus ReadyForQuery before dropping the terminal acknowledgement"
    );
    assert_eq!(
        proxy.connection_count(),
        1,
        "Wardnet must not reconnect or replay publication work before an explicit caller retry"
    );
    assert_eq!(
        generation_9_residue(&container).trim(),
        "1:1:1:1",
        "a server-completed COMMIT with a lost client acknowledgement must leave exactly one immutable generation/publication/audit/head tuple"
    );

    assert_eq!(
        pool.publish_reputation_source(&tenant, &generation_9)
            .await
            .expect("byte-identical explicit reconciliation must read durable state"),
        PublicationOutcome::Replay
    );
    assert_eq!(
        generation_9_residue(&container).trim(),
        "1:1:1:1",
        "explicit reconciliation must not duplicate durable publication state"
    );

    let changed_evidence = publication_with(
        Some("generation-8"),
        "generation-9",
        9,
        "provenance-generation-9-divergent",
        "subject:commit-fixture",
        "decision:publish-generation-9-9",
    );
    assert_conflict(
        pool.publish_reputation_source(&tenant, &changed_evidence)
            .await,
        "changed evidence must not reconcile an ambiguous commit",
    );

    let changed_prior = publication(None, "generation-9", 9);
    assert_conflict(
        pool.publish_reputation_source(&tenant, &changed_prior)
            .await,
        "changed prior-generation expectation must not reconcile an ambiguous commit",
    );

    let changed_actor = publication_with(
        Some("generation-8"),
        "generation-9",
        9,
        "provenance-generation-9",
        "subject:different-actor",
        "decision:publish-generation-9-9",
    );
    assert_conflict(
        pool.publish_reputation_source(&tenant, &changed_actor)
            .await,
        "changed actor attribution must not reconcile an ambiguous commit",
    );

    let changed_decision = publication_with(
        Some("generation-8"),
        "generation-9",
        9,
        "provenance-generation-9",
        "subject:commit-fixture",
        "decision:different-decision",
    );
    assert_conflict(
        pool.publish_reputation_source(&tenant, &changed_decision)
            .await,
        "changed decision attribution must not reconcile an ambiguous commit",
    );

    let probe = pool
        .probe_unbound_context()
        .await
        .expect("replacement checkout must remain usable");
    assert_eq!(
        probe.tenant_id(),
        None,
        "replacement checkout must not retain transaction-local tenant authority"
    );
    assert!(
        pool.current_reputation_source_publication(&other_tenant, "urlhaus")
            .await
            .expect("cross-tenant lookup must remain a valid empty read")
            .is_none(),
        "tenant B must not see tenant A's reconciled publication"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn precommit_connection_loss_rolls_back_and_exact_retry_commits_once() {
    let Some(container) = prepare_database() else {
        return;
    };
    let proxy = CommitFaultProxy::start(container.host_port);
    let pool = connect_pool(&container, &proxy).await;
    let tenant = TenantId::parse("tenant-a").expect("tenant identity must validate");
    let other_tenant = TenantId::parse("tenant-b").expect("tenant identity must validate");

    assert_eq!(
        pool.publish_reputation_source(&tenant, &publication(None, "generation-8", 8))
            .await
            .expect("baseline publication must commit"),
        PublicationOutcome::Committed
    );

    let generation_9 = publication(Some("generation-8"), "generation-9", 9);
    proxy.arm_drop_before_commit();
    let ambiguous = pool.publish_reputation_source(&tenant, &generation_9).await;
    assert_commit_unknown(ambiguous);
    assert!(
        proxy.commit_was_withheld(),
        "fault fixture must prove that it intercepted the generation-9 COMMIT frame"
    );
    assert!(
        !proxy.commit_was_forwarded(),
        "pre-COMMIT fault must not send the intercepted COMMIT frame to PostgreSQL"
    );
    assert!(
        !proxy.commit_completed_before_drop(),
        "pre-COMMIT fault must not fabricate server completion evidence"
    );
    assert_eq!(
        proxy.connection_count(),
        1,
        "Wardnet must not reconnect or replay publication work before an explicit caller retry"
    );

    await_generation_9_absent(&container);
    let current = assert_success(
        psql(
            &container,
            "SELECT source_generation FROM public.reputation_source_publication_head WHERE tenant_id = 'tenant-a' AND source_id = 'urlhaus';",
        ),
        "inspect head after pre-COMMIT loss",
    );
    assert_eq!(
        current.trim(),
        "generation-8",
        "server rollback must keep the baseline publication authoritative"
    );

    assert_eq!(
        pool.publish_reputation_source(&tenant, &generation_9)
            .await
            .expect("explicit retry after proven pre-COMMIT loss may commit"),
        PublicationOutcome::Committed
    );
    assert_eq!(
        generation_9_residue(&container).trim(),
        "1:1:1:1",
        "explicit retry after server rollback must commit generation 9 exactly once"
    );

    let probe = pool
        .probe_unbound_context()
        .await
        .expect("replacement checkout must remain usable");
    assert_eq!(
        probe.tenant_id(),
        None,
        "replacement checkout must not retain transaction-local tenant authority"
    );
    assert!(
        pool.current_reputation_source_publication(&other_tenant, "urlhaus")
            .await
            .expect("cross-tenant lookup must remain a valid empty read")
            .is_none(),
        "tenant B must not see tenant A's retried publication"
    );
}
