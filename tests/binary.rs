//! End-to-end coverage for the `main.rs` shim and shutdown path.
//!
//! Spawns the real gateway binary, waits until it reports readiness (proving it
//! bound the listener), then stops it with the platform-appropriate mechanism.
//! Running the binary under `cargo llvm-cov` records coverage for `main.rs` and
//! `shutdown_signal`, which cannot be reached from in-process unit tests.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

#[test]
#[cfg(unix)]
fn binary_serves_then_shuts_down_on_sigterm() {
    let mut child = spawn_ready_gateway();

    // SIGTERM drives the graceful-shutdown path so the process exits cleanly
    // (and flushes coverage counters) instead of being force-killed.
    let signalled = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signalled.success(), "failed to deliver SIGTERM");

    let exit = child.wait().expect("await gateway exit");
    assert!(
        exit.success(),
        "gateway should exit cleanly on SIGTERM: {exit:?}"
    );
}

#[test]
#[cfg(not(unix))]
fn binary_serves_until_force_stopped_on_windows() {
    let mut child = spawn_ready_gateway();
    child.kill().expect("force-stop gateway binary");
    let exit = child.wait().expect("await gateway exit");
    assert!(
        !exit.success(),
        "forced Windows shutdown should not masquerade as graceful: {exit:?}"
    );
}

#[test]
fn binary_does_not_report_readiness_before_state_validation() {
    let state_path = std::env::temp_dir().join(format!(
        "wardnet-corrupt-state-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::write(&state_path, "not-json").expect("write corrupt state fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("WAF_IDS_STATE_PATH", &state_path)
        .env_remove("ADMIN_TOKEN")
        .env_remove("ADMIN_TOKENS")
        .env_remove("WAF_IDS_CREDENTIALS_PATH")
        .env_remove("CORAZA_LIB_PATH")
        .env_remove("CORAZA_RULES_PATH")
        .env_remove("CORAZA_DIRECTIVES")
        .env_remove("CONTROL_PLANE_DATABASE_URL")
        .output()
        .expect("spawn gateway binary for startup validation check");
    let _ = std::fs::remove_file(&state_path);

    assert!(
        !output.status.success(),
        "corrupt state must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("is not valid JSON"),
        "startup error should explain the invalid state file:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported until persisted state validates:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_when_libcoraza_path_is_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("CORAZA_LIB_PATH", "/no/such/libcoraza.so")
        .env("CORAZA_DIRECTIVES", "SecRuleEngine On")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("ADMIN_TOKEN")
        .env_remove("ADMIN_TOKENS")
        .output()
        .expect("spawn gateway binary for libcoraza path check");
    assert!(
        !output.status.success(),
        "missing libcoraza must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("CORAZA_LIB_PATH") || combined.contains("does not exist"),
        "startup error should name the missing library:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported when libcoraza cannot load:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_non_loopback_listen_without_postgres() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "0.0.0.0:0")
        .env_remove("CONTROL_PLANE_DATABASE_URL")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("ADMIN_TOKEN")
        .env_remove("ADMIN_TOKENS")
        .env_remove("CORAZA_LIB_PATH")
        .output()
        .expect("spawn gateway binary for production postgres gate");
    assert!(
        !output.status.success(),
        "production bind without postgres must fail: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("CONTROL_PLANE_DATABASE_URL"),
        "startup error should name the missing control plane:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported without production postgres:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_when_control_plane_sslmode_is_ambiguous() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env(
            "CONTROL_PLANE_DATABASE_URL",
            "postgres://wardnet@127.0.0.1/wardnet?sslmode=prefer",
        )
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("CORAZA_LIB_PATH")
        .output()
        .expect("spawn gateway binary for sslmode check");
    assert!(
        !output.status.success(),
        "sslmode=prefer must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("sslmode"),
        "startup error should name the rejected sslmode:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported for an ambiguous sslmode:\n{combined}"
    );
}

#[test]
fn binary_fail_closes_when_control_plane_url_is_not_postgres() {
    let output = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("CONTROL_PLANE_DATABASE_URL", "mysql://not-postgres")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("CORAZA_LIB_PATH")
        .output()
        .expect("spawn gateway binary for control-plane URL check");
    assert!(
        !output.status.success(),
        "non-postgres URL must fail startup: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("postgres://"),
        "startup error should require a postgres URL:\n{combined}"
    );
    assert!(
        !combined.contains("waf-ids-ai-soc listening on"),
        "readiness must not be reported for a rejected control-plane URL:\n{combined}"
    );
}

fn spawn_ready_gateway() -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("EVENT_LIMIT")
        .env_remove("RATE_LIMIT")
        .env_remove("RATE_LIMIT_WINDOW")
        .env_remove("MAX_BODY_BYTES")
        .env_remove("CORAZA_LIB_PATH")
        .env_remove("CORAZA_RULES_PATH")
        .env_remove("CORAZA_DIRECTIVES")
        .env_remove("CORAZA_WAF_URL")
        .env_remove("CONTROL_PLANE_DATABASE_URL")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn gateway binary");

    // Block until the readiness line is printed, proving the listener bound.
    let stdout = child.stdout.take().expect("captured stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read readiness line");
    assert!(
        line.contains("listening on"),
        "unexpected startup line: {line:?}"
    );
    child
}

#[test]
fn release_checksums_script_emits_sha256_lines() {
    let dir = std::env::temp_dir().join(format!("wardnet-checksums-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let artifact = dir.join("artifact.bin");
    std::fs::write(&artifact, b"wardnet-release-fixture").expect("write fixture");
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release-checksums.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg(&artifact)
        .output()
        .expect("run release-checksums.sh");
    assert!(
        output.status.success(),
        "checksums script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().expect("one checksum line");
    let digest = line.split_whitespace().next().expect("hex digest");
    assert_eq!(digest.len(), 64, "SHA-256 hex: {line}");
    assert!(
        digest.chars().all(|ch| ch.is_ascii_hexdigit()),
        "digest must be hex: {digest}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
