//! End-to-end coverage for the `main.rs` shim and shutdown path.
//!
//! Spawns the real gateway binary, waits until it reports readiness (proving it
//! bound the listener), then stops it with the platform-appropriate mechanism.
//! Running the binary under `cargo llvm-cov` records coverage for `main.rs` and
//! `shutdown_signal`, which cannot be reached from in-process unit tests.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

#[test]
fn windows_ctrl_c_listener_is_created_before_the_shutdown_future() {
    let source = include_str!("../src/main.rs");
    let windows_impl = source
        .split("#[cfg(all(not(test), windows))]")
        .nth(1)
        .and_then(|section| section.split("#[cfg(").next())
        .expect("main.rs must define a Windows-specific shutdown listener");
    let listener = windows_impl
        .find("tokio::signal::windows::ctrl_c()")
        .expect("Windows shutdown must create its Ctrl-C listener eagerly");
    let future = windows_impl
        .find("Box::pin(async move")
        .expect("Windows shutdown must move the listener into its future");

    assert!(
        listener < future,
        "the Windows Ctrl-C listener must exist before the shutdown future is returned"
    );
}

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

fn spawn_ready_gateway() -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_waf-ids-ai-soc"))
        .env("BIND_ADDR", "127.0.0.1:0")
        .env_remove("WAF_IDS_STATE_PATH")
        .env_remove("EVENT_LIMIT")
        .env_remove("RATE_LIMIT")
        .env_remove("RATE_LIMIT_WINDOW")
        .env_remove("MAX_BODY_BYTES")
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
