// The gateway entrypoint is intentionally a thin shim: all configuration
// parsing, binding, and serving live in `waf_ids_ai_soc::run_from_env` so they
// are unit-testable, while this file is covered end-to-end by `tests/binary.rs`.
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Registered eagerly, before `run_from_env` binds its listener and prints
    // the readiness line, so a SIGTERM delivered immediately on startup (as
    // container runtimes and the e2e test harness do) cannot race the OS-level
    // handler installation and fall through to the default "kill" disposition.
    let shutdown = install_shutdown_signal();
    waf_ids_ai_soc::run_from_env(Box::pin(shutdown)).await
}

#[cfg(all(not(test), unix))]
fn install_shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    // `tokio::signal::unix::signal` registers the handler synchronously on
    // call; only the subsequent `.recv()` wait is deferred to the returned
    // future, so callers must invoke this *before* announcing readiness.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    async move {
        term.recv().await;
    }
}

#[cfg(all(not(test), windows))]
fn install_shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    // Mirrors the Unix path: `tokio::signal::windows::ctrl_c` registers the
    // handler synchronously, so only `.recv()` is deferred to the future.
    // Scoped to `windows` specifically (not `not(unix)`) since that API only
    // exists on Windows -- a broader non-Unix target would fail to compile.
    let mut ctrl_c = tokio::signal::windows::ctrl_c().expect("install Ctrl-C handler");
    async move {
        ctrl_c.recv().await;
    }
}
