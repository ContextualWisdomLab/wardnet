// The gateway entrypoint is intentionally a thin shim: all configuration
// parsing, binding, and serving live in `waf_ids_ai_soc::run_from_env` so they
// are unit-testable, while this file is covered end-to-end by `tests/binary.rs`.
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    waf_ids_ai_soc::run_from_env(Box::pin(shutdown_signal())).await
}

#[cfg(all(not(test), unix))]
async fn shutdown_signal() {
    // Shut down gracefully on SIGTERM (what container runtimes and the e2e test
    // harness send) so in-flight requests drain and the process exits cleanly.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    term.recv().await;
}

#[cfg(all(not(test), not(unix)))]
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl-C handler");
}
