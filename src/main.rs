// The gateway entrypoint is intentionally a thin shim: all configuration
// parsing, binding, and serving live in `waf_ids_ai_soc::run_from_env` so they
// are unit-testable, while this file is covered end-to-end by `tests/binary.rs`.
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    waf_ids_ai_soc::run_from_env(Box::pin(shutdown_signal())).await
}

#[cfg(all(not(test), unix))]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    // Shut down gracefully on SIGTERM (what container runtimes and the e2e test
    // harness send) so in-flight requests drain and the process exits cleanly.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    async move {
        term.recv().await;
    }
}

#[cfg(all(not(test), windows))]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c().expect("install Ctrl-C handler");
    async move {
        ctrl_c.recv().await;
    }
}
