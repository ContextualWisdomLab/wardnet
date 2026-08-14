// The gateway entrypoint is intentionally a thin shim: all configuration
// parsing, binding, and serving live in `waf_ids_ai_soc::run_from_env` so they
// are unit-testable, while this file is covered end-to-end by `tests/binary.rs`.
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Construct the shutdown future before binding and printing readiness. On
    // Unix this eagerly installs the SIGTERM listener, so a container runtime
    // cannot terminate the process in the small interval between the readiness
    // line and the first poll of Axum's graceful-shutdown future.
    waf_ids_ai_soc::run_from_env(shutdown_signal()).await
}

#[cfg(all(not(test), unix))]
fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    // Register synchronously. Merely constructing an `async fn` future would
    // defer registration until its first poll and make readiness racy under
    // instrumentation such as `cargo llvm-cov`.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    Box::pin(async move {
        term.recv().await;
    })
}

#[cfg(all(not(test), windows))]
fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    // Register before returning the future, matching the eager Unix listener.
    // `tokio::signal::ctrl_c()` would defer registration until first poll.
    let mut interrupt = tokio::signal::windows::ctrl_c().expect("install Windows Ctrl-C handler");
    Box::pin(async move {
        let _ = interrupt.recv().await;
    })
}

#[cfg(all(not(test), not(any(unix, windows))))]
fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    })
}
