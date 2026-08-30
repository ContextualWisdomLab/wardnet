// The gateway entrypoint is intentionally a thin shim: all configuration
// parsing, binding, and serving live in `waf_ids_ai_soc::run_from_env` so they
// are unit-testable, while this file is covered end-to-end by `tests/binary.rs`.
#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    waf_ids_ai_soc::run_from_env(shutdown_signal()?).await
}

#[cfg(all(not(test), unix))]
fn shutdown_signal() -> Result<
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    Box<dyn std::error::Error>,
> {
    // Install SIGTERM handling before readiness can be reported, so a fast
    // supervisor or test harness cannot kill the process before graceful
    // shutdown is armed.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(Box::pin(async move {
        term.recv().await;
    }))
}

#[cfg(all(not(test), not(unix)))]
fn shutdown_signal() -> Result<
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    Box<dyn std::error::Error>,
> {
    Ok(Box::pin(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    }))
}
