#[path = "../litellm_guard_proxy.rs"]
mod litellm_guard_proxy;

use litellm_guard_proxy::{ProxyConfig, RuntimeConfigRegistry, configuration_path_from_args};
use std::io::{Error, ErrorKind};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Registered eagerly, before the config is parsed and `serve` binds its
    // listener and prints the readiness line, so a SIGTERM/SIGINT delivered
    // immediately on startup (as container runtimes do) cannot race the
    // OS-level handler installation and fall through to the default "kill"
    // disposition. Mirrors `src/main.rs`'s `install_shutdown_signal`, which
    // fixed the identical race for the main gateway binary.
    let shutdown = install_shutdown_signal();
    let config_path =
        configuration_path_from_args(std::env::args_os().skip(1)).map_err(invalid_configuration)?;
    let registry =
        RuntimeConfigRegistry::from_json_file(config_path).map_err(invalid_configuration)?;
    let config = ProxyConfig::from_registry(&registry).map_err(invalid_configuration)?;
    litellm_guard_proxy::serve(config, shutdown).await
}

fn invalid_configuration(message: String) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

#[cfg(unix)]
fn install_shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    // `tokio::signal::unix::signal` registers each handler synchronously on
    // call; only the subsequent `.recv()` wait is deferred to the returned
    // future, so both listeners must be constructed here rather than inside
    // the async block itself.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("install SIGINT handler");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
    }
}

#[cfg(windows)]
fn install_shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    // Mirrors the Unix path: `tokio::signal::windows::ctrl_c` registers the
    // handler synchronously, so only `.recv()` is deferred to the future.
    let mut ctrl_c = tokio::signal::windows::ctrl_c().expect("install Ctrl-C handler");
    async move {
        ctrl_c.recv().await;
    }
}
