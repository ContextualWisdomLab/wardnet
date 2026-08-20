#[path = "../litellm_guard_proxy.rs"]
mod litellm_guard_proxy;

use litellm_guard_proxy::{ProxyConfig, RuntimeConfigRegistry, configuration_path_from_args};
use std::io::{Error, ErrorKind};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path =
        configuration_path_from_args(std::env::args_os().skip(1)).map_err(invalid_configuration)?;
    let registry =
        RuntimeConfigRegistry::from_json_file(config_path).map_err(invalid_configuration)?;
    let config = ProxyConfig::from_registry(&registry).map_err(invalid_configuration)?;
    litellm_guard_proxy::serve(config, shutdown_signal()).await
}

fn invalid_configuration(message: String) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
