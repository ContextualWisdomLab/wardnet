#[cfg(not(test))]
use std::{env, error::Error, io, path::PathBuf};
#[cfg(not(test))]
use waf_ids_ai_soc::{AppConfig, AppState, build_app};

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let config = AppConfig {
        admin_token: env::var("ADMIN_TOKEN").ok(),
        state_path: env::var("WAF_IDS_STATE_PATH").ok().map(PathBuf::from),
        dnsbl_origin: env::var("DNSBL_ORIGIN")
            .unwrap_or_else(|_| AppConfig::DEFAULT_DNSBL_ORIGIN.to_string()),
        event_limit: parse_event_limit()?,
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("waf-ids-ai-soc listening on http://{bind_addr}");
    axum::serve(listener, build_app(AppState::load(config).await?)).await?;
    Ok(())
}

#[cfg(not(test))]
fn parse_event_limit() -> Result<usize, Box<dyn Error>> {
    let value = match env::var("EVENT_LIMIT") {
        Ok(raw) => raw.parse::<usize>()?,
        Err(_) => AppConfig::DEFAULT_EVENT_LIMIT,
    };

    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "EVENT_LIMIT must be greater than 0",
        )
        .into());
    }

    Ok(value)
}
