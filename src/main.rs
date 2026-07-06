#[cfg(not(test))]
use std::{env, error::Error, io, path::PathBuf};
#[cfg(not(test))]
use waf_ids_ai_soc::{AppConfig, AppState, build_app, parse_admin_tokens};

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
    let rate_limit = parse_u32_env("RATE_LIMIT", 0)?;
    let rate_limit_window = parse_u64_env("RATE_LIMIT_WINDOW", 60)?;
    let admin_tokens = parse_admin_tokens(&env::var("ADMIN_TOKENS").unwrap_or_default());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("waf-ids-ai-soc listening on http://{bind_addr}");
    let state = AppState::load(config)
        .await
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))?
        .with_rate_limit(rate_limit, rate_limit_window)
        .with_admin_tokens(admin_tokens);
    axum::serve(listener, build_app(state)).await?;
    Ok(())
}

#[cfg(not(test))]
fn parse_event_limit() -> Result<usize, Box<dyn Error>> {
    let value = match env::var("EVENT_LIMIT") {
        Ok(raw) => raw.parse::<usize>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("EVENT_LIMIT must be a positive integer, got {raw:?}: {error}"),
            )
        })?,
        Err(env::VarError::NotPresent) => AppConfig::DEFAULT_EVENT_LIMIT,
        Err(error) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("EVENT_LIMIT is not valid Unicode: {error}"),
            )
            .into());
        }
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

#[cfg(not(test))]
fn parse_u32_env(name: &str, default: u32) -> Result<u32, Box<dyn Error>> {
    match env::var(name) {
        Ok(raw) => Ok(raw.parse::<u32>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be a non-negative integer, got {raw:?}: {error}"),
            )
        })?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode: {error}"),
        )
        .into()),
    }
}

#[cfg(not(test))]
fn parse_u64_env(name: &str, default: u64) -> Result<u64, Box<dyn Error>> {
    match env::var(name) {
        Ok(raw) => Ok(raw.parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be a positive integer, got {raw:?}: {error}"),
            )
        })?),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode: {error}"),
        )
        .into()),
    }
}
