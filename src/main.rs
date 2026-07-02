use std::{env, error::Error};
use waf_ids_ai_soc::{AppState, build_app};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let admin_token = env::var("ADMIN_TOKEN").ok();
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("waf-ids-ai-soc listening on http://{bind_addr}");
    axum::serve(listener, build_app(AppState::seeded(admin_token))).await?;
    Ok(())
}
