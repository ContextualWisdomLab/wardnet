use std::path::PathBuf;

use waf_ids_ai_soc::{DeploymentMode, RuntimeConfiguration, StateAuthority};

fn runtime(
    deployment_mode: DeploymentMode,
    state_authority: StateAuthority,
    state_path: Option<&str>,
) -> RuntimeConfiguration {
    RuntimeConfiguration {
        bind_addr: RuntimeConfiguration::DEFAULT_BIND_ADDR.to_string(),
        state_path: state_path.map(PathBuf::from),
        dnsbl_origin: "dnsbl.example".to_string(),
        event_limit: 100,
        rate_limit: 0,
        rate_limit_window: 60,
        max_body_bytes: 1_048_576,
        deployment_mode,
        state_authority,
    }
}

#[test]
fn production_mode_rejects_file_authority_even_on_loopback() {
    let config = runtime(
        DeploymentMode::Production,
        StateAuthority::File,
        Some("state.json"),
    );

    let error = config.validate_state_authority().unwrap_err();
    assert!(
        error.to_string().contains("production"),
        "production authority errors must identify the deployment invariant: {error}"
    );
}

#[test]
fn production_mode_requires_postgres_authority() {
    let config = runtime(DeploymentMode::Production, StateAuthority::Postgres, None);

    config
        .validate_state_authority()
        .expect("explicit PostgreSQL authority satisfies the production-mode contract");
}

#[test]
fn standalone_file_authority_requires_an_explicit_path() {
    let config = runtime(DeploymentMode::Standalone, StateAuthority::File, None);

    let error = config.validate_state_authority().unwrap_err();
    assert!(
        error.to_string().contains("state path"),
        "file authority without a path must fail closed: {error}"
    );
}

#[test]
fn standalone_memory_and_file_authorities_remain_valid() {
    runtime(DeploymentMode::Standalone, StateAuthority::Memory, None)
        .validate_state_authority()
        .unwrap();
    runtime(
        DeploymentMode::Standalone,
        StateAuthority::File,
        Some("state.json"),
    )
    .validate_state_authority()
    .unwrap();
}
