use std::path::PathBuf;

use waf_ids_ai_soc::RuntimeConfiguration;

fn runtime(production: bool, authority: &str, state_path: Option<&str>) -> RuntimeConfiguration {
    let deployment_mode = if production {
        RuntimeConfiguration::PRODUCTION_MODE
    } else {
        RuntimeConfiguration::STANDALONE_MODE
    };
    let state_authority = match authority {
        "memory" => RuntimeConfiguration::MEMORY_AUTHORITY,
        "file" => RuntimeConfiguration::FILE_AUTHORITY,
        "postgres" => RuntimeConfiguration::POSTGRES_AUTHORITY,
        other => panic!("unexpected test authority {other}"),
    };
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
    let config = runtime(true, "file", Some("state.json"));

    let error = config.validate_state_authority().unwrap_err();
    assert!(
        error.to_string().contains("production"),
        "production authority errors must identify the deployment invariant: {error}"
    );
}

#[test]
fn production_mode_requires_postgres_authority_without_silent_downgrade() {
    let config = runtime(true, "postgres", None);

    config
        .validate_state_authority()
        .expect("explicit PostgreSQL authority satisfies the production-mode contract");
    let error = config.ensure_state_backend_available().unwrap_err();
    assert!(
        error.to_string().contains("not available"),
        "PostgreSQL selection must fail closed until the durable adapter lands: {error}"
    );
}

#[test]
fn standalone_file_authority_requires_an_explicit_path() {
    let config = runtime(false, "file", None);

    let error = config.validate_state_authority().unwrap_err();
    assert!(
        error.to_string().contains("state path"),
        "file authority without a path must fail closed: {error}"
    );
}

#[test]
fn standalone_memory_and_file_authorities_remain_valid() {
    runtime(false, "memory", None)
        .validate_state_authority()
        .unwrap();
    runtime(false, "file", Some("state.json"))
        .validate_state_authority()
        .unwrap();
}
