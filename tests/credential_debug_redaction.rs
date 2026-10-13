use waf_ids_ai_soc::{AppConfig, CredentialRegistry};

#[test]
fn registry_debug_never_exposes_bootstrapped_secrets() {
    let token = "synthetic-registry-debug-marker";
    let tokens = "synthetic-list-debug-marker:operator";
    let registry = CredentialRegistry::bootstrap_secrets(
        None,
        Some(token.to_string()),
        Some(tokens.to_string()),
    )
    .unwrap();
    for rendered in [format!("{registry:?}"), format!("{registry:#?}")] {
        assert!(
            !rendered.contains(token),
            "single token leaked through Debug"
        );
        assert!(
            !rendered.contains(tokens),
            "token list leaked through Debug"
        );
        assert!(rendered.contains("CredentialRegistry"));
        assert!(rendered.contains("Env"));
    }
    assert!(registry.has_admin_auth());
}

#[test]
fn app_config_debug_never_exposes_admin_token() {
    let token = "synthetic-config-debug-marker";
    let config = AppConfig::memory(Some(token.to_string()));
    for rendered in [format!("{config:?}"), format!("{config:#?}")] {
        assert!(
            !rendered.contains(token),
            "admin token leaked through Debug"
        );
        assert!(rendered.contains("AppConfig"));
        assert!(rendered.contains("dnsbl.local"));
    }
    assert_eq!(config.admin_token.as_deref(), Some(token));
    let absent = AppConfig::memory(None);
    assert!(format!("{absent:?}").contains("None"));
}
