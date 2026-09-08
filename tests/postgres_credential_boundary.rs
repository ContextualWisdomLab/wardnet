use std::path::PathBuf;
use waf_ids_ai_soc::{CRED_POSTGRES_DSN, CredentialRegistry};

fn temp_credentials_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "wardnet-{label}-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn postgres_dsn_is_kept_in_the_secret_registry() {
    let registry = CredentialRegistry::bootstrap_secrets_with_postgres(
        None,
        None,
        None,
        Some("postgres-dsn-unit-test-value".to_string()),
    )
    .unwrap();

    assert_eq!(
        registry.get_credential(CRED_POSTGRES_DSN),
        Some("postgres-dsn-unit-test-value")
    );
}

#[test]
fn credentials_file_overrides_environment_postgres_dsn() {
    let path = temp_credentials_path("postgres-dsn");
    std::fs::write(&path, r#"{"postgres_dsn":"postgres-dsn-file-value"}"#).unwrap();

    let registry = CredentialRegistry::bootstrap_secrets_with_postgres(
        Some(&path),
        None,
        None,
        Some("postgres-dsn-env-value".to_string()),
    )
    .unwrap();

    assert_eq!(
        registry.get_credential(CRED_POSTGRES_DSN),
        Some("postgres-dsn-file-value")
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn empty_postgres_dsn_is_not_registered() {
    let registry =
        CredentialRegistry::bootstrap_secrets_with_postgres(None, None, None, Some(String::new()))
            .unwrap();

    assert_eq!(registry.get_credential(CRED_POSTGRES_DSN), None);
}
