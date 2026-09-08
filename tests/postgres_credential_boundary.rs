use std::path::PathBuf;
use waf_ids_ai_soc::{CredentialRegistry, CredentialSource};

const POSTGRES_DSN_KEY: &str = "postgres_dsn";

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
        registry.get_credential(POSTGRES_DSN_KEY),
        Some("postgres-dsn-unit-test-value")
    );
    assert_eq!(registry.source(), CredentialSource::None);
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
        registry.get_credential(POSTGRES_DSN_KEY),
        Some("postgres-dsn-file-value")
    );
    assert_eq!(registry.source(), CredentialSource::None);

    let _ = std::fs::remove_file(path);
}

#[test]
fn empty_postgres_dsn_is_not_registered() {
    let registry =
        CredentialRegistry::bootstrap_secrets_with_postgres(None, None, None, Some(String::new()))
            .unwrap();

    assert_eq!(registry.get_credential(POSTGRES_DSN_KEY), None);
}

#[test]
fn blank_environment_postgres_dsn_is_not_registered() {
    let registry = CredentialRegistry::bootstrap_secrets_with_postgres(
        None,
        None,
        None,
        Some(" \t  ".to_string()),
    )
    .unwrap();

    assert_eq!(registry.get_credential(POSTGRES_DSN_KEY), None);
    assert_eq!(registry.source(), CredentialSource::None);
    assert!(!registry.has_admin_auth());
}

#[test]
fn blank_credentials_file_postgres_dsn_is_not_registered() {
    let path = temp_credentials_path("blank-postgres-dsn");
    std::fs::write(&path, r#"{"postgres_dsn":" \t  "}"#).unwrap();

    let registry =
        CredentialRegistry::bootstrap_secrets_with_postgres(Some(&path), None, None, None).unwrap();

    assert_eq!(registry.get_credential(POSTGRES_DSN_KEY), None);
    assert_eq!(registry.source(), CredentialSource::None);
    assert!(!registry.has_admin_auth());

    let _ = std::fs::remove_file(path);
}

#[test]
fn nonblank_postgres_dsn_is_preserved_byte_for_byte() {
    let dsn = "host=db.internal dbname=wardnet user=wardnet";
    let registry = CredentialRegistry::bootstrap_secrets_with_postgres(
        None,
        None,
        None,
        Some(dsn.to_string()),
    )
    .unwrap();

    assert_eq!(registry.get_credential(POSTGRES_DSN_KEY), Some(dsn));
    assert_eq!(registry.source(), CredentialSource::None);
    assert!(!registry.has_admin_auth());
}

#[test]
fn non_string_credentials_file_postgres_dsn_fails_closed() {
    let malformed_values = [
        ("number", "42"),
        ("boolean", "true"),
        ("array", r#"["host=db.internal"]"#),
        ("object", r#"{"host":"db.internal"}"#),
    ];

    for (label, malformed_value) in malformed_values {
        let path = temp_credentials_path(label);
        std::fs::write(&path, format!(r#"{{"postgres_dsn":{malformed_value}}}"#)).unwrap();

        let error = CredentialRegistry::bootstrap_secrets_with_postgres(
            Some(&path),
            None,
            None,
            Some("host=env.internal dbname=wardnet".to_string()),
        )
        .expect_err("explicit malformed file DSN must not fall back to environment bootstrap");

        assert!(
            error.contains(POSTGRES_DSN_KEY),
            "{label} error must identify the malformed credential key without secret material: {error}"
        );
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn null_credentials_file_postgres_dsn_remains_absent() {
    let path = temp_credentials_path("null-postgres-dsn");
    std::fs::write(&path, r#"{"postgres_dsn":null}"#).unwrap();

    let registry =
        CredentialRegistry::bootstrap_secrets_with_postgres(Some(&path), None, None, None).unwrap();

    assert_eq!(registry.get_credential(POSTGRES_DSN_KEY), None);
    assert_eq!(registry.source(), CredentialSource::None);
    assert!(!registry.has_admin_auth());

    let _ = std::fs::remove_file(path);
}
