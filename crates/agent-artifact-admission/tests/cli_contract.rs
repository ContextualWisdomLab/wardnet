use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AdmissionServiceConfig, ApprovedArtifact, ApprovedManifest, CredentialFile,
    load_admin_token, load_config, parse_cli_args, validate_service_config,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn valid_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-08-29.1".to_string(),
        allowed_executables: vec!["npm".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: digest('a'),
        }],
        approved_artifacts: vec![ApprovedArtifact {
            ecosystem: "npm".to_string(),
            name: "@cwl/example".to_string(),
            version: "1.2.3".to_string(),
            registry_url: "https://registry.npmjs.org".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: digest('b'),
            artifact_argument: "@cwl/example@1.2.3".to_string(),
        }],
    }
}

fn valid_config() -> AdmissionServiceConfig {
    AdmissionServiceConfig {
        configuration_version: "1".to_string(),
        bind_address: "127.0.0.1:8787".to_string(),
        max_request_body_bytes: 64 * 1024,
        audit_log_path: "/var/lib/wardnet/agent-artifact-admission.ndjson".to_string(),
        policy: valid_policy(),
    }
}

fn temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-agent-config-{label}-{}-{nonce}.json",
        std::process::id()
    ))
}

#[test]
fn strict_cli_requires_exactly_one_config_and_credentials_path() {
    let args = vec![
        "--config".to_string(),
        "/etc/wardnet/admission.json".to_string(),
        "--credentials".to_string(),
        "/run/secrets/admission.json".to_string(),
    ];
    let parsed = parse_cli_args(&args).expect("valid CLI must parse");
    assert_eq!(parsed.config_path, "/etc/wardnet/admission.json");
    assert_eq!(parsed.credentials_path, "/run/secrets/admission.json");

    for invalid in [
        vec!["--config", "a"],
        vec!["--credentials", "b"],
        vec!["--config", "a", "--config", "b", "--credentials", "c"],
        vec!["--config", "a", "--credentials", "b", "--credentials", "c"],
        vec!["--config", "a", "--credentials"],
        vec!["--config", "a", "--credentials", "b", "extra"],
        vec!["--config", "a", "--credentials", "b", "--unknown", "x"],
    ] {
        let invalid: Vec<String> = invalid.into_iter().map(str::to_string).collect();
        assert!(parse_cli_args(&invalid).is_err(), "accepted invalid argv: {invalid:?}");
    }
}

#[test]
fn service_config_rejects_unsafe_boundaries_and_policy_drift() {
    let mut cases = Vec::new();

    let mut config = valid_config();
    config.configuration_version = "2".to_string();
    cases.push(config);

    let mut config = valid_config();
    config.bind_address = "0.0.0.0:8787".to_string();
    cases.push(config);

    let mut config = valid_config();
    config.max_request_body_bytes = 0;
    cases.push(config);

    let mut config = valid_config();
    config.max_request_body_bytes = 2 * 1024 * 1024;
    cases.push(config);

    let mut config = valid_config();
    config.audit_log_path.clear();
    cases.push(config);

    let mut config = valid_config();
    config.policy.allowed_executables.push("npm".to_string());
    cases.push(config);

    let mut config = valid_config();
    config.policy.allowed_executables = vec!["bash".to_string()];
    cases.push(config);

    let mut config = valid_config();
    config.policy.approved_manifests.push(config.policy.approved_manifests[0].clone());
    cases.push(config);

    let mut config = valid_config();
    config.policy.approved_manifests[0].sha256 = "ABC".to_string();
    cases.push(config);

    let mut config = valid_config();
    config.policy.approved_artifacts.push(config.policy.approved_artifacts[0].clone());
    cases.push(config);

    let mut config = valid_config();
    config.policy.approved_artifacts[0].version = "latest".to_string();
    cases.push(config);

    let mut config = valid_config();
    config.policy.approved_artifacts[0].registry_url = "http://registry.example".to_string();
    cases.push(config);

    let mut config = valid_config();
    config.policy.approved_artifacts[0].artifact_argument.clear();
    cases.push(config);

    for config in cases {
        assert!(validate_service_config(&config).is_err(), "unsafe config validated: {config:?}");
    }

    assert!(validate_service_config(&valid_config()).is_ok());
}

#[test]
fn loaders_are_bounded_strict_and_do_not_accept_short_credentials() {
    let config_path = temp_path("config");
    fs::write(
        &config_path,
        serde_json::to_vec(&valid_config()).expect("config must serialize"),
    )
    .expect("config fixture must write");
    let loaded = load_config(&config_path).expect("valid config must load");
    assert_eq!(loaded, valid_config());

    fs::write(
        &config_path,
        br#"{"configuration_version":"1","bind_address":"127.0.0.1:8787","max_request_body_bytes":1024,"audit_log_path":"audit.ndjson","policy":{"policy_id":"deny-all","policy_revision":"1","allowed_executables":[],"approved_manifests":[],"approved_artifacts":[]},"extra":true}"#,
    )
    .expect("strict config fixture must write");
    assert!(load_config(&config_path).is_err());

    let credential_path = temp_path("credentials");
    let credential = CredentialFile {
        admin_token: "0123456789abcdef0123456789abcdef".to_string(),
    };
    fs::write(
        &credential_path,
        serde_json::to_vec(&credential).expect("credential must serialize"),
    )
    .expect("credential fixture must write");
    assert_eq!(
        load_admin_token(&credential_path).expect("valid credential must load"),
        credential.admin_token
    );

    fs::write(&credential_path, br#"{"admin_token":"short"}"#)
        .expect("short credential fixture must write");
    assert!(load_admin_token(&credential_path).is_err());

    fs::write(
        &credential_path,
        serde_json::to_vec(&CredentialFile {
            admin_token: "x".repeat(4097),
        })
        .expect("oversized credential fixture must serialize"),
    )
    .expect("oversized credential fixture must write");
    assert!(load_admin_token(&credential_path).is_err());

    let _ = fs::remove_file(config_path);
    let _ = fs::remove_file(credential_path);
}
