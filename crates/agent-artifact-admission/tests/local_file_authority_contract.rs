#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AdmissionServiceConfig, CredentialFile, load_admin_token, load_config,
};

fn temp_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-agent-local-file-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn valid_config() -> AdmissionServiceConfig {
    AdmissionServiceConfig {
        configuration_version: "1".to_string(),
        bind_address: "127.0.0.1:8787".to_string(),
        max_request_body_bytes: 64 * 1024,
        audit_log_path: "/var/lib/wardnet/agent-artifact-admission.ndjson".to_string(),
        policy: AdmissionPolicy {
            policy_id: "deny-all".to_string(),
            policy_revision: "test".to_string(),
            allowed_executables: Vec::new(),
            approved_manifests: Vec::new(),
            approved_artifacts: Vec::new(),
        },
    }
}

#[test]
fn credential_loader_rejects_final_symlink_even_to_owner_only_regular_file() {
    let target = temp_path("credential-target.json");
    let link = temp_path("credential-link.json");
    let credential = CredentialFile {
        admin_token: "0123456789abcdef0123456789abcdef".to_string(),
    };

    fs::write(
        &target,
        serde_json::to_vec(&credential).expect("credential fixture must serialize"),
    )
    .expect("credential target must write");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("credential target must be owner-only");
    symlink(&target, &link).expect("credential symlink must be created");

    assert!(
        load_admin_token(&link).is_err(),
        "a symlink must not become credential-path authority even when its target is owner-only"
    );

    let _ = fs::remove_file(link);
    let _ = fs::remove_file(target);
}

#[test]
fn policy_loader_rejects_final_symlink_even_to_integrity_protected_regular_file() {
    let target = temp_path("policy-target.json");
    let link = temp_path("policy-link.json");

    fs::write(
        &target,
        serde_json::to_vec(&valid_config()).expect("policy fixture must serialize"),
    )
    .expect("policy target must write");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
        .expect("policy target must not be group/other writable");
    symlink(&target, &link).expect("policy symlink must be created");

    assert!(
        load_config(&link).is_err(),
        "a symlink must not become reviewed policy-path authority even when its target is not group/other writable"
    );

    let _ = fs::remove_file(link);
    let _ = fs::remove_file(target);
}
