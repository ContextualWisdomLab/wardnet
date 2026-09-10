#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{AdmissionPolicy, AdmissionServiceConfig, load_config};

fn temp_path() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-admission-policy-permissions-{}-{nonce}.json",
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
            policy_revision: "config-permission-red".to_string(),
            allowed_executables: Vec::new(),
            approved_manifests: Vec::new(),
            approved_artifacts: Vec::new(),
        },
    }
}

#[test]
fn configuration_loader_rejects_group_or_other_write_authority() {
    let path = temp_path();
    let encoded = serde_json::to_vec(&valid_config()).expect("config must serialize");
    fs::write(&path, encoded).expect("config fixture must write");

    for safe_mode in [0o600, 0o640, 0o644, 0o400] {
        fs::set_permissions(&path, fs::Permissions::from_mode(safe_mode))
            .expect("safe configuration mode must apply");
        assert!(
            load_config(&path).is_ok(),
            "read-only group/other visibility must not be confused with policy mutation authority: {safe_mode:o}"
        );
    }

    for unsafe_mode in [0o660, 0o606, 0o664, 0o646, 0o666] {
        fs::set_permissions(&path, fs::Permissions::from_mode(unsafe_mode))
            .expect("unsafe configuration mode must apply");
        assert!(
            load_config(&path).is_err(),
            "configuration mode {unsafe_mode:o} grants group/other policy mutation authority"
        );
    }

    let _ = fs::remove_file(path);
}
