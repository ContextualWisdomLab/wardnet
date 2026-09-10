#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AdmissionServiceConfig, CredentialFile, load_admin_token, load_config,
};

#[cfg(target_os = "linux")]
const FIFO_HELPER_PATH: &str = "WARDNET_ADMISSION_FIFO_HELPER_PATH";
#[cfg(target_os = "linux")]
const HELPER_DEADLINE: Duration = Duration::from_secs(3);

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

#[cfg(target_os = "linux")]
#[test]
fn loaders_reject_fifo_without_blocking_before_file_type_validation() {
    let fifo_path = temp_path("authority-fifo");
    let mkfifo = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo must be available on the Linux test runner");
    assert!(mkfifo.success(), "FIFO fixture must be created");

    let executable = std::env::current_exe().expect("current test executable must resolve");
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg("local_authority_fifo_open_helper")
        .arg("--nocapture")
        .env(FIFO_HELPER_PATH, &fifo_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("isolated FIFO helper must start");

    let deadline = Instant::now() + HELPER_DEADLINE;
    let status = loop {
        match child
            .try_wait()
            .expect("FIFO helper status must be readable")
        {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            None => break None,
        }
    };

    let _ = fs::remove_file(&fifo_path);

    match status {
        Some(status) => assert!(
            status.success(),
            "both local authority readers must reject a FIFO through their stable fail-closed errors"
        ),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "an admission local-file reader blocked while opening a FIFO; special inputs must fail closed promptly"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn local_authority_fifo_open_helper() {
    let Ok(path) = std::env::var(FIFO_HELPER_PATH) else {
        return;
    };
    let path = PathBuf::from(path);

    assert!(load_admin_token(&path).is_err());
    assert!(load_config(&path).is_err());
}
