#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AuditError, AuditRecord, AuditSink, FileAuditSink, InstallIntent,
    admission_decision, build_audit_record,
};

const UMASK_HELPER_PATH: &str = "WARDNET_AUDIT_UMASK_HELPER_PATH";

fn temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-agent-admission-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn blocked_record() -> AuditRecord {
    let intent = InstallIntent::unowned_llms_package_for_test();
    let decision = admission_decision(&AdmissionPolicy::deny_all_for_test(), &intent);
    build_audit_record(&intent, &decision).expect("audit record must build")
}

#[test]
fn file_sink_rejects_final_symlink_without_modifying_target() {
    let target = temp_path("audit-symlink-target");
    let audit_path = temp_path("audit-symlink-path");
    fs::write(&target, b"sentinel\n").expect("sentinel target must be created");
    symlink(&target, &audit_path).expect("audit symlink must be created");

    let result = FileAuditSink::new(audit_path.clone()).append(&blocked_record());

    assert_eq!(result, Err(AuditError::StorageUnavailable));
    assert_eq!(
        fs::read(&target).expect("sentinel target must remain readable"),
        b"sentinel\n"
    );

    let _ = fs::remove_file(audit_path);
    let _ = fs::remove_file(target);
}

#[test]
fn newly_created_audit_file_is_private_even_with_permissive_umask() {
    let audit_path = temp_path("audit-private-mode");
    let executable = std::env::current_exe().expect("current test executable must resolve");
    let status = Command::new("sh")
        .arg("-c")
        .arg("umask 000; exec \"$0\" --exact audit_creation_under_permissive_umask_helper --nocapture")
        .arg(executable)
        .env(UMASK_HELPER_PATH, &audit_path)
        .status()
        .expect("isolated umask helper must start");
    assert!(status.success(), "isolated umask helper must succeed");

    let mode = fs::metadata(&audit_path)
        .expect("audit file must exist")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o077,
        0,
        "audit evidence must not grant group/other permissions"
    );

    let _ = fs::remove_file(audit_path);
}

#[test]
fn audit_creation_under_permissive_umask_helper() {
    let Ok(path) = std::env::var(UMASK_HELPER_PATH) else {
        return;
    };
    FileAuditSink::new(path)
        .append(&blocked_record())
        .expect("audit append under isolated umask must succeed");
}
