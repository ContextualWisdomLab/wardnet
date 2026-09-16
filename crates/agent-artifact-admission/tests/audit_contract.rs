use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AuditSink, FileAuditSink, InstallIntent, MemoryAuditSink, admission_decision,
    build_audit_record,
};

fn sensitive_blocked_attempt() -> (
    InstallIntent,
    wardnet_agent_artifact_admission::AdmissionDecision,
) {
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv.push("sk-test-secret-raw-command".to_string());
    intent.source.uri = Some(
        "https://example.invalid/llms.txt?token=sk-test-secret-query#secret-fragment".to_string(),
    );
    let decision = admission_decision(&AdmissionPolicy::deny_all_for_test(), &intent);
    (intent, decision)
}

fn temp_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wardnet-agent-admission-{label}-{}-{nonce}.ndjson",
        std::process::id()
    ))
}

#[test]
fn audit_record_minimizes_untrusted_command_and_source_data() {
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let json = serde_json::to_string(&record).expect("audit record must serialize");

    assert!(record.timestamp_unix_ms > 0);
    assert_eq!(record.request_id, intent.request_id);
    assert_eq!(record.actor_id, intent.actor_id);
    assert_eq!(record.workspace_id, intent.workspace_id);
    assert_eq!(record.operation, "install");
    assert_eq!(record.command_sha256, decision.command_sha256);
    assert_eq!(record.request_body_sha256, None);
    assert_eq!(record.manifest_sha256, Some(intent.manifest_sha256.clone()));
    assert_eq!(
        record.normalized_source_uri.as_deref(),
        Some("https://example.invalid/llms.txt")
    );
    assert_eq!(record.artifacts.len(), 1);
    assert_eq!(record.artifacts[0].name, "@unowned/example");
    assert_eq!(
        record.artifacts[0].sha256,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );

    assert!(!json.contains("sk-test-secret-raw-command"));
    assert!(!json.contains("sk-test-secret-query"));
    assert!(!json.contains("secret-fragment"));
    assert!(!json.contains("artifact_argument"));
    assert!(!json.contains("\"argv\""));
}

#[test]
fn memory_sink_preserves_complete_records_in_append_order() {
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let sink = MemoryAuditSink::default();

    sink.append(&record).expect("first append must succeed");
    sink.append(&record).expect("second append must succeed");

    let records = sink.records().expect("memory audit snapshot must succeed");
    assert_eq!(records, vec![record.clone(), record]);
}

#[test]
fn file_sink_appends_complete_synchronized_ndjson_records() {
    let path = temp_path("append");
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let sink = FileAuditSink::new(path.clone());

    sink.append(&record).expect("first append must succeed");
    sink.append(&record).expect("second append must succeed");

    let body = fs::read_to_string(&path).expect("audit file must be readable");
    let lines: Vec<_> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("each audit line must be complete JSON");
        assert_eq!(parsed["request_id"], intent.request_id);
    }

    let _ = fs::remove_file(path);
}

#[cfg(target_os = "linux")]
#[test]
fn file_sink_rejects_existing_regular_file_with_group_or_other_permissions() {
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");

    for mode in [0o666, 0o640, 0o604] {
        let path = temp_path(&format!("unsafe-mode-{mode:o}"));
        fs::write(&path, b"existing-audit-record\n").expect("audit fixture must write");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("audit fixture permissions must be set");
        let sink = FileAuditSink::new(path.clone());

        assert!(
            sink.append(&record).is_err(),
            "pre-existing audit file mode {mode:o} must fail closed before security evidence is appended"
        );
        assert_eq!(
            fs::read(&path).expect("audit fixture must remain readable"),
            b"existing-audit-record\n",
            "unsafe pre-existing audit storage must remain unmodified"
        );

        let _ = fs::remove_file(path);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn file_sink_accepts_existing_owner_only_regular_file() {
    let path = temp_path("existing-owner-only");
    fs::write(&path, b"existing-audit-record\n").expect("audit fixture must write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("audit fixture must be owner-only");
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let sink = FileAuditSink::new(path.clone());

    sink.append(&record)
        .expect("owner-only pre-existing audit storage must remain appendable");
    let body = fs::read_to_string(&path).expect("audit file must be readable");
    assert_eq!(body.lines().count(), 2);

    let _ = fs::remove_file(path);
}

#[cfg(target_os = "linux")]
#[test]
fn file_sink_rejects_hard_linked_owner_only_regular_file() {
    let target = temp_path("hard-link-target");
    let path = temp_path("hard-link-audit");
    let original = b"sensitive-owner-only-file\n";
    fs::write(&target, original).expect("hard-link target fixture must write");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("hard-link target must be owner-only");
    fs::hard_link(&target, &path).expect("audit hard-link fixture must be created");

    let target_metadata = fs::metadata(&target).expect("target metadata must be readable");
    let audit_metadata = fs::metadata(&path).expect("audit metadata must be readable");
    assert_eq!(target_metadata.ino(), audit_metadata.ino());
    assert!(target_metadata.nlink() > 1);

    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let sink = FileAuditSink::new(path.clone());

    assert!(
        sink.append(&record).is_err(),
        "multiply-linked audit storage must fail closed before mutating the shared inode"
    );
    assert_eq!(
        fs::read(&target).expect("hard-link target must remain readable"),
        original,
        "the aliased target must remain byte-identical"
    );
    assert_eq!(
        fs::read(&path).expect("audit hard link must remain readable"),
        original,
        "the configured audit path must remain byte-identical"
    );

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(target);
}

#[cfg(target_os = "linux")]
#[test]
fn file_sink_rejects_symlinked_parent_directory_without_writing() {
    let target_directory = temp_path("parent-symlink-target").with_extension("");
    let configured_root = temp_path("parent-symlink-root").with_extension("");
    let symlinked_parent = configured_root.join("linked");
    fs::create_dir_all(&target_directory).expect("target directory fixture must be created");
    fs::create_dir_all(&configured_root).expect("configured root fixture must be created");
    std::os::unix::fs::symlink(&target_directory, &symlinked_parent)
        .expect("parent symlink fixture must be created");

    let configured_path = symlinked_parent.join("audit.ndjson");
    let resolved_target = target_directory.join("audit.ndjson");
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let sink = FileAuditSink::new(configured_path);

    let append_result = sink.append(&record);
    let redirected_file_was_created = resolved_target.exists();

    let _ = fs::remove_file(&resolved_target);
    let _ = fs::remove_file(&symlinked_parent);
    let _ = fs::remove_dir(&configured_root);
    let _ = fs::remove_dir(&target_directory);

    assert!(
        append_result.is_err(),
        "audit storage must fail closed when any parent path component is a symlink"
    );
    assert!(
        !redirected_file_was_created,
        "audit evidence must not be created through a symlinked parent directory"
    );
}

#[test]
fn file_sink_rejects_oversized_serialized_record_without_writing() {
    let path = temp_path("oversized");
    let (mut intent, decision) = sensitive_blocked_attempt();
    intent.actor_id = "x".repeat(70 * 1024);
    let mut record = build_audit_record(&intent, &decision).expect("audit record must build");
    record.policy_id = "x".repeat(70 * 1024);
    let sink = FileAuditSink::new(path.clone());

    assert!(sink.append(&record).is_err());
    assert!(!path.exists());
}

#[test]
fn file_sink_reports_deterministic_storage_failure() {
    let path = temp_path("missing-parent")
        .with_extension("")
        .join("audit.ndjson");
    let (intent, decision) = sensitive_blocked_attempt();
    let record = build_audit_record(&intent, &decision).expect("audit record must build");
    let sink = FileAuditSink::new(path);

    assert!(sink.append(&record).is_err());
}
