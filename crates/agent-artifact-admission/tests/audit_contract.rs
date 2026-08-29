use std::fs;
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
    let record = build_audit_record(&intent, &decision);
    let json = serde_json::to_string(&record).expect("audit record must serialize");

    assert!(record.timestamp_unix_ms > 0);
    assert_eq!(record.request_id, intent.request_id);
    assert_eq!(record.actor_id, intent.actor_id);
    assert_eq!(record.workspace_id, intent.workspace_id);
    assert_eq!(record.operation, "install");
    assert_eq!(record.command_sha256, decision.command_sha256);
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
    let record = build_audit_record(&intent, &decision);
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
    let record = build_audit_record(&intent, &decision);
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

#[test]
fn file_sink_rejects_oversized_serialized_record_without_writing() {
    let path = temp_path("oversized");
    let (mut intent, decision) = sensitive_blocked_attempt();
    intent.actor_id = "x".repeat(70 * 1024);
    let record = build_audit_record(&intent, &decision);
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
    let record = build_audit_record(&intent, &decision);
    let sink = FileAuditSink::new(path);

    assert!(sink.append(&record).is_err());
}
