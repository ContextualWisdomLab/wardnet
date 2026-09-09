use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn required_string<'a>(receipt: &'a Value, key: &str) -> &'a str {
    receipt
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("recovery receipt must contain {key}"))
}

fn required_true(receipt: &Value, key: &str) {
    let value = receipt.get(key).and_then(Value::as_bool);
    assert_eq!(value, Some(true), "recovery receipt must prove {key}");
}

fn required_u64(receipt: &Value, key: &str) -> u64 {
    receipt
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("recovery receipt must contain integer {key}"))
}

#[test]
fn physical_recovery_drill_preserves_security_authority_and_zero_publication_rpo() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let drill = root.join("scripts/postgres_recovery_drill.sh");
    assert!(drill.is_file(), "physical recovery drill must exist");

    let output = Command::new("bash")
        .arg(&drill)
        .env("WARDNET_POSTGRES_IMAGE", "postgres:18.4-bookworm")
        .output()
        .expect("physical recovery drill must execute");
    assert!(
        output.status.success(),
        "recovery drill failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout)
        .expect("recovery drill stdout must be one JSON receipt");
    assert_eq!(
        receipt.get("postgres_image").and_then(Value::as_str),
        Some("postgres:18.4-bookworm")
    );

    for key in [
        "source_timeline",
        "source_wal_lsn",
        "backup_start_lsn",
        "backup_end_lsn",
        "backup_manifest_sha256",
        "recovery_target_lsn",
        "latest_recovered_lsn",
    ] {
        required_string(&receipt, key);
    }

    for key in [
        "backup_manifest_verified",
        "used_archived_wal_beyond_base_backup",
        "source_destroyed_before_restore",
        "recovery_reached_declared_target",
        "runtime_rls_enforced",
        "tenant_isolation_verified",
        "publication_history_verified",
        "audit_attribution_verified",
        "current_head_verified",
        "schema_version_verified",
        "historical_aba_rejected",
        "divergent_replay_rejected",
        "unbound_runtime_has_no_tenant_authority",
        "post_restore_publication_committed",
    ] {
        required_true(&receipt, key);
    }

    assert_eq!(
        required_u64(&receipt, "rpo_lost_publication_transactions"),
        0
    );
    assert!(required_u64(&receipt, "rto_ms") > 0);
    assert_eq!(
        receipt
            .get("runtime_login_is_superuser")
            .and_then(Value::as_bool),
        Some(false)
    );

    let hostile = receipt
        .get("hostile_cases")
        .expect("recovery receipt must contain hostile_cases");
    for key in [
        "corrupt_manifest_failed_closed",
        "missing_wal_failed_closed",
        "unreachable_target_failed_closed",
        "partial_schema_or_rls_state_failed_closed",
        "unsafe_role_mapping_failed_closed",
    ] {
        required_true(hostile, key);
    }
}
