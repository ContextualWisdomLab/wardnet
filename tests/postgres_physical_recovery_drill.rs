use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn required_non_empty_string<'a>(receipt: &'a Value, key: &str) -> &'a str {
    receipt
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("recovery receipt must contain non-empty {key}"))
}

#[test]
fn physical_recovery_drill_preserves_security_authority_and_zero_publication_rpo() {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let drill = repository_root.join("scripts/postgres_recovery_drill.sh");

    assert!(
        drill.is_file(),
        "Wardnet must ship an executable physical PostgreSQL backup/WAL/PITR recovery drill at {}",
        drill.display()
    );

    let output = Command::new("bash")
        .arg(&drill)
        .env("WARDNET_POSTGRES_IMAGE", "postgres:18.4-bookworm")
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {}: {error}", drill.display()));

    assert!(
        output.status.success(),
        "physical recovery drill failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "recovery drill stdout must be one machine-readable JSON receipt: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });

    assert_eq!(
        receipt.get("postgres_image").and_then(Value::as_str),
        Some("postgres:18.4-bookworm"),
        "the destructive acceptance must run against the pinned PostgreSQL 18.4 image"
    );
    assert_eq!(
        receipt.get("backup_manifest_verified").and_then(Value::as_bool),
        Some(true),
        "a base backup is not recovery evidence until its manifest verifies"
    );
    assert_eq!(
        receipt
            .get("used_archived_wal_beyond_base_backup")
            .and_then(Value::as_bool),
        Some(true),
        "the recovery target must require archived WAL committed after the base backup"
    );
    assert_eq!(
        receipt
            .get("source_destroyed_before_restore")
            .and_then(Value::as_bool),
        Some(true),
        "restore must not be able to read the live source data directory"
    );
    assert_eq!(
        receipt
            .get("recovery_reached_declared_target")
            .and_then(Value::as_bool),
        Some(true),
        "restored PostgreSQL must reach the explicitly recorded recovery target"
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
        required_non_empty_string(&receipt, key);
    }

    assert_eq!(
        receipt
            .get("rpo_lost_publication_transactions")
            .and_then(Value::as_u64),
        Some(0),
        "the controlled recovery fixture must lose zero committed Wardnet publication transactions"
    );
    assert!(
        receipt
            .get("rto_ms")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "RTO must be measured from declared restore start through the first successful bounded runtime verification"
    );

    assert_eq!(
        receipt.get("runtime_login_is_superuser").and_then(Value::as_bool),
        Some(false),
        "post-restore verification must use the ordinary bounded runtime LOGIN"
    );
    for key in [
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
        assert_eq!(
            receipt.get(key).and_then(Value::as_bool),
            Some(true),
            "recovery receipt must prove {key}"
        );
    }

    let hostile_cases = receipt
        .get("hostile_cases")
        .and_then(Value::as_object)
        .expect("recovery receipt must include hostile_cases");
    for key in [
        "corrupt_manifest_failed_closed",
        "missing_wal_failed_closed",
        "unreachable_target_failed_closed",
        "partial_role_or_rls_state_failed_closed",
    ] {
        assert_eq!(
            hostile_cases.get(key).and_then(Value::as_bool),
            Some(true),
            "recovery drill must prove hostile case {key}"
        );
    }
}
