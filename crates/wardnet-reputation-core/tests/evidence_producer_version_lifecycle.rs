use serde_json::json;
use wardnet_reputation_core::{
    ContractValidationErrorV1, EvidenceRecordV1, ProducerRecordLifecycleCursorV1,
};

const NOW: u64 = 1_788_652_800;

fn evidence(
    source_id: &str,
    producer_record_id: &str,
    producer_record_version: &str,
    revoked: bool,
    deleted: bool,
    enforcement_eligible: bool,
) -> EvidenceRecordV1 {
    serde_json::from_value(json!({
        "schema_version": "wardnet.reputation.v1",
        "source_id": source_id,
        "producer_record_id": producer_record_id,
        "producer_record_version": producer_record_version,
        "subject": {
            "kind": "exact_host",
            "value": "updates.example.invalid",
            "scope": "exact"
        },
        "classification": "known_malicious",
        "producer_severity": "high",
        "producer_confidence": 90,
        "observed_at_unix": NOW - 120,
        "received_at_unix": NOW - 60,
        "valid_from_unix": NOW - 120,
        "valid_until_unix": NOW + 120,
        "revoked": revoked,
        "deleted": deleted,
        "enforcement_eligible": enforcement_eligible,
        "tenant_id": "tenant-example",
        "marking": "TLP:CLEAR",
        "license_ref": "synthetic-fixture",
        "provenance_refs": ["urn:wardnet:test:record-1"]
    }))
    .expect("the v1 producer evidence fixture must deserialize")
}

fn cursor(version: &str, ordinal: u64, tombstoned: bool) -> ProducerRecordLifecycleCursorV1 {
    ProducerRecordLifecycleCursorV1 {
        schema_version: "wardnet.reputation.v1".to_owned(),
        source_id: "required-source".to_owned(),
        producer_record_id: "record-1".to_owned(),
        producer_record_version: version.to_owned(),
        producer_version_ordinal: ordinal,
        tombstoned,
    }
}

#[test]
fn older_active_version_cannot_replay_after_tombstone() {
    let current = cursor("8", 8, true);
    let replay = evidence("required-source", "record-1", "7", false, false, true);

    assert_eq!(
        current.admit(&replay, 7, NOW),
        Err(ContractValidationErrorV1::StaleProducerRecordVersion)
    );
}

#[test]
fn tombstoned_identity_cannot_be_reactivated_at_same_or_newer_ordinal() {
    let current = cursor("8", 8, true);

    for (version, ordinal) in [("8", 8), ("9", 9)] {
        let replay = evidence(
            "required-source",
            "record-1",
            version,
            false,
            false,
            true,
        );
        assert_eq!(
            current.admit(&replay, ordinal, NOW),
            Err(ContractValidationErrorV1::TombstoneResurrection),
            "tombstoned producer identity must remain terminal at ordinal {ordinal}"
        );
    }
}

#[test]
fn tombstone_replay_is_idempotent() {
    let current = cursor("8", 8, true);
    let replay = evidence("required-source", "record-1", "8", true, false, false);

    assert_eq!(current.admit(&replay, 8, NOW), Ok(current));
}

#[test]
fn active_cursor_can_advance_and_then_transition_to_tombstone() {
    let current = cursor("8", 8, false);
    let next = evidence("required-source", "record-1", "9", false, false, true);
    let advanced = current
        .admit(&next, 9, NOW)
        .expect("newer active producer evidence may advance the lifecycle cursor");
    assert_eq!(advanced.producer_record_version, "9");
    assert_eq!(advanced.producer_version_ordinal, 9);
    assert!(!advanced.tombstoned);

    let tombstone = evidence("required-source", "record-1", "10", true, false, false);
    let terminal = advanced
        .admit(&tombstone, 10, NOW)
        .expect("newer producer lifecycle evidence may establish a tombstone");
    assert_eq!(terminal.producer_record_version, "10");
    assert_eq!(terminal.producer_version_ordinal, 10);
    assert!(terminal.tombstoned);
}

#[test]
fn equal_ordinal_with_different_opaque_version_token_fails_closed() {
    let current = cursor("8", 8, false);
    let collision = evidence("required-source", "record-1", "8b", false, false, true);

    assert_eq!(
        current.admit(&collision, 8, NOW),
        Err(ContractValidationErrorV1::ProducerRecordVersionCollision)
    );
}

#[test]
fn lifecycle_cursor_rejects_different_source_or_record_identity() {
    let current = cursor("8", 8, false);

    for candidate in [
        evidence("other-source", "record-1", "9", false, false, true),
        evidence("required-source", "record-2", "9", false, false, true),
    ] {
        assert_eq!(
            current.admit(&candidate, 9, NOW),
            Err(ContractValidationErrorV1::LifecycleIdentityMismatch)
        );
    }
}
