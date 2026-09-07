use serde_json::json;
use wardnet_reputation_core::EvidenceSnapshotV1;

const NOW: u64 = 1_788_652_800;

fn snapshot_with_lifecycle(
    revoked: bool,
    deleted: bool,
    enforcement_eligible: bool,
) -> EvidenceSnapshotV1 {
    serde_json::from_value(json!({
        "schema_version": "wardnet.reputation.v1",
        "evidence_generation": "snapshot-44",
        "source_snapshots": [{
            "schema_version": "wardnet.reputation.v1",
            "source_id": "required-source",
            "source_generation": "source-generation-44",
            "completed_at_unix": NOW - 30,
            "valid_until_unix": NOW + 300
        }],
        "records": [{
            "source_generation": "source-generation-44",
            "record": {
                "schema_version": "wardnet.reputation.v1",
                "source_id": "required-source",
                "producer_record_id": "record-1",
                "producer_record_version": "8",
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
            }
        }]
    }))
    .expect("the v1 contract must deserialize lifecycle state explicitly")
}

#[test]
fn revoked_or_deleted_records_cannot_remain_enforcement_eligible() {
    for (revoked, deleted, case_name) in [
        (true, false, "revoked"),
        (false, true, "deleted"),
        (true, true, "revoked-and-deleted"),
    ] {
        let snapshot = snapshot_with_lifecycle(revoked, deleted, true);
        assert!(
            snapshot.validate_at(NOW).is_err(),
            "{case_name} evidence must fail closed when it still claims enforcement eligibility"
        );
    }
}

#[test]
fn active_enforcement_evidence_remains_valid() {
    snapshot_with_lifecycle(false, false, true)
        .validate_at(NOW)
        .expect("active evidence with exact generation lineage remains enforcement eligible");
}

#[test]
fn revoked_or_deleted_records_remain_valid_as_non_enforcement_history() {
    for (revoked, deleted) in [(true, false), (false, true), (true, true)] {
        snapshot_with_lifecycle(revoked, deleted, false)
            .validate_at(NOW)
            .expect("producer lifecycle history remains representable when it cannot enforce");
    }
}
