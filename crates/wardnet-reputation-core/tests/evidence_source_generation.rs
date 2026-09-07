use serde_json::json;
use wardnet_reputation_core::{ContractValidationErrorV1, EvidenceSnapshotV1};

const NOW: u64 = 1_788_652_800;

fn snapshot_json(record_source_generation: &str) -> serde_json::Value {
    json!({
        "schema_version": "wardnet.reputation.v1",
        "evidence_generation": "snapshot-43",
        "source_snapshots": [{
            "schema_version": "wardnet.reputation.v1",
            "source_id": "required-source",
            "source_generation": "source-generation-43",
            "completed_at_unix": NOW - 30,
            "valid_until_unix": NOW + 300
        }],
        "records": [{
            "source_generation": record_source_generation,
            "record": {
                "schema_version": "wardnet.reputation.v1",
                "source_id": "required-source",
                "producer_record_id": "record-1",
                "producer_record_version": "7",
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
                "revoked": false,
                "deleted": false,
                "enforcement_eligible": true,
                "tenant_id": "tenant-example",
                "marking": "TLP:CLEAR",
                "license_ref": "synthetic-fixture",
                "provenance_refs": ["urn:wardnet:test:record-1"]
            }
        }]
    })
}

#[test]
fn stale_record_from_an_older_source_generation_fails_closed() {
    let stale: EvidenceSnapshotV1 = serde_json::from_value(snapshot_json("source-generation-42"))
        .expect("the v1 snapshot contract must represent exact source-generation membership");

    assert!(
        stale.validate_at(NOW).is_err(),
        "a record admitted from generation 42 must not be accepted as a member of completed generation 43"
    );
}

#[test]
fn record_bound_to_the_completed_source_generation_is_valid() {
    let current: EvidenceSnapshotV1 = serde_json::from_value(snapshot_json("source-generation-43"))
        .expect("the v1 snapshot contract must represent exact source-generation membership");

    current
        .validate_at(NOW)
        .expect("a record bound to the represented completed source generation remains valid");
}

#[test]
fn admitted_source_generation_is_bounded_before_membership_matching() {
    let oversized_generation = "g".repeat(1_025);
    let snapshot: EvidenceSnapshotV1 = serde_json::from_value(snapshot_json(&oversized_generation))
        .expect("oversized untrusted text reaches explicit contract validation");

    assert_eq!(
        snapshot.validate_at(NOW),
        Err(ContractValidationErrorV1::BoundExceeded(
            "snapshot_record.source_generation"
        )),
        "membership matching must not accept or scan an unbounded source-generation identity"
    );
}
