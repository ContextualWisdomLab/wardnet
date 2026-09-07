use serde_json::json;
use wardnet_reputation_core::{
    ContractValidationErrorV1, EvidenceRecordV1, EvidenceSnapshotRecordV1, EvidenceSnapshotV1,
    SourceBatchCompletenessV1, SourceReplacementBatchV1, SourceReplacementErrorV1,
    SourceSnapshotV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn evidence(source_id: &str, producer_record_id: &str) -> EvidenceRecordV1 {
    serde_json::from_value(json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "source_id": source_id,
        "producer_record_id": producer_record_id,
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
        "revoked": false,
        "deleted": false,
        "enforcement_eligible": true,
        "tenant_id": "tenant-example",
        "marking": "TLP:CLEAR",
        "license_ref": "synthetic-fixture",
        "provenance_refs": ["urn:wardnet:test:source-replacement"]
    }))
    .expect("the v1 source-replacement evidence fixture must deserialize")
}

fn source_snapshot(source_id: &str, generation: &str) -> SourceSnapshotV1 {
    SourceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        source_id: source_id.to_owned(),
        source_generation: generation.to_owned(),
        completed_at_unix: NOW - 30,
        valid_until_unix: NOW + 300,
    }
}

fn member(source_id: &str, generation: &str, producer_record_id: &str) -> EvidenceSnapshotRecordV1 {
    EvidenceSnapshotRecordV1 {
        source_generation: generation.to_owned(),
        record: evidence(source_id, producer_record_id),
    }
}

fn prior_snapshot() -> EvidenceSnapshotV1 {
    let snapshot = EvidenceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        evidence_generation: "evidence-generation-8".to_owned(),
        source_snapshots: vec![
            source_snapshot("required-source", "generation-8"),
            source_snapshot("unrelated-source", "generation-3"),
        ],
        records: vec![
            member("required-source", "generation-8", "required-1"),
            member("required-source", "generation-8", "required-2"),
            member("unrelated-source", "generation-3", "unrelated-1"),
        ],
    };
    snapshot
        .validate_at(NOW)
        .expect("the prior immutable evidence snapshot must be valid");
    snapshot
}

fn replacement_batch(
    completeness: SourceBatchCompletenessV1,
    expected_previous_source_generation: Option<&str>,
    records: Vec<EvidenceSnapshotRecordV1>,
) -> SourceReplacementBatchV1 {
    SourceReplacementBatchV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        completeness,
        expected_previous_source_generation: expected_previous_source_generation.map(str::to_owned),
        source_snapshot: source_snapshot("required-source", "generation-9"),
        records,
    }
}

#[test]
fn incomplete_replacement_fails_without_changing_last_known_good_snapshot() {
    let prior = prior_snapshot();
    let retained = prior.clone();
    let truncated = replacement_batch(
        SourceBatchCompletenessV1::Incomplete,
        Some("generation-8"),
        vec![member("required-source", "generation-9", "required-1")],
    );

    assert_eq!(
        prior.replace_source(truncated, "evidence-generation-9", NOW),
        Err(SourceReplacementErrorV1::IncompleteSourceBatch)
    );
    assert_eq!(prior, retained);
}

#[test]
fn complete_empty_replacement_advances_only_one_source_and_preserves_unrelated_state() {
    let prior = prior_snapshot();
    let complete_empty = replacement_batch(
        SourceBatchCompletenessV1::Complete,
        Some("generation-8"),
        Vec::new(),
    );

    let next = prior
        .replace_source(complete_empty, "evidence-generation-9", NOW)
        .expect("an authenticated complete empty source generation is a valid replacement");

    assert_eq!(next.evidence_generation, "evidence-generation-9");
    assert!(next.source_snapshots.iter().any(|snapshot| {
        snapshot.source_id == "required-source" && snapshot.source_generation == "generation-9"
    }));
    assert!(next.source_snapshots.iter().any(|snapshot| {
        snapshot.source_id == "unrelated-source" && snapshot.source_generation == "generation-3"
    }));
    assert!(next
        .records
        .iter()
        .all(|member| member.record.source_id != "required-source"));
    assert!(next.records.iter().any(|member| {
        member.record.source_id == "unrelated-source"
            && member.source_generation == "generation-3"
            && member.record.producer_record_id == "unrelated-1"
    }));
    next.validate_at(NOW)
        .expect("the complete empty replacement must produce a valid immutable snapshot");
}

#[test]
fn replacement_rejects_mixed_source_or_generation_membership_atomically() {
    let prior = prior_snapshot();

    for records in [
        vec![member("unrelated-source", "generation-9", "foreign-record")],
        vec![member("required-source", "generation-8", "stale-generation")],
    ] {
        let replacement = replacement_batch(
            SourceBatchCompletenessV1::Complete,
            Some("generation-8"),
            records,
        );
        assert_eq!(
            prior.replace_source(replacement, "evidence-generation-9", NOW),
            Err(SourceReplacementErrorV1::SourceReplacementIdentityMismatch)
        );
    }
}

#[test]
fn source_replacement_is_compare_and_swap_bound_to_exact_prior_generation() {
    let prior = prior_snapshot();
    let stale_writer = replacement_batch(
        SourceBatchCompletenessV1::Complete,
        Some("generation-7"),
        vec![member("required-source", "generation-9", "required-3")],
    );

    assert_eq!(
        prior.replace_source(stale_writer, "evidence-generation-9", NOW),
        Err(SourceReplacementErrorV1::PreviousSourceGenerationMismatch)
    );
}

#[test]
fn source_creation_and_replacement_expectations_fail_closed_when_contradictory() {
    let prior = prior_snapshot();
    let create_existing = replacement_batch(
        SourceBatchCompletenessV1::Complete,
        None,
        vec![member("required-source", "generation-9", "required-3")],
    );
    assert_eq!(
        prior.replace_source(create_existing, "evidence-generation-9", NOW),
        Err(SourceReplacementErrorV1::PreviousSourceGenerationMismatch)
    );

    let create_new = SourceReplacementBatchV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        completeness: SourceBatchCompletenessV1::Complete,
        expected_previous_source_generation: None,
        source_snapshot: source_snapshot("new-source", "generation-1"),
        records: vec![member("new-source", "generation-1", "new-1")],
    };
    let created = prior
        .replace_source(create_new, "evidence-generation-9", NOW)
        .expect("a source absent from the prior snapshot may be created with no prior generation");
    assert!(created.source_snapshots.iter().any(|snapshot| {
        snapshot.source_id == "new-source" && snapshot.source_generation == "generation-1"
    }));

    let replace_absent = SourceReplacementBatchV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        completeness: SourceBatchCompletenessV1::Complete,
        expected_previous_source_generation: Some("generation-0".to_owned()),
        source_snapshot: source_snapshot("another-new-source", "generation-1"),
        records: Vec::new(),
    };
    assert_eq!(
        prior.replace_source(replace_absent, "evidence-generation-9", NOW),
        Err(SourceReplacementErrorV1::PreviousSourceGenerationMismatch)
    );
}

#[test]
fn changed_snapshot_cannot_reuse_immutable_evidence_generation_identity() {
    let prior = prior_snapshot();
    let replacement = replacement_batch(
        SourceBatchCompletenessV1::Complete,
        Some("generation-8"),
        Vec::new(),
    );

    assert_eq!(
        prior.replace_source(replacement, "evidence-generation-8", NOW),
        Err(SourceReplacementErrorV1::ReusedEvidenceGeneration)
    );
}

#[test]
fn invalid_complete_batch_is_rejected_by_existing_snapshot_validation() {
    let prior = prior_snapshot();
    let replacement = replacement_batch(
        SourceBatchCompletenessV1::Complete,
        Some("generation-8"),
        vec![
            member("required-source", "generation-9", "duplicate"),
            member("required-source", "generation-9", "duplicate"),
        ],
    );

    assert_eq!(
        prior.replace_source(replacement, "evidence-generation-9", NOW),
        Err(SourceReplacementErrorV1::Contract(
            ContractValidationErrorV1::DuplicateEvidenceRecord
        ))
    );
}
