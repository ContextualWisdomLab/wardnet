use wardnet_reputation_core::{
    ContractValidationErrorV1, DestinationScopeV1, DestinationSubjectKindV1, DestinationSubjectV1,
    EvidenceClassificationV1, EvidenceRecordV1, EvidenceSnapshotV1, REPUTATION_SCHEMA_V1,
    SourceSnapshotV1,
};

const NOW: u64 = 1_788_652_800;

fn subject() -> DestinationSubjectV1 {
    DestinationSubjectV1 {
        kind: DestinationSubjectKindV1::ExactHost,
        value: "updates.example.invalid".to_string(),
        scope: DestinationScopeV1::Exact,
    }
}

fn source_snapshot(source_id: &str) -> SourceSnapshotV1 {
    SourceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        source_id: source_id.to_string(),
        source_generation: "source-generation-42".to_string(),
        completed_at_unix: NOW - 30,
        valid_until_unix: NOW + 300,
    }
}

fn evidence(source_id: &str, record_id: &str) -> EvidenceRecordV1 {
    EvidenceRecordV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        source_id: source_id.to_string(),
        producer_record_id: record_id.to_string(),
        producer_record_version: "1".to_string(),
        subject: subject(),
        classification: EvidenceClassificationV1::KnownMalicious,
        producer_severity: Some("high".to_string()),
        producer_confidence: Some(90),
        observed_at_unix: NOW - 120,
        received_at_unix: NOW - 60,
        valid_from_unix: NOW - 120,
        valid_until_unix: NOW + 120,
        revoked: false,
        deleted: false,
        enforcement_eligible: true,
        tenant_id: Some("tenant-example".to_string()),
        marking: Some("TLP:CLEAR".to_string()),
        license_ref: "synthetic-fixture".to_string(),
        provenance_refs: vec![format!("urn:wardnet:test:{record_id}")],
    }
}

fn snapshot() -> EvidenceSnapshotV1 {
    EvidenceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        evidence_generation: "snapshot-42".to_string(),
        source_snapshots: vec![source_snapshot("required-source")],
        records: Vec::new(),
    }
}

#[test]
fn authenticated_complete_empty_snapshot_is_distinct_from_source_unavailability() {
    let candidate = snapshot();

    candidate
        .validate_at(NOW)
        .expect("a complete current source snapshot may legitimately contain zero adverse records");

    assert_eq!(candidate.source_snapshots.len(), 1);
    assert!(candidate.records.is_empty());
}

#[test]
fn duplicate_source_snapshots_fail_closed() {
    let mut candidate = snapshot();
    candidate
        .source_snapshots
        .push(source_snapshot("required-source"));

    assert_eq!(
        candidate.validate_at(NOW),
        Err(ContractValidationErrorV1::DuplicateSourceSnapshot),
        "one source must not advertise two competing current generations in one immutable evaluation snapshot"
    );
}

#[test]
fn orphan_evidence_without_a_complete_source_snapshot_fails_closed() {
    let mut candidate = snapshot();
    candidate.records.push(evidence("other-source", "record-1"));

    assert_eq!(
        candidate.validate_at(NOW),
        Err(ContractValidationErrorV1::MissingSourceSnapshot),
        "an adverse record must not be admitted when the aggregate lacks a complete snapshot for its source authority"
    );
}

#[test]
fn future_or_inverted_source_snapshot_time_fails_closed() {
    let mut future = snapshot();
    future.source_snapshots[0].completed_at_unix = NOW + 1;
    assert_eq!(
        future.validate_at(NOW),
        Err(ContractValidationErrorV1::InvalidTimeOrder)
    );

    let mut inverted = snapshot();
    inverted.source_snapshots[0].valid_until_unix = NOW - 31;
    assert_eq!(
        inverted.validate_at(NOW),
        Err(ContractValidationErrorV1::InvalidTimeOrder)
    );
}

#[test]
fn duplicate_producer_record_identity_fails_closed() {
    let mut candidate = snapshot();
    candidate
        .records
        .push(evidence("required-source", "record-1"));
    candidate
        .records
        .push(evidence("required-source", "record-1"));

    assert_eq!(
        candidate.validate_at(NOW),
        Err(ContractValidationErrorV1::DuplicateEvidenceRecord),
        "replayed duplicate evidence must not enter an immutable source snapshot twice"
    );
}
