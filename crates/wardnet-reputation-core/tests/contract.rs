use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use wardnet_reputation_core::{
    ContractValidationErrorV1, DestinationContextV1, DestinationScopeV1, DestinationSubjectKindV1,
    DestinationSubjectV1, DirectionV1, EvaluationModeV1, EvidenceClassificationV1,
    EvidenceRecordV1, PolicySnapshotV1, REPUTATION_SCHEMA_V1, SourcePolicyV1,
    SourceTenantScopeV1,
};

const NOW: u64 = 1_788_652_800;

fn subject() -> DestinationSubjectV1 {
    DestinationSubjectV1 {
        kind: DestinationSubjectKindV1::ExactHost,
        value: "updates.example.invalid".to_string(),
        scope: DestinationScopeV1::Exact,
    }
}

fn context() -> DestinationContextV1 {
    DestinationContextV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        direction: DirectionV1::Outbound,
        tenant_id: "tenant-example".to_string(),
        workload_id: "workload-example".to_string(),
        purpose: "package_metadata".to_string(),
        operation_id: "op-0001".to_string(),
        profile_id: "protect-default".to_string(),
        subject: subject(),
        canonicalization_profile: "egressweave-offline-fixture".to_string(),
        canonicalization_version: "1".to_string(),
    }
}

fn source_policy() -> SourcePolicyV1 {
    SourcePolicyV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        source_id: "reviewed-source".to_string(),
        enforcement_capable: true,
        permitted_subject_kinds: vec![DestinationSubjectKindV1::ExactHost],
        max_evidence_age_seconds: 3_600,
        tenant_scope: SourceTenantScopeV1::ExplicitTenantSet,
        allowed_tenant_ids: vec!["tenant-example".to_string()],
        allowed_purposes: vec!["package_metadata".to_string()],
    }
}

fn evidence() -> EvidenceRecordV1 {
    EvidenceRecordV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        source_id: "reviewed-source".to_string(),
        producer_record_id: "record-1".to_string(),
        producer_record_version: "1".to_string(),
        subject: subject(),
        classification: EvidenceClassificationV1::KnownMalicious,
        producer_severity: Some("high".to_string()),
        producer_confidence: Some(80),
        observed_at_unix: NOW - 120,
        received_at_unix: NOW - 60,
        valid_from_unix: NOW - 120,
        valid_until_unix: NOW + 600,
        revoked: false,
        deleted: false,
        enforcement_eligible: true,
        tenant_id: Some("tenant-example".to_string()),
        marking: Some("TLP:CLEAR".to_string()),
        license_ref: "synthetic-fixture".to_string(),
        provenance_refs: vec!["urn:wardnet:test:record-1".to_string()],
    }
}

fn assert_unknown_field_rejected<T>(candidate: T, field: &str)
where
    T: Serialize + DeserializeOwned,
{
    let mut value = serde_json::to_value(candidate).expect("contract serializes");
    value
        .as_object_mut()
        .expect("wire contract serializes as an object")
        .insert(field.to_string(), json!(true));
    assert!(
        serde_json::from_value::<T>(value).is_err(),
        "v1 wire contract must reject unknown field {field}"
    );
}

#[test]
fn rejects_wrong_direction_and_unknown_schema() {
    let mut candidate = context();
    candidate.direction = DirectionV1::Inbound;
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::WrongDirection)
    );

    let mut candidate = context();
    candidate.schema_version = "wardnet.reputation.v2".to_string();
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::UnsupportedSchema)
    );
}

#[test]
fn rejects_blank_authenticated_context_fields() {
    for field in ["workload_id", "purpose"] {
        let mut candidate = context();
        match field {
            "workload_id" => candidate.workload_id = " \t".to_string(),
            "purpose" => candidate.purpose.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            candidate.validate(),
            Err(ContractValidationErrorV1::BlankField(field))
        );
    }
}

#[test]
fn rejects_ambiguous_subject_scope() {
    let mut candidate = context();
    candidate.subject.kind = DestinationSubjectKindV1::ObservableUrl;
    candidate.subject.scope = DestinationScopeV1::HostAndSubdomains;
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::AmbiguousSubjectScope)
    );
}

#[test]
fn rejects_missing_required_source_policy() {
    let policy = PolicySnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_string(),
        policy_id: "protect-default".to_string(),
        revision: 1,
        mode: EvaluationModeV1::Protect,
        required_sources: Vec::new(),
        valid_from_unix: NOW - 60,
        valid_until_unix: NOW + 600,
    };
    assert_eq!(
        policy.validate_at(NOW),
        Err(ContractValidationErrorV1::EmptyRequiredSources)
    );
}

#[test]
fn rejects_invalid_evidence_time_order_and_confidence() {
    let mut candidate = evidence();
    candidate.valid_from_unix = NOW + 10;
    candidate.valid_until_unix = NOW;
    assert_eq!(
        candidate.validate_at(NOW),
        Err(ContractValidationErrorV1::InvalidTimeOrder)
    );

    let mut candidate = evidence();
    candidate.producer_confidence = Some(101);
    assert_eq!(
        candidate.validate_at(NOW),
        Err(ContractValidationErrorV1::InvalidConfidence)
    );
}

#[test]
fn rejects_enforcement_evidence_without_provenance() {
    let mut candidate = evidence();
    candidate.provenance_refs.clear();

    assert_eq!(
        candidate.validate_at(NOW),
        Err(ContractValidationErrorV1::MissingEnforcementProvenance),
        "enforcement-eligible evidence without provenance must fail closed"
    );
}

#[test]
fn rejects_unknown_evidence_fields_that_could_widen_scope() {
    let mut value = serde_json::to_value(evidence()).expect("evidence serializes");
    let object = value
        .as_object_mut()
        .expect("evidence contract serializes as an object");
    object.remove("tenant_id");
    object.insert("tenant_ids".to_string(), json!(["tenant-example"]));

    let decoded = serde_json::from_value::<EvidenceRecordV1>(value);
    assert!(
        decoded.is_err(),
        "an unrecognized tenant restriction must fail closed instead of degrading to global evidence"
    );
}

#[test]
fn rejects_unknown_fields_across_nondecision_v1_wire_structs() {
    assert_unknown_field_rejected(subject(), "unexpected_subject_field");
    assert_unknown_field_rejected(context(), "caller_authenticated");
    assert_unknown_field_rejected(evidence(), "unexpected_evidence_scope");
    assert_unknown_field_rejected(source_policy(), "fallback_allow");
    assert_unknown_field_rejected(
        PolicySnapshotV1 {
            schema_version: REPUTATION_SCHEMA_V1.to_string(),
            policy_id: "protect-default".to_string(),
            revision: 1,
            mode: EvaluationModeV1::Protect,
            required_sources: vec!["reviewed-source".to_string()],
            valid_from_unix: NOW - 60,
            valid_until_unix: NOW + 600,
        },
        "unknown_policy_extension",
    );
}

#[test]
fn rejects_empty_source_eligibility() {
    let mut candidate = source_policy();
    candidate.permitted_subject_kinds.clear();
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::EmptySourceEligibility)
    );

    let mut candidate = source_policy();
    candidate.allowed_purposes.clear();
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::EmptySourceEligibility)
    );
}

#[test]
fn rejects_source_policy_without_explicit_tenant_eligibility() {
    let mut value = serde_json::to_value(source_policy()).expect("source policy serializes");
    let object = value
        .as_object_mut()
        .expect("source policy serializes as an object");
    object.remove("tenant_scope");
    object.remove("allowed_tenant_ids");

    assert!(
        serde_json::from_value::<SourcePolicyV1>(value).is_err(),
        "a reviewed source must declare tenant eligibility explicitly instead of silently widening to every tenant"
    );
}

#[test]
fn rejects_ambiguous_source_tenant_eligibility() {
    let mut candidate = source_policy();
    candidate.tenant_scope = SourceTenantScopeV1::ExplicitTenantSet;
    candidate.allowed_tenant_ids.clear();
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::InvalidTenantEligibility)
    );

    let mut candidate = source_policy();
    candidate.tenant_scope = SourceTenantScopeV1::AllAuthenticatedTenants;
    assert_eq!(
        candidate.validate(),
        Err(ContractValidationErrorV1::InvalidTenantEligibility)
    );
}

#[test]
fn accepts_reviewed_all_authenticated_tenant_scope_without_tenant_list() {
    let mut candidate = source_policy();
    candidate.tenant_scope = SourceTenantScopeV1::AllAuthenticatedTenants;
    candidate.allowed_tenant_ids.clear();
    candidate
        .validate()
        .expect("explicit reviewed all-tenant eligibility remains a valid source policy");
}

#[derive(Debug, Deserialize)]
struct ContractFixture {
    case_id: String,
    now_unix: u64,
    context: DestinationContextV1,
    source_policy: SourcePolicyV1,
    evidence: Vec<EvidenceRecordV1>,
    expected_assessment: String,
    expected_action: String,
    expected_reason: String,
    expected_visibility: String,
}

#[test]
fn exact_host_fixture_round_trips_stably() {
    let fixture: ContractFixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reputation/v1/exact_host_roundtrip.json"
    ))
    .expect("synthetic contract fixture is valid JSON");

    assert_eq!(fixture.case_id, "REP-CONTRACT-ROUNDTRIP-01");
    assert_eq!(fixture.now_unix, NOW);
    assert_eq!(fixture.expected_assessment, "unknown");
    assert_eq!(fixture.expected_action, "deny");
    assert_eq!(fixture.expected_reason, "unknown_destination");
    assert_eq!(fixture.expected_visibility, "exact_host");
    assert!(fixture.evidence.is_empty());
    fixture
        .context
        .validate()
        .expect("fixture context is valid");
    fixture
        .source_policy
        .validate()
        .expect("fixture source policy is valid");

    let encoded = serde_json::to_string(&fixture.context).expect("context serializes");
    let decoded: DestinationContextV1 =
        serde_json::from_str(&encoded).expect("context deserializes");
    assert_eq!(decoded, fixture.context);
}