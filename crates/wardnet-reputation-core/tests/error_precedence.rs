use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, DecisionReasonV1, DestinationContextV1,
    DestinationScopeV1, DestinationSubjectKindV1, DestinationSubjectV1, DirectionV1,
    EvidenceHealthV1, PolicyActionV1, REPUTATION_SCHEMA_V1, ReputationAssessmentV1,
};

const NOW: u64 = 1_788_652_800;

fn context() -> DestinationContextV1 {
    DestinationContextV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        direction: DirectionV1::Outbound,
        tenant_id: "tenant-example".to_owned(),
        workload_id: "workload-example".to_owned(),
        purpose: "package_metadata".to_owned(),
        operation_id: "op-error-precedence".to_owned(),
        profile_id: "protect-default".to_owned(),
        subject: DestinationSubjectV1 {
            kind: DestinationSubjectKindV1::ExactHost,
            value: "updates.example.invalid".to_owned(),
            scope: DestinationScopeV1::Exact,
        },
        canonicalization_profile: "egressweave-offline-fixture".to_owned(),
        canonicalization_version: "1".to_owned(),
    }
}

fn base_decision() -> DecisionEnvelopeV1 {
    DecisionEnvelopeV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        evaluation_id: "eval-error-precedence".to_owned(),
        context: context(),
        policy_id: "protect-default".to_owned(),
        policy_revision: 1,
        evidence_generation: "snapshot-42".to_owned(),
        assessment: ReputationAssessmentV1::Unknown,
        evidence_health: EvidenceHealthV1::Fresh,
        action: PolicyActionV1::Deny,
        reason: DecisionReasonV1::UnknownDestination,
        evaluated_at_unix: NOW,
        expires_at_unix: NOW + 60,
        evidence_refs: Vec::new(),
    }
}

#[test]
fn adverse_allow_returns_the_specific_fail_closed_error() {
    let mut decision = base_decision();
    decision.assessment = ReputationAssessmentV1::KnownMalicious;
    decision.action = PolicyActionV1::Allow;
    decision.reason = DecisionReasonV1::KnownMalicious;
    decision.evidence_refs = vec!["urn:wardnet:evidence:record-1".to_owned()];

    assert_eq!(
        decision.validate(),
        Err(ContractValidationErrorV1::UnsafeAdverseAllow),
        "an otherwise coherent adverse decision must classify the unsafe allow itself, not hide it behind a generic action/reason mismatch",
    );
}

#[test]
fn unhealthy_required_authority_allow_returns_the_specific_fail_closed_error() {
    let mut decision = base_decision();
    decision.evidence_health = EvidenceHealthV1::Unavailable;
    decision.action = PolicyActionV1::Allow;
    decision.reason = DecisionReasonV1::RequiredAuthorityUnavailable;

    assert_eq!(
        decision.validate(),
        Err(ContractValidationErrorV1::UnsafeUnhealthyEvidenceAllow),
        "an otherwise coherent required-authority outage must classify the unsafe allow itself, not hide it behind a generic action/reason mismatch",
    );
}
