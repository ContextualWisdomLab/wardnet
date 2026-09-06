use serde_json::{Value, json};
use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn decision_json(workload_id: &str, evidence_generation: &str) -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-0001",
        "policy_id": "protect-default",
        "policy_revision": 1,
        "assessment": "unknown",
        "evidence_health": "fresh",
        "action": "deny",
        "reason": "unknown_destination",
        "evaluated_at_unix": NOW,
        "expires_at_unix": NOW + 60,
        "evidence_refs": [],
        "context": {
            "schema_version": REPUTATION_SCHEMA_V1,
            "direction": "outbound",
            "tenant_id": "tenant-example",
            "workload_id": workload_id,
            "purpose": "package_metadata",
            "operation_id": "op-0001",
            "profile_id": "protect-default",
            "subject": {
                "kind": "exact_host",
                "value": "updates.example.invalid",
                "scope": "exact"
            },
            "canonicalization_profile": "egressweave-offline-fixture",
            "canonicalization_version": "1"
        },
        "evidence_generation": evidence_generation
    })
}

fn business_authorization_json(workload_id: &str) -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "authorization_id": "authz-0001",
        "authorization_revision": 1,
        "policy_id": "protect-default",
        "policy_revision": 1,
        "authority": "security-change-authority",
        "origin": "change-ticket",
        "tenant_id": "tenant-example",
        "workload_id": workload_id,
        "purpose": "package_metadata",
        "profile_id": "protect-default",
        "subject": {
            "kind": "exact_host",
            "value": "updates.example.invalid",
            "scope": "exact"
        },
        "canonicalization_profile": "egressweave-offline-fixture",
        "canonicalization_version": "1",
        "valid_from_unix": NOW - 60,
        "valid_until_unix": NOW + 120,
        "revoked": false,
        "approver_id": "approver-example",
        "ticket_ref": "SEC-1234",
        "provenance_refs": ["urn:wardnet:authorization:authz-0001:1"]
    })
}

fn add_business_authorization(value: &mut Value, workload_id: &str) {
    value["business_authorization"] = business_authorization_json(workload_id);
}

#[test]
fn decision_envelope_rejects_unknown_wire_fields() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["transport_authorized"] = json!(true);

    assert!(
        serde_json::from_value::<DecisionEnvelopeV1>(value).is_err(),
        "v1 decision readers must reject unknown transport or authorization claims instead of ignoring them"
    );
}

#[test]
fn decision_envelope_rejects_invalid_authenticated_context_binding() {
    let decision: DecisionEnvelopeV1 = serde_json::from_value(decision_json("", "snapshot-42"))
        .expect("v1 decision envelope should deserialize");

    assert_eq!(
        decision.validate(),
        Err(ContractValidationErrorV1::BlankField("workload_id"))
    );
}

#[test]
fn decision_envelope_rejects_missing_evidence_generation_binding() {
    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(decision_json("workload-example", ""))
            .expect("v1 decision envelope should deserialize");

    assert_eq!(
        decision.validate(),
        Err(ContractValidationErrorV1::BlankField("evidence_generation"))
    );
}

#[test]
fn decision_envelope_rejects_untraceable_adverse_assessment() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["assessment"] = json!("known_malicious");
    value["reason"] = json!("known_malicious");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "known-malicious decisions without evidence references must fail closed"
    );
}

#[test]
fn decision_envelope_rejects_known_malicious_allow() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["assessment"] = json!("known_malicious");
    value["action"] = json!("allow");
    value["reason"] = json!("known_malicious");
    value["evidence_refs"] = json!(["urn:wardnet:evidence:record-1"]);

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "known-malicious assessments must never serialize as an allow action"
    );
}

#[test]
fn decision_envelope_rejects_unavailable_required_authority_allow() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["evidence_health"] = json!("unavailable");
    value["action"] = json!("allow");
    value["reason"] = json!("required_authority_unavailable");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "required-authority outage must never serialize as a reputation allow"
    );
}

#[test]
fn decision_envelope_rejects_known_malicious_with_non_adverse_reason() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["assessment"] = json!("known_malicious");
    value["reason"] = json!("unknown_destination");
    value["evidence_refs"] = json!(["urn:wardnet:evidence:record-1"]);

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "known-malicious assessments must not serialize with a contradictory SOC reason"
    );
}

#[test]
fn decision_envelope_rejects_adverse_reason_for_unknown_assessment() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["reason"] = json!("suspicious");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "adverse SOC reasons must not be detached from the matching adverse assessment"
    );
}

#[test]
fn decision_envelope_accepts_consistent_suspicious_denial() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["assessment"] = json!("suspicious");
    value["reason"] = json!("suspicious");
    value["evidence_refs"] = json!(["urn:wardnet:evidence:record-2"]);

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    decision
        .validate()
        .expect("consistent suspicious deny must remain a valid reputation decision");
}

#[test]
fn decision_envelope_accepts_authority_failure_reason_over_adverse_assessment() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["assessment"] = json!("suspicious");
    value["evidence_health"] = json!("unavailable");
    value["reason"] = json!("required_authority_unavailable");
    value["evidence_refs"] = json!(["urn:wardnet:evidence:record-2"]);

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    decision.validate().expect(
        "higher-precedence required-authority failure must remain explainable without erasing the adverse assessment",
    );
}

#[test]
fn decision_envelope_rejects_unknown_destination_reason_on_allow() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["action"] = json!("allow");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "unknown_destination describes a protect denial and must not validate as an allow reason"
    );
}

#[test]
fn decision_envelope_rejects_invalid_contract_reason_on_allow() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["action"] = json!("allow");
    value["reason"] = json!("invalid_contract");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert!(
        decision.validate().is_err(),
        "invalid_contract is fail-closed and must never validate as an allow reason"
    );
}

#[test]
fn decision_envelope_accepts_business_authorization_allow_with_fresh_evidence() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["action"] = json!("allow");
    value["reason"] = json!("business_authorization");
    add_business_authorization(&mut value, "workload-example");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    decision.validate().expect(
        "unknown plus an exact-scope business authorization may continue when required evidence is fresh",
    );
}

#[test]
fn decision_envelope_accepts_business_authorization_allow_with_optional_degradation() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["evidence_health"] = json!("degraded");
    value["action"] = json!("allow");
    value["reason"] = json!("business_authorization");
    add_business_authorization(&mut value, "workload-example");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    decision.validate().expect(
        "optional-source degradation may coexist with an authorized unknown allow while required sources remain healthy",
    );
}

#[test]
fn decision_envelope_rejects_business_authorization_reason_on_deny() {
    let mut value = decision_json("workload-example", "snapshot-42");
    value["reason"] = json!("business_authorization");

    let decision: DecisionEnvelopeV1 =
        serde_json::from_value(value).expect("v1 decision envelope should deserialize");

    assert_eq!(
        decision.validate(),
        Err(ContractValidationErrorV1::InconsistentActionReason)
    );
}
