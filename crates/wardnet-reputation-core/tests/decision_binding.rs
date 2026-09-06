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
