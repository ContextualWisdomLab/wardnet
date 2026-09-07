use serde_json::{Value, json};
use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn decision_json() -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-decision-freshness",
        "policy_id": "protect-default",
        "policy_revision": 1,
        "policy_mode": "protect",
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
            "workload_id": "workload-example",
            "purpose": "package_metadata",
            "operation_id": "op-decision-freshness",
            "profile_id": "protect-default",
            "subject": {
                "kind": "exact_host",
                "value": "updates.example.invalid",
                "scope": "exact"
            },
            "canonicalization_profile": "egressweave-offline-fixture",
            "canonicalization_version": "1"
        },
        "evidence_generation": "snapshot-42"
    })
}

fn decision(value: Value) -> DecisionEnvelopeV1 {
    serde_json::from_value(value).expect("the v1 decision envelope should deserialize")
}

#[test]
fn live_validation_rejects_an_expired_decision_without_breaking_archival_validation() {
    let decision = decision(decision_json());

    decision
        .validate()
        .expect("structural validation must remain usable for retained audit evidence");
    assert_eq!(
        decision.validate_at(NOW + 61),
        Err(ContractValidationErrorV1::DecisionOutsideValidityWindow),
        "a structurally valid but expired decision must not be reusable as current policy evidence"
    );
}

#[test]
fn live_validation_rejects_a_future_decision() {
    let mut value = decision_json();
    value["evaluated_at_unix"] = json!(NOW + 10);
    value["expires_at_unix"] = json!(NOW + 70);
    let decision = decision(value);

    decision
        .validate()
        .expect("a future-dated envelope is structurally coherent archival data");
    assert_eq!(
        decision.validate_at(NOW),
        Err(ContractValidationErrorV1::DecisionOutsideValidityWindow),
        "a decision must not be consumed before its recorded evaluation time"
    );
}

#[test]
fn live_validation_accepts_the_inclusive_current_window() {
    let decision = decision(decision_json());

    decision
        .validate_at(NOW)
        .expect("the exact evaluation instant is inside the decision validity window");
    decision.validate_at(NOW + 60).expect(
        "the declared expiry instant remains inclusive like the other v1 validity intervals",
    );
}
