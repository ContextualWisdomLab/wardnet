use serde_json::{Value, json};
use wardnet_reputation_core::{DecisionEnvelopeV1, REPUTATION_SCHEMA_V1};

const NOW: u64 = 1_788_652_800;

fn business_authorized_allow_json() -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-business-authorization-red",
        "policy_id": "protect-default",
        "policy_revision": 1,
        "assessment": "unknown",
        "evidence_health": "fresh",
        "action": "allow",
        "reason": "business_authorization",
        "evaluated_at_unix": NOW,
        "expires_at_unix": NOW + 60,
        "evidence_refs": [],
        "context": {
            "schema_version": REPUTATION_SCHEMA_V1,
            "direction": "outbound",
            "tenant_id": "tenant-example",
            "workload_id": "workload-example",
            "purpose": "package_metadata",
            "operation_id": "op-business-authorization-red",
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

#[test]
fn business_authorization_allow_requires_an_exact_authorization_binding() {
    let decision: DecisionEnvelopeV1 = serde_json::from_value(business_authorized_allow_json())
        .expect("the existing v1 envelope should deserialize before the causal fix");

    assert!(
        decision.validate().is_err(),
        "a business_authorization enum value alone must not manufacture an auditable allow grant"
    );
}
