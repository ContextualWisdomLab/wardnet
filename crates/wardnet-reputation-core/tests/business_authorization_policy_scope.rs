use serde_json::{Value, json};
use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn bound_allow_json() -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-business-policy-scope",
        "context": {
            "schema_version": REPUTATION_SCHEMA_V1,
            "direction": "outbound",
            "tenant_id": "tenant-example",
            "workload_id": "workload-example",
            "purpose": "package_metadata",
            "operation_id": "op-business-policy-scope",
            "profile_id": "protect-default",
            "subject": {
                "kind": "exact_host",
                "value": "updates.example.invalid",
                "scope": "exact"
            },
            "canonicalization_profile": "egressweave-offline-fixture",
            "canonicalization_version": "1"
        },
        "policy_id": "protect-default",
        "policy_revision": 7,
        "evidence_generation": "snapshot-42",
        "assessment": "unknown",
        "evidence_health": "fresh",
        "action": "allow",
        "reason": "business_authorization",
        "evaluated_at_unix": NOW,
        "expires_at_unix": NOW + 60,
        "evidence_refs": [],
        "business_authorization": {
            "schema_version": REPUTATION_SCHEMA_V1,
            "authorization_id": "authz-policy-scope-0001",
            "authorization_revision": 3,
            "policy_id": "protect-default",
            "policy_revision": 7,
            "authority": "security-change-authority",
            "origin": "change-ticket",
            "tenant_id": "tenant-example",
            "workload_id": "workload-example",
            "purpose": "package_metadata",
            "profile_id": "protect-default",
            "subject": {
                "kind": "exact_host",
                "value": "updates.example.invalid",
                "scope": "exact"
            },
            "valid_from_unix": NOW - 60,
            "valid_until_unix": NOW + 120,
            "revoked": false,
            "approver_id": "approver-example",
            "ticket_ref": "SEC-1234",
            "provenance_refs": ["urn:wardnet:authorization:authz-policy-scope-0001:3"]
        }
    })
}

fn decision(value: Value) -> DecisionEnvelopeV1 {
    serde_json::from_value(value).expect("the v1 decision envelope should deserialize")
}

#[test]
fn exact_policy_scope_remains_valid() {
    decision(bound_allow_json())
        .validate()
        .expect("an exact-scope reviewed business authorization should remain valid");
}

#[test]
fn changed_policy_identity_must_not_inherit_an_old_business_authorization() {
    let mut value = bound_allow_json();
    value["policy_id"] = json!("protect-replacement");

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::BusinessAuthorizationPolicyMismatch),
        "a business authorization reviewed for one policy identity must not authorize a different policy"
    );
}

#[test]
fn changed_policy_revision_must_not_inherit_an_old_business_authorization() {
    let mut value = bound_allow_json();
    value["policy_revision"] = json!(8);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::BusinessAuthorizationPolicyMismatch),
        "a business authorization reviewed for one immutable policy revision must not survive policy revision drift"
    );
}
