use serde_json::{Value, json};
use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn authorized_allow_json() -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-canonicalization-binding",
        "policy_id": "protect-default",
        "policy_revision": 1,
        "policy_mode": "protect",
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
            "operation_id": "op-canonicalization-binding",
            "profile_id": "protect-default",
            "subject": {
                "kind": "exact_host",
                "value": "updates.example.invalid",
                "scope": "exact"
            },
            "canonicalization_profile": "egressweave-offline-fixture",
            "canonicalization_version": "1"
        },
        "evidence_generation": "snapshot-42",
        "business_authorization": {
            "schema_version": REPUTATION_SCHEMA_V1,
            "authorization_id": "authz-0001",
            "authorization_revision": 1,
            "policy_id": "protect-default",
            "policy_revision": 1,
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
            "canonicalization_profile": "egressweave-offline-fixture",
            "canonicalization_version": "1",
            "valid_from_unix": NOW - 60,
            "valid_until_unix": NOW + 120,
            "revoked": false,
            "approver_id": "approver-example",
            "ticket_ref": "SEC-1234",
            "provenance_refs": ["urn:wardnet:authorization:authz-0001:1"]
        }
    })
}

fn decision(value: Value) -> DecisionEnvelopeV1 {
    serde_json::from_value(value).expect("the v1 decision envelope should deserialize")
}

#[test]
fn authorization_does_not_survive_canonicalization_profile_drift() {
    let mut value = authorized_allow_json();
    value["context"]["canonicalization_profile"] = json!("different-owner-profile");

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::BusinessAuthorizationContextMismatch),
        "an authorization reviewed under one canonicalization profile must not authorize a context produced under another profile"
    );
}

#[test]
fn authorization_does_not_survive_canonicalization_version_drift() {
    let mut value = authorized_allow_json();
    value["context"]["canonicalization_version"] = json!("2");

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::BusinessAuthorizationContextMismatch),
        "an authorization must not survive a semantic canonicalization-version change merely because the opaque subject string stayed equal"
    );
}
