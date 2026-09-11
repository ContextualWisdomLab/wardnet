use serde_json::{Value, json};
use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn decision_with_evidence_refs(count: usize) -> DecisionEnvelopeV1 {
    let evidence_refs: Vec<String> = (0..count)
        .map(|index| format!("urn:wardnet:evidence:record-{index}"))
        .collect();
    let value: Value = json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-evidence-limit",
        "policy_id": "protect-default",
        "policy_revision": 1,
        "assessment": "suspicious",
        "evidence_health": "fresh",
        "action": "deny",
        "reason": "suspicious",
        "evaluated_at_unix": NOW,
        "expires_at_unix": NOW + 60,
        "evidence_refs": evidence_refs,
        "context": {
            "schema_version": REPUTATION_SCHEMA_V1,
            "direction": "outbound",
            "tenant_id": "tenant-example",
            "workload_id": "workload-example",
            "purpose": "package_metadata",
            "operation_id": "op-evidence-limit",
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
    });

    serde_json::from_value(value).expect("v1 decision envelope should deserialize")
}

#[test]
fn decision_envelope_accepts_declared_32_evidence_reference_limit() {
    decision_with_evidence_refs(32)
        .validate()
        .expect("the proposed v1 contract explicitly permits 32 returned evidence references");
}

#[test]
fn decision_envelope_rejects_more_than_declared_32_evidence_references() {
    assert_eq!(
        decision_with_evidence_refs(33).validate(),
        Err(ContractValidationErrorV1::BoundExceeded("evidence_refs")),
        "the pure core must not silently widen the proposed v1 decision contract beyond 32 returned evidence references"
    );
}
