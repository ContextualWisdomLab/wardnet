use serde_json::{Value, json};
use wardnet_reputation_core::{
    ContractValidationErrorV1, DecisionEnvelopeV1, REPUTATION_SCHEMA_V1,
};

const NOW: u64 = 1_788_652_800;

fn business_authorized_allow_json() -> Value {
    json!({
        "schema_version": REPUTATION_SCHEMA_V1,
        "evaluation_id": "eval-business-authorization",
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
            "operation_id": "op-business-authorization",
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

fn authorization_json() -> Value {
    json!({
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
    })
}

fn bound_business_authorized_allow_json() -> Value {
    let mut value = business_authorized_allow_json();
    value["business_authorization"] = authorization_json();
    value
}

fn decision(value: Value) -> DecisionEnvelopeV1 {
    serde_json::from_value(value).expect("the v1 decision envelope should deserialize")
}

#[test]
fn business_authorization_allow_requires_an_exact_authorization_binding() {
    assert_eq!(
        decision(business_authorized_allow_json()).validate(),
        Err(ContractValidationErrorV1::MissingBusinessAuthorization),
        "a business_authorization enum value alone must not manufacture an auditable allow grant"
    );
}

#[test]
fn exact_current_business_authorization_binding_is_accepted() {
    decision(bound_business_authorized_allow_json())
        .validate()
        .expect(
            "a current non-revoked authorization exactly bound to the evaluated context is valid",
        );
}

#[test]
fn revoked_business_authorization_fails_closed() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["revoked"] = json!(true);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::RevokedBusinessAuthorization)
    );
}

#[test]
fn expired_business_authorization_fails_closed() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["valid_until_unix"] = json!(NOW - 1);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::ExpiredBusinessAuthorization)
    );
}

#[test]
fn future_business_authorization_fails_closed() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["valid_from_unix"] = json!(NOW + 1);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::ExpiredBusinessAuthorization)
    );
}

#[test]
fn authorization_revision_must_identify_a_real_revision() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["authorization_revision"] = json!(0);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::InvalidBusinessAuthorizationRevision)
    );
}

#[test]
fn business_authorization_requires_provenance() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["provenance_refs"] = json!([]);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::MissingBusinessAuthorizationProvenance)
    );
}

#[test]
fn business_authorization_rejects_unknown_scope_bearing_fields() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["tenant_ids"] = json!(["tenant-example"]);

    assert!(
        serde_json::from_value::<DecisionEnvelopeV1>(value).is_err(),
        "unknown authorization scope must not be ignored by a v1 reader"
    );
}

#[test]
fn business_authorization_scope_is_bound_to_every_context_dimension() {
    for (field, hostile_value) in [
        ("tenant_id", json!("other-tenant")),
        ("workload_id", json!("other-workload")),
        ("purpose", json!("other-purpose")),
        ("profile_id", json!("other-profile")),
    ] {
        let mut value = bound_business_authorized_allow_json();
        value["business_authorization"][field] = hostile_value;

        assert_eq!(
            decision(value).validate(),
            Err(ContractValidationErrorV1::BusinessAuthorizationContextMismatch),
            "authorization {field} must match the authenticated evaluated context exactly"
        );
    }
}

#[test]
fn business_authorization_subject_is_exactly_bound() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["subject"]["value"] = json!("mirror.example.invalid");

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::BusinessAuthorizationContextMismatch)
    );
}

#[test]
fn business_authorization_must_not_widen_to_subdomains() {
    let mut value = bound_business_authorized_allow_json();
    value["context"]["subject"]["scope"] = json!("host_and_subdomains");
    value["business_authorization"]["subject"]["scope"] = json!("host_and_subdomains");

    assert!(
        decision(value).validate().is_err(),
        "the exact-scope business-exception contract must not become a host-and-subdomains authorization"
    );
}

#[test]
fn decision_cannot_outlive_its_business_authorization() {
    let mut value = bound_business_authorized_allow_json();
    value["business_authorization"]["valid_until_unix"] = json!(NOW + 30);

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::BusinessAuthorizationExpiryMismatch)
    );
}

#[test]
fn authorization_evidence_is_rejected_when_the_decision_does_not_use_it() {
    let mut value = bound_business_authorized_allow_json();
    value["action"] = json!("deny");
    value["reason"] = json!("unknown_destination");

    assert_eq!(
        decision(value).validate(),
        Err(ContractValidationErrorV1::StrayBusinessAuthorization)
    );
}
