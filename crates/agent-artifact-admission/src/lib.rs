//! Fail-closed package-install admission primitives for AI coding agents.

mod admission;
mod artifact_source_identity;
mod artifact_variant;
mod audit;
mod cargo_install_authority;
mod config;
mod dependency_cardinality;
mod http;
mod oci_transport;
mod policy;
mod pypi_hash_mode;

pub use admission::{
    AdmissionDecision, AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate,
    DecisionKind, InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode,
};
pub use audit::{
    AuditArtifact, AuditError, AuditRecord, AuditSink, FileAuditSink, MemoryAuditSink,
    build_audit_record, build_malformed_audit_record, build_unavailable_request_audit_record,
};
pub use config::{
    AdmissionServiceConfig, CliArgs, ConfigError, CredentialFile, load_admin_token, load_config,
    parse_cli_args, validate_service_config,
};
pub use http::{AdmissionState, ServiceError, build_app, run_cli, run_service};
pub use policy::{is_sha256_hex, sha256_hex, validate_install_intent};

/// Compute a deterministic fail-closed admission decision for one install intent.
pub fn admission_decision(
    policy: &AdmissionPolicy,
    intent: &InstallIntent,
) -> AdmissionDecision {
    let mut decision = policy::admission_decision(policy, intent);
    if artifact_source_identity::requests_unapproved_artifact_source(intent) {
        if !decision.reason_codes.contains(&ReasonCode::ArtifactNotApproved) {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if artifact_variant::requests_unapproved_artifact_variant(intent) {
        if !decision.reason_codes.contains(&ReasonCode::ArtifactNotApproved) {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if cargo_install_authority::requests_unapproved_cargo_install_mutation(intent) {
        if !decision.reason_codes.contains(&ReasonCode::ArtifactNotApproved) {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if dependency_cardinality::misses_exact_dependency_set_guard(intent) {
        if !decision.reason_codes.contains(&ReasonCode::MissingSafetyFlag) {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if dependency_cardinality::npm_family_dependency_closure_is_unverified(intent) {
        if !decision.reason_codes.contains(&ReasonCode::ArtifactNotApproved) {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_hash_mode::requests_disabled_hash_requirement(intent) {
        if !decision.reason_codes.contains(&ReasonCode::MissingSafetyFlag) {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if oci_transport::requests_unapproved_oci_transport_trust(intent) {
        if !decision.reason_codes.contains(&ReasonCode::AlternateTrustRoot) {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    decision
}
