//! Fail-closed package-install admission primitives for AI coding agents.

mod admission;
mod artifact_variant;
mod audit;
mod config;
mod http;
mod oci_transport;
mod policy;

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
    if artifact_variant::requests_unapproved_oci_artifact_variant(intent) {
        if !decision.reason_codes.contains(&ReasonCode::ArtifactNotApproved) {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
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
