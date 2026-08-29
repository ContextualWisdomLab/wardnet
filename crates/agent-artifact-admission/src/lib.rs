//! Fail-closed package-install admission primitives for AI coding agents.

mod audit;
mod model;
mod policy;

pub use audit::{
    AuditArtifact, AuditError, AuditRecord, AuditSink, FileAuditSink, MemoryAuditSink,
    build_audit_record,
};
pub use model::{
    AdmissionDecision, AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate,
    DecisionKind, InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode,
};
pub use policy::{admission_decision, is_sha256_hex, sha256_hex};
