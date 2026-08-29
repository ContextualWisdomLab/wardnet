//! Fail-closed package-install admission primitives for AI coding agents.

mod audit;
mod config;
mod http;
mod model;
mod policy;

pub use audit::{
    AuditArtifact, AuditError, AuditRecord, AuditSink, FileAuditSink, MemoryAuditSink,
    build_audit_record, build_malformed_audit_record,
};
pub use config::{
    AdmissionServiceConfig, CliArgs, ConfigError, CredentialFile, load_admin_token, load_config,
    parse_cli_args, validate_service_config,
};
pub use http::{AdmissionState, ServiceError, build_app, run_cli, run_service};
pub use model::{
    AdmissionDecision, AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate,
    DecisionKind, InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode,
};
pub use policy::{
    admission_decision, is_sha256_hex, sha256_hex, validate_install_intent,
};
