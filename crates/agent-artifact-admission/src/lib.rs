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
mod pypi_build_directory_retention_authority;
mod pypi_cache_directory_authority;
mod pypi_certificate_store_authority;
mod pypi_client_certificate_authority;
mod pypi_constraint_authority;
mod pypi_dependency_group_authority;
mod pypi_global_option_authority;
mod pypi_hash_mode;
mod pypi_install_mutation_authority;
mod pypi_install_report_authority;
mod pypi_install_root_abbreviation_authority;
mod pypi_keyring_provider_authority;
mod pypi_log_output_authority;
mod pypi_noninteractive_authority;
mod pypi_proxy_authority;
mod pypi_python_interpreter_authority;
mod pypi_registry_authority;
mod pypi_requires_python_authority;
mod pypi_system_package_authority;
mod uv_bytecode_compilation_authority;
mod uv_configuration_authority;
mod uv_link_mode_authority;

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
pub fn admission_decision(policy: &AdmissionPolicy, intent: &InstallIntent) -> AdmissionDecision {
    let submitted_intent = intent;
    let global_normalized_intent =
        pypi_global_option_authority::normalize_reviewed_direct_pip_global_options(intent);
    let intent = global_normalized_intent.as_ref().unwrap_or(intent);
    let post_command_python_normalized_intent =
        pypi_python_interpreter_authority::normalize_reviewed_post_command_pip_python_interpreter_value(
            intent,
        );
    let intent = post_command_python_normalized_intent
        .as_ref()
        .unwrap_or(intent);
    let certificate_store_normalized_intent =
        pypi_certificate_store_authority::normalize_reviewed_pypi_certificate_store_values(intent);
    let intent = certificate_store_normalized_intent
        .as_ref()
        .unwrap_or(intent);
    let mut decision = policy::admission_decision(policy, intent);
    if artifact_source_identity::requests_unapproved_artifact_source(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if artifact_variant::requests_unapproved_artifact_variant(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if cargo_install_authority::requests_unapproved_cargo_install_mutation(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if dependency_cardinality::misses_exact_dependency_set_guard(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag)
        {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if dependency_cardinality::npm_family_dependency_closure_is_unverified(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_build_directory_retention_authority::requests_unapproved_pypi_build_directory_retention(
        intent,
    ) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateInstallRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_cache_directory_authority::requests_unapproved_pypi_cache_directory_authority(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateInstallRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_certificate_store_authority::requests_unapproved_pypi_certificate_store_abbreviation(
        intent,
    ) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_client_certificate_authority::requests_unapproved_pypi_client_certificate_authority(
        intent,
    ) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_constraint_authority::requests_unapproved_pypi_constraint_authority(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_dependency_group_authority::requests_unapproved_pip_dependency_group(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_hash_mode::requests_disabled_hash_requirement(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag)
        {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_install_mutation_authority::requests_unapproved_pypi_install_mutation(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_install_report_authority::requests_unapproved_pypi_report_authority(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateInstallRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_install_root_abbreviation_authority::requests_unapproved_pypi_target_abbreviation(
        intent,
    ) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateInstallRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_keyring_provider_authority::requests_unapproved_pypi_keyring_provider_authority(intent)
    {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_log_output_authority::requests_unapproved_pypi_log_output_authority(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateInstallRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_noninteractive_authority::misses_required_noninteractive_mode(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag)
        {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_proxy_authority::requests_unapproved_pypi_proxy_authority(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_python_interpreter_authority::requests_unapproved_pypi_python_interpreter_authority(
        intent,
    ) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
        {
            decision
                .reason_codes
                .insert(0, ReasonCode::AlternateInstallRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_registry_authority::disables_reviewed_registry(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_requires_python_authority::requests_pypi_requires_python_override(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag)
        {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if pypi_system_package_authority::requests_pypi_system_package_override(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag)
        {
            decision.reason_codes.push(ReasonCode::MissingSafetyFlag);
        }
        decision.decision = DecisionKind::Block;
    }
    if uv_link_mode_authority::requests_unapproved_uv_symlink_link_mode(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if uv_bytecode_compilation_authority::requests_unapproved_uv_bytecode_compilation(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved)
        {
            decision.reason_codes.push(ReasonCode::ArtifactNotApproved);
        }
        decision.decision = DecisionKind::Block;
    }
    if uv_configuration_authority::requests_unapproved_uv_configuration_authority(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    if oci_transport::requests_unapproved_oci_transport_trust(intent) {
        if !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot)
        {
            decision.reason_codes.push(ReasonCode::AlternateTrustRoot);
        }
        decision.decision = DecisionKind::Block;
    }
    decision.command_sha256 = sha256_hex(submitted_intent.argv.join("\u{1f}").as_bytes());
    decision
}
