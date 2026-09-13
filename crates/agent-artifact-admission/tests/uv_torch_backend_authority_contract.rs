use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
};

#[test]
fn approved_uv_install_without_torch_backend_override_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn uv_torch_backend_attached_value_cannot_inherit_artifact_approval() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--torch-backend=cpu".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "caller-selected uv torch backend must not replace the reviewed package source authority"
    );
    assert_eq!(
        decision.reason_codes,
        vec![ReasonCode::AlternateTrustRoot],
        "attached torch-backend selection must fail causally at the alternate trust-root boundary"
    );
}

#[test]
fn uv_torch_backend_separate_value_reports_alternate_trust_root() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--torch-backend".to_string());
    intent.argv.push("cpu".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "separate-value torch-backend selection must be rejected for source authority rather than only as an accidental positional artifact mismatch: {:?}",
        decision.reason_codes
    );
}

#[test]
fn uv_global_option_preserves_attached_torch_backend_source_evidence() {
    let (policy, mut intent) = approved_uv_install();
    intent
        .argv
        .splice(1..1, ["--color".to_string(), "never".to_string()]);
    intent.argv.push("--torch-backend=cpu".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "a reviewed uv global option must not hide the pip-install torch-backend source authority: {:?}",
        decision.reason_codes
    );
}

#[test]
fn uv_global_option_preserves_separate_torch_backend_source_evidence() {
    let (policy, mut intent) = approved_uv_install();
    intent
        .argv
        .splice(1..1, ["--color".to_string(), "never".to_string()]);
    intent.argv.push("--torch-backend".to_string());
    intent.argv.push("cpu".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "separate-value torch-backend authority must remain visible after uv global options: {:?}",
        decision.reason_codes
    );
}

fn approved_uv_install() -> (AdmissionPolicy, InstallIntent) {
    let artifact = ArtifactCoordinate {
        ecosystem: "pypi".to_string(),
        name: "cwl-example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "cwl-example==1.2.3".to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "uv-torch-backend-authority".to_string(),
        policy_revision: "2026-09-11.1".to_string(),
        allowed_executables: vec!["uv".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        }],
        approved_artifacts: vec![ApprovedArtifact {
            ecosystem: artifact.ecosystem.clone(),
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            registry_url: artifact.registry_url.clone(),
            owner: artifact.owner.clone(),
            sha256: artifact.sha256.clone(),
            artifact_argument: artifact.artifact_argument.clone(),
        }],
    };
    let intent = InstallIntent {
        request_id: "req-uv-torch-backend-authority".to_string(),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            "uv".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
        ],
        manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![artifact],
    };
    (policy, intent)
}
