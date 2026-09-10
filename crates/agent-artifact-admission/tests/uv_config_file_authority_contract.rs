use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent, ReasonCode,
    admission_decision,
};

#[test]
fn reviewed_uv_install_without_config_override_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn uv_attached_config_file_cannot_replace_reviewed_package_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent
        .argv
        .push("--config-file=/tmp/attacker-uv.toml".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "caller-selected uv config can replace index and trust settings: {:?}",
        decision.reason_codes
    );
}

#[test]
fn uv_separate_config_file_value_is_classified_as_trust_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--config-file".to_string());
    intent.argv.push("/tmp/attacker-uv.toml".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "an incidental positional-operand rejection must not hide the config authority: {:?}",
        decision.reason_codes
    );
}

fn approved_uv_install() -> (AdmissionPolicy, InstallIntent) {
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "uv".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "example-package==1.2.3".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
    ];
    let artifact = intent
        .artifacts
        .first_mut()
        .expect("test helper supplies one artifact");
    artifact.ecosystem = "pypi".to_string();
    artifact.name = "example-package".to_string();
    artifact.version = "1.2.3".to_string();
    artifact.registry_url = "https://pypi.org/simple".to_string();
    artifact.owner = "Example".to_string();
    artifact.artifact_argument = "example-package==1.2.3".to_string();

    let approved_artifact = ApprovedArtifact {
        ecosystem: artifact.ecosystem.clone(),
        name: artifact.name.clone(),
        version: artifact.version.clone(),
        registry_url: artifact.registry_url.clone(),
        owner: artifact.owner.clone(),
        sha256: artifact.sha256.clone(),
        artifact_argument: artifact.artifact_argument.clone(),
    };
    let policy = AdmissionPolicy {
        policy_id: "uv-config-authority".to_string(),
        policy_revision: "2026-09-10.1".to_string(),
        allowed_executables: vec!["uv".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: intent.workspace_id.clone(),
            sha256: intent.manifest_sha256.clone(),
        }],
        approved_artifacts: vec![approved_artifact],
    };
    (policy, intent)
}
