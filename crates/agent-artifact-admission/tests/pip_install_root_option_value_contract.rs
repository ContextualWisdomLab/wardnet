use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
};

#[test]
fn approved_pip_install_without_root_override_remains_admissible() {
    let (policy, intent) = approved_pip_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn pip_separate_target_value_is_not_misclassified_as_an_artifact() {
    let (policy, mut intent) = approved_pip_install();
    intent
        .argv
        .extend(["--target".to_string(), "/tmp/wardnet-target".to_string()]);

    assert_target_override_is_causally_blocked(&policy, &intent);
}

#[test]
fn pip_short_target_value_is_not_misclassified_as_an_artifact() {
    let (policy, mut intent) = approved_pip_install();
    intent
        .argv
        .extend(["-t".to_string(), "/tmp/wardnet-target".to_string()]);

    assert_target_override_is_causally_blocked(&policy, &intent);
}

#[test]
fn pip_target_selector_does_not_hide_a_real_unapproved_artifact_operand() {
    let (policy, mut intent) = approved_pip_install();
    intent.argv.extend([
        "attacker-extra==9.9.9".to_string(),
        "--target".to_string(),
        "/tmp/wardnet-target".to_string(),
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert_eq!(
        decision.reason_codes,
        vec![
            ReasonCode::AlternateInstallRoot,
            ReasonCode::ArtifactNotApproved,
        ],
        "only the target option value is consumed; a second package operand remains an artifact-policy violation"
    );
}

fn assert_target_override_is_causally_blocked(policy: &AdmissionPolicy, intent: &InstallIntent) {
    let decision = admission_decision(policy, intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "caller-selected pip target must remain fail-closed before execution"
    );
    assert_eq!(
        decision.reason_codes,
        vec![ReasonCode::AlternateInstallRoot],
        "a value consumed by --target/-t is install-root authority, not a second artifact operand"
    );
}

fn approved_pip_install() -> (AdmissionPolicy, InstallIntent) {
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
        policy_id: "pip-install-root-option-value".to_string(),
        policy_revision: "2026-09-11.1".to_string(),
        allowed_executables: vec!["pip".to_string()],
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
        request_id: "req-pip-install-root-option-value".to_string(),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
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
