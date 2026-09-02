use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent,
    admission_decision,
};

fn npm_artifact_policy_allowing_cargo() -> AdmissionPolicy {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.policy_id = "enterprise-default".to_string();
    policy.policy_revision = "2026-09-02.2".to_string();
    policy.allowed_executables = vec!["npm".to_string(), "cargo".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "npm".to_string(),
        name: "ripgrep".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "Example".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "ripgrep@1.2.3".to_string(),
    }];
    policy
}

#[test]
fn approved_npm_identity_cannot_authorize_same_shaped_cargo_operand() {
    let policy = npm_artifact_policy_allowing_cargo();
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "cargo".to_string(),
        "install".to_string(),
        "ripgrep@1.2.3".to_string(),
        "--locked".to_string(),
    ];
    let artifact = intent
        .artifacts
        .first_mut()
        .expect("test helper supplies one artifact");
    artifact.ecosystem = "npm".to_string();
    artifact.name = "ripgrep".to_string();
    artifact.version = "1.2.3".to_string();
    artifact.registry_url = "https://registry.npmjs.org".to_string();
    artifact.owner = "Example".to_string();
    artifact.artifact_argument = "ripgrep@1.2.3".to_string();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved"),
        "cross-ecosystem package-manager reuse must fail closed: {:?}",
        decision.reason_codes
    );
}
