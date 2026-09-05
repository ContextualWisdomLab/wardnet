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

fn cargo_artifact_policy() -> AdmissionPolicy {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.policy_id = "enterprise-default".to_string();
    policy.policy_revision = "2026-09-02.2".to_string();
    policy.allowed_executables = vec!["cargo".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "cargo".to_string(),
        name: "ripgrep".to_string(),
        version: "14.1.1".to_string(),
        registry_url: "https://crates.io".to_string(),
        owner: "Example".to_string(),
        sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        artifact_argument: "ripgrep@14.1.1".to_string(),
    }];
    policy
}

fn cargo_intent(ecosystem: &str, version: &str, registry_url: &str, digest: &str) -> InstallIntent {
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "cargo".to_string(),
        "install".to_string(),
        format!("ripgrep@{version}"),
        "--locked".to_string(),
    ];
    let artifact = intent
        .artifacts
        .first_mut()
        .expect("test helper supplies one artifact");
    artifact.ecosystem = ecosystem.to_string();
    artifact.name = "ripgrep".to_string();
    artifact.version = version.to_string();
    artifact.registry_url = registry_url.to_string();
    artifact.owner = "Example".to_string();
    artifact.sha256 = digest.to_string();
    artifact.artifact_argument = format!("ripgrep@{version}");
    intent
}

#[test]
fn approved_npm_identity_cannot_authorize_same_shaped_cargo_operand() {
    let policy = npm_artifact_policy_allowing_cargo();
    let intent = cargo_intent(
        "npm",
        "1.2.3",
        "https://registry.npmjs.org",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );

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

#[test]
fn cargo_identity_remains_allowed_through_cargo_install() {
    let policy = cargo_artifact_policy();
    let intent = cargo_intent(
        "cargo",
        "14.1.1",
        "https://crates.io",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}
