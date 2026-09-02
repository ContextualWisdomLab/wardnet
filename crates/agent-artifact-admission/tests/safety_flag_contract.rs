use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent,
    admission_decision,
};

fn approved_npm_policy() -> AdmissionPolicy {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.policy_id = "enterprise-default".to_string();
    policy.policy_revision = "2026-09-02.1".to_string();
    policy.allowed_executables = vec!["npm".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "npm".to_string(),
        name: "@unowned/example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "Unowned".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "@unowned/example@1.2.3".to_string(),
    }];
    policy
}

#[test]
fn npm_boolean_overrides_cannot_reenable_install_scripts() {
    let policy = approved_npm_policy();

    for conflicting_flag in ["--ignore-scripts=false", "--no-ignore-scripts"] {
        let mut intent = InstallIntent::unowned_llms_package_for_test();
        intent.argv = vec![
            "npm".to_string(),
            "install".to_string(),
            "@unowned/example@1.2.3".to_string(),
            "--ignore-scripts".to_string(),
            conflicting_flag.to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block, "{conflicting_flag}");
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "missing_safety_flag"),
            "{conflicting_flag}"
        );
    }
}
