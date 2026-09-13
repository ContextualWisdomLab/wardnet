use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent, ReasonCode,
    admission_decision,
};

#[test]
fn reviewed_uv_install_with_default_index_strategy_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn explicit_safe_first_index_strategy_remains_admissible() {
    for selector in [
        vec!["--index-strategy=first-index".to_string()],
        vec!["--index-strategy".to_string(), "first-index".to_string()],
    ] {
        let (policy, mut intent) = approved_uv_install();
        for (offset, token) in selector.into_iter().enumerate() {
            intent.argv.insert(3 + offset, token);
        }

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow);
        assert!(decision.reason_codes.is_empty());
    }
}

#[test]
fn unsafe_best_match_equals_form_is_explicit_trust_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent
        .argv
        .insert(3, "--index-strategy=unsafe-best-match".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "unsafe-best-match must have explicit trust evidence: {:?}",
        decision.reason_codes
    );
}

#[test]
fn unsafe_best_match_separate_value_is_explicit_trust_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.insert(3, "--index-strategy".to_string());
    intent.argv.insert(4, "unsafe-best-match".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "separate unsafe-best-match must have explicit trust evidence: {:?}",
        decision.reason_codes
    );
}

#[test]
fn unsafe_first_match_is_explicit_trust_authority() {
    for selector in [
        vec!["--index-strategy=unsafe-first-match".to_string()],
        vec![
            "--index-strategy".to_string(),
            "unsafe-first-match".to_string(),
        ],
    ] {
        let (policy, mut intent) = approved_uv_install();
        for (offset, token) in selector.into_iter().enumerate() {
            intent.argv.insert(3 + offset, token);
        }

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "unsafe-first-match must have explicit trust evidence: {:?}",
            decision.reason_codes
        );
    }
}

#[test]
fn near_spelling_does_not_fabricate_trust_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent
        .argv
        .insert(3, "--index-strateg=unsafe-best-match".to_string());

    let decision = admission_decision(&policy, &intent);

    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "near spelling must not be interpreted as uv index-strategy authority: {:?}",
        decision.reason_codes
    );
}

#[test]
fn delegated_child_argv_does_not_fabricate_uv_trust_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "run".to_string(),
        "--no-python-downloads".to_string(),
        "python".to_string(),
        "--index-strategy=unsafe-best-match".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "delegated child argv must remain outside uv trust authority: {:?}",
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
        "--no-python-downloads".to_string(),
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
        policy_id: "uv-index-strategy-authority".to_string(),
        policy_revision: "2026-09-13.1".to_string(),
        allowed_executables: vec!["uv".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: intent.workspace_id.clone(),
            sha256: intent.manifest_sha256.clone(),
        }],
        approved_artifacts: vec![approved_artifact],
    };
    (policy, intent)
}
