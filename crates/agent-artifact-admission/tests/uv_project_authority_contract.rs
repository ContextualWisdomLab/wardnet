use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent, ReasonCode,
    admission_decision, sha256_hex,
};

#[test]
fn uv_run_project_root_is_configuration_authority() {
    let (policy, mut intent) = approved_uv_install();

    for argv in [
        vec![
            "uv",
            "run",
            "--project",
            "/tmp/attacker-project",
            "python",
        ],
        vec!["uv", "run", "--project=/tmp/attacker-project", "python"],
    ] {
        intent.argv = argv.into_iter().map(str::to_string).collect();

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ForbiddenCommand),
            "unsupported uv run must remain fail-closed: {:?}",
            decision.reason_codes
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "caller-selected uv project discovery must retain stable alternate_trust_root evidence: {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
            "audit identity must remain bound to the exact submitted argv"
        );
    }
}

#[test]
fn uv_run_child_project_argument_is_not_reinterpreted_as_uv_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "run".to_string(),
        "python".to_string(),
        "--project".to_string(),
        "/tmp/child-project".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ForbiddenCommand)
    );
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "delegated child argv must not be reinterpreted as uv configuration authority: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
    );
}

#[test]
fn uv_run_nearby_project_spelling_does_not_inherit_project_semantics() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "run".to_string(),
        "--projectx=/tmp/attacker-project".to_string(),
        "python".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ForbiddenCommand)
    );
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "Wardnet must not invent uv option semantics for nearby spellings: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
    );
}

#[test]
fn uv_pip_project_remains_indirect_source_not_configuration_authority() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.extend([
        "--project".to_string(),
        "/tmp/requirements-project".to_string(),
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved),
        "uv pip --project must keep the existing indirect-source control: {:?}",
        decision.reason_codes
    );
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "Astral documents --project as ineffective in the uv pip interface: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
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
        policy_id: "uv-project-authority".to_string(),
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
