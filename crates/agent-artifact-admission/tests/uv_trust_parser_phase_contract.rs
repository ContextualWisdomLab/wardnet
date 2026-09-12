use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent, ReasonCode,
    admission_decision, sha256_hex,
};

#[test]
fn unsupported_uv_run_child_argv_does_not_inherit_install_trust_authority() {
    let (policy, mut intent) = approved_uv_install();

    for argv in [
        vec!["uv", "run", "python", "--system-certs"],
        vec![
            "uv",
            "run",
            "python",
            "--index-url",
            "https://attacker.invalid/simple",
        ],
        vec!["uv", "run", "python", "--trusted-host=attacker.invalid"],
    ] {
        intent.argv = argv.into_iter().map(str::to_string).collect();

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ForbiddenCommand),
            "unsupported uv run must remain fail-closed at the command boundary: {:?}",
            decision.reason_codes
        );
        assert!(
            !decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "arguments delegated to the uv run child command must not be reinterpreted as Agent Artifact Admission trust-root evidence: {:?}",
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
fn uv_global_trust_authority_before_run_remains_visible() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "--system-certs".to_string(),
        "run".to_string(),
        "python".to_string(),
    ];

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
        "uv-owned global trust authority before the run command boundary must remain visible: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
    );
}

#[test]
fn uv_global_option_values_named_like_commands_do_not_shift_trust_phase() {
    let (policy, mut intent) = approved_uv_install();

    intent.argv = vec![
        "uv".to_string(),
        "--cache-dir".to_string(),
        "pip".to_string(),
        "run".to_string(),
        "python".to_string(),
        "--index-url".to_string(),
        "https://attacker.invalid/simple".to_string(),
    ];
    let child_decision = admission_decision(&policy, &intent);
    assert_eq!(child_decision.decision, DecisionKind::Block);
    assert!(
        child_decision
            .reason_codes
            .contains(&ReasonCode::ForbiddenCommand)
    );
    assert!(
        !child_decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "a global option value named `pip` must not make uv run child argv look like uv-owned trust authority: {:?}",
        child_decision.reason_codes
    );

    intent.argv = vec![
        "uv".to_string(),
        "--cache-dir".to_string(),
        "run".to_string(),
        "--trusted-host".to_string(),
        "attacker.invalid".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "example-package==1.2.3".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
    ];
    let install_decision = admission_decision(&policy, &intent);
    assert_eq!(install_decision.decision, DecisionKind::Block);
    assert!(
        install_decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "a global option value named `run` must not hide a later uv-owned trust override before the real pip command: {:?}",
        install_decision.reason_codes
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
        policy_id: "uv-trust-parser-phase".to_string(),
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
