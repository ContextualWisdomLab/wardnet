use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

#[test]
fn approved_uv_install_without_global_parser_options_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn uv_global_options_preserve_undeclared_artifact_causal_evidence() {
    let (policy, mut hostile) = approved_uv_install();
    hostile.argv = vec![
        "uv".to_string(),
        "--color".to_string(),
        "never".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "cwl-example==1.2.3".to_string(),
        "undeclared-example==9.9.9".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
        "--no-python-downloads".to_string(),
    ];

    let decision = admission_decision(&policy, &hostile);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ForbiddenCommand),
        "reviewed uv global-option grammar remains outside the deliberately narrow supported install command: {:?}",
        decision.reason_codes
    );
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved),
        "parser-valid uv global options must not erase causal evidence for an undeclared artifact: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(hostile.argv.join("\u{1f}").as_bytes()),
        "audit identity must remain bound to the exact submitted argv"
    );
}

#[test]
fn uv_global_install_root_value_is_not_fabricated_as_an_artifact_operand() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "--color".to_string(),
        "never".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "cwl-example==1.2.3".to_string(),
        "--target".to_string(),
        "/tmp/wardnet-admission".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
        "--no-python-downloads".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::ForbiddenCommand)
    );
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot)
    );
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::ArtifactNotApproved),
        "the consumed --target value is install-root authority, not a package operand: {:?}",
        decision.reason_codes
    );
}

#[test]
fn non_install_uv_grammar_does_not_inherit_artifact_operand_semantics() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "--color".to_string(),
        "never".to_string(),
        "pip".to_string(),
        "sync".to_string(),
        "cwl-example==1.2.3".to_string(),
        "undeclared-example==9.9.9".to_string(),
        "--no-python-downloads".to_string(),
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
            .contains(&ReasonCode::ArtifactNotApproved),
        "non-install uv grammar must not inherit pip-install artifact-operand evidence: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
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
        policy_id: "uv-global-artifact-operand-authority".to_string(),
        policy_revision: "2026-09-14.1".to_string(),
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
        request_id: "req-uv-global-artifact-operand-authority".to_string(),
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
            "--no-python-downloads".to_string(),
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
