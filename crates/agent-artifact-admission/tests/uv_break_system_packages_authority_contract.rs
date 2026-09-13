use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

#[test]
fn approved_uv_install_without_system_package_override_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn uv_break_system_packages_cannot_inherit_artifact_approval() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--break-system-packages".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "caller-selected uv authority to modify an externally managed Python installation must not inherit ordinary artifact approval"
    );
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag),
        "uv break-system-packages authority must carry the stable missing_safety_flag reason: {:?}",
        decision.reason_codes
    );
}

#[test]
fn uv_global_options_preserve_break_system_packages_causal_evidence() {
    let (policy, mut intent) = approved_uv_install();
    intent
        .argv
        .splice(1..1, ["--color".to_string(), "never".to_string()]);
    intent.argv.push("--break-system-packages".to_string());

    let expected_command_sha256 = sha256_hex(intent.argv.join("\u{1f}").as_bytes());
    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision.reason_codes.contains(&ReasonCode::ForbiddenCommand),
        "the deliberately narrow supported-command grammar must remain fail-closed: {:?}",
        decision.reason_codes
    );
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag),
        "parser-valid uv global options must not erase break-system-packages causal evidence: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256, expected_command_sha256,
        "normalization or causal classification must not replace exact submitted argv audit identity"
    );
}

#[test]
fn uv_global_parser_controls_do_not_fabricate_system_package_authority() {
    let (policy, mut near_spelling) = approved_uv_install();
    near_spelling
        .argv
        .splice(1..1, ["--color".to_string(), "never".to_string()]);
    near_spelling
        .argv
        .push("--break-system-package".to_string());

    let near_spelling_decision = admission_decision(&policy, &near_spelling);
    assert!(
        !near_spelling_decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag),
        "uv uses exact long-option matching for this authority boundary: {:?}",
        near_spelling_decision.reason_codes
    );

    let (policy, mut non_install) = approved_uv_install();
    non_install.argv = vec![
        "uv".to_string(),
        "--color".to_string(),
        "never".to_string(),
        "pip".to_string(),
        "sync".to_string(),
        "requirements.txt".to_string(),
        "--break-system-packages".to_string(),
    ];

    let non_install_decision = admission_decision(&policy, &non_install);
    assert!(
        !non_install_decision
            .reason_codes
            .contains(&ReasonCode::MissingSafetyFlag),
        "non-install uv grammar must not fabricate install-scope system-package authority: {:?}",
        non_install_decision.reason_codes
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
        policy_id: "uv-break-system-packages-authority".to_string(),
        policy_revision: "2026-09-11.1".to_string(),
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
        request_id: "req-uv-break-system-packages-authority".to_string(),
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
