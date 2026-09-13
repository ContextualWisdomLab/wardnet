use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

#[test]
fn approved_uv_install_without_bytecode_compilation_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn uv_compile_bytecode_cannot_inherit_artifact_approval() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--compile-bytecode".to_string());

    assert_bytecode_compilation_is_blocked(&policy, &intent);
}

#[test]
fn uv_compile_alias_cannot_inherit_artifact_approval() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--compile".to_string());

    assert_bytecode_compilation_is_blocked(&policy, &intent);
}

#[test]
fn uv_run_bytecode_compilation_preserves_generated_artifact_evidence() {
    for compile_flag in ["--compile-bytecode", "--compile"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "run".to_string(),
            compile_flag.to_string(),
            "cwl-example==1.2.3".to_string(),
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
                .contains(&ReasonCode::ArtifactNotApproved),
            "uv-owned bytecode compilation must retain generated-artifact authority evidence: {:?}",
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
fn delegated_uv_run_child_compile_flags_are_not_reinterpreted_as_uv_authority() {
    for compile_flag in ["--compile-bytecode", "--compile"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "run".to_string(),
            "cwl-example==1.2.3".to_string(),
            compile_flag.to_string(),
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
            "delegated child argv must not be reinterpreted as uv bytecode authority: {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(intent.argv.join("\u{1f}").as_bytes())
        );
    }
}

#[test]
fn nearby_uv_run_compile_spelling_does_not_inherit_uv_semantics() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "run".to_string(),
        "--compile-bytecodex".to_string(),
        "cwl-example==1.2.3".to_string(),
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
        "Wardnet must not invent uv bytecode semantics for nearby option spellings: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
    );
}

#[test]
fn uv_global_options_preserve_pip_install_bytecode_authority_evidence() {
    for compile_flag in ["--compile-bytecode", "--compile"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "--color".to_string(),
            "never".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            compile_flag.to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ForbiddenCommand),
            "global-option uv grammar remains outside the supported install command: {:?}",
            decision.reason_codes
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ArtifactNotApproved),
            "uv pip install bytecode authority must survive reviewed global options: {:?}",
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
fn uv_global_option_controls_do_not_fabricate_pip_install_bytecode_authority() {
    for argv in [
        vec![
            "uv",
            "--color",
            "never",
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--require-hashes",
            "--no-deps",
            "--compile-bytecodex",
        ],
        vec![
            "uv",
            "--color",
            "never",
            "pip",
            "sync",
            "cwl-example==1.2.3",
            "--compile-bytecode",
        ],
    ] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = argv.into_iter().map(str::to_string).collect();

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
            "nearby spelling or non-install pip command must not inherit bytecode authority: {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(intent.argv.join("\u{1f}").as_bytes())
        );
    }
}

fn assert_bytecode_compilation_is_blocked(policy: &AdmissionPolicy, intent: &InstallIntent) {
    let decision = admission_decision(policy, intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "caller-selected eager bytecode materialization must not inherit reviewed artifact approval"
    );
    assert_eq!(
        decision.reason_codes,
        vec![ReasonCode::ArtifactNotApproved],
        "uv bytecode compilation must fail causally as unreviewed generated-artifact authority"
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
        policy_id: "uv-bytecode-compilation-authority".to_string(),
        policy_revision: "2026-09-13.1".to_string(),
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
        request_id: "req-uv-bytecode-compilation-authority".to_string(),
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
