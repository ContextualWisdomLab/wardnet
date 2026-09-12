use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

#[test]
fn approved_uv_install_without_python_provider_override_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
    );
}

#[test]
fn uv_managed_python_mode_cannot_inherit_artifact_approval() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--managed-python".to_string());

    assert_python_provider_selection_is_blocked(&policy, &intent);
}

#[test]
fn uv_system_python_search_mode_cannot_inherit_artifact_approval() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--no-managed-python".to_string());

    assert_python_provider_selection_is_blocked(&policy, &intent);
}

#[test]
fn uv_global_python_provider_modes_preserve_causal_install_root_evidence() {
    for option in ["--managed-python", "--no-managed-python"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            option.to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "global uv Python-provider authority must remain fail closed"
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateInstallRoot),
            "documented global {option} must preserve causal interpreter/install-root evidence; got {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
            "audit identity must remain bound to exact submitted argv"
        );
    }
}

#[test]
fn uv_global_python_provider_near_spellings_do_not_inherit_authority_semantics() {
    for option in ["--managed-pytho", "--no-managed-pytho"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            option.to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            !decision
                .reason_codes
                .contains(&ReasonCode::AlternateInstallRoot),
            "unreviewed near spelling {option} must not inherit uv Python-provider semantics"
        );
    }
}

#[test]
fn uv_run_child_arguments_do_not_inherit_python_provider_authority() {
    for option in ["--managed-python", "--no-managed-python"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "run".to_string(),
            "python".to_string(),
            option.to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "uv run remains outside Wardnet's supported artifact-install grammar"
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ForbiddenCommand),
            "unsupported uv run must remain fail closed"
        );
        assert!(
            !decision
                .reason_codes
                .contains(&ReasonCode::AlternateInstallRoot),
            "child-program argument {option} must not be misclassified as uv Python-provider authority; got {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
            "audit identity must remain bound to exact submitted argv"
        );
    }
}

fn assert_python_provider_selection_is_blocked(policy: &AdmissionPolicy, intent: &InstallIntent) {
    let decision = admission_decision(policy, intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "caller-selected uv Python-provider authority must not inherit reviewed artifact approval"
    );
    assert_eq!(
        decision.reason_codes,
        vec![ReasonCode::AlternateInstallRoot],
        "uv Python-provider selection must fail causally as caller-selected interpreter/install-root authority"
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes()),
        "audit identity must remain bound to exact submitted argv"
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
        policy_id: "uv-managed-python-authority".to_string(),
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
        request_id: "req-uv-managed-python-authority".to_string(),
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
