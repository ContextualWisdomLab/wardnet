use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

#[test]
fn parser_valid_global_project_value_named_run_preserves_python_provider_evidence() {
    for option in ["--managed-python", "--no-managed-python"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "--project".to_string(),
            "run".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-python-downloads".to_string(),
            option.to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ForbiddenCommand),
            "global-option uv install remains deliberately outside the supported command grammar: {:?}",
            decision.reason_codes
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateInstallRoot),
            "the value token `run` consumed by --project is not the uv run command and must not erase causal {option} provider evidence: {:?}",
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
fn ordinary_global_project_value_keeps_existing_provider_evidence_control() {
    for option in ["--managed-python", "--no-managed-python"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "--project".to_string(),
            "workspace".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-python-downloads".to_string(),
            option.to_string(),
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
                .contains(&ReasonCode::AlternateInstallRoot),
            "a non-command global value already preserves {option} provider evidence: {:?}",
            decision.reason_codes
        );
    }
}

#[test]
fn actual_uv_run_after_global_project_value_does_not_gain_install_provider_semantics() {
    for option in ["--managed-python", "--no-managed-python"] {
        let (policy, mut intent) = approved_uv_install();
        intent.argv = vec![
            "uv".to_string(),
            "--project".to_string(),
            "workspace".to_string(),
            "run".to_string(),
            option.to_string(),
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
                .contains(&ReasonCode::AlternateInstallRoot),
            "actual uv run remains outside Agent Artifact Admission install-provider semantics: {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(intent.argv.join("\u{1f}").as_bytes())
        );
    }
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
        policy_id: "uv-global-python-provider-value-boundary".to_string(),
        policy_revision: "2026-09-19.1".to_string(),
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
        request_id: "req-uv-global-python-provider-value-boundary".to_string(),
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
