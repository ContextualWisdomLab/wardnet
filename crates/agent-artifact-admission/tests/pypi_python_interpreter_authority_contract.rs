use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";
const INTERPRETER: &str = "/tmp/attacker-python";

#[test]
fn reviewed_direct_pip_install_without_python_override_remains_admissible() {
    for executable in ["pip", "pip3"] {
        let (policy, intent) = approved_pip_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow);
        assert!(decision.reason_codes.is_empty());
    }
}

#[test]
fn global_direct_pip_python_interpreter_authority_is_causally_classified() {
    for executable in ["pip", "pip3"] {
        for option in ["--python", "--py"] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv = vec![
                executable.to_string(),
                option.to_string(),
                INTERPRETER.to_string(),
                "install".to_string(),
                ARTIFACT_ARGUMENT.to_string(),
                "--require-hashes".to_string(),
                "--no-deps".to_string(),
                "--no-input".to_string(),
            ];
            let submitted_argv = intent.argv.clone();

            let decision = admission_decision(&policy, &intent);

            assert_eq!(decision.decision, DecisionKind::Block);
            assert_eq!(
                decision.reason_codes,
                vec![ReasonCode::AlternateInstallRoot],
                "{executable} global separate {option} must identify caller-selected interpreter authority without manufacturing command or artifact findings"
            );
            assert_eq!(
                decision.command_sha256,
                sha256_hex(submitted_argv.join("\u{1f}").as_bytes()),
                "internal policy normalization must retain the exact submitted argv as audit identity"
            );
        }
    }
}

#[test]
fn attached_global_direct_pip_python_interpreter_authority_is_causally_classified() {
    for executable in ["pip", "pip3"] {
        for option in ["--python", "--py"] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv = vec![
                executable.to_string(),
                format!("{option}={INTERPRETER}"),
                "install".to_string(),
                ARTIFACT_ARGUMENT.to_string(),
                "--require-hashes".to_string(),
                "--no-deps".to_string(),
                "--no-input".to_string(),
            ];
            let submitted_argv = intent.argv.clone();

            let decision = admission_decision(&policy, &intent);

            assert_eq!(decision.decision, DecisionKind::Block);
            assert_eq!(
                decision.reason_codes,
                vec![ReasonCode::AlternateInstallRoot],
                "{executable} global attached {option} must identify caller-selected interpreter authority"
            );
            assert_eq!(
                decision.command_sha256,
                sha256_hex(submitted_argv.join("\u{1f}").as_bytes())
            );
        }
    }
}

#[test]
fn direct_pip_python_selector_does_not_hide_a_real_extra_artifact_operand() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv = vec![
            executable.to_string(),
            "--python".to_string(),
            INTERPRETER.to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
            "unapproved-extra==9.9.9".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-input".to_string(),
        ];

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert_eq!(
            decision.reason_codes,
            vec![
                ReasonCode::AlternateInstallRoot,
                ReasonCode::ArtifactNotApproved,
            ],
            "the interpreter value is option grammar, but a genuine second package operand remains an artifact-policy violation"
        );
    }
}

fn approved_pip_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
    let artifact = ArtifactCoordinate {
        ecosystem: "pypi".to_string(),
        name: "cwl-example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: ARTIFACT_DIGEST.to_string(),
        artifact_argument: ARTIFACT_ARGUMENT.to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "pypi-python-interpreter-authority".to_string(),
        policy_revision: "2026-09-12.1".to_string(),
        allowed_executables: vec![executable.to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: MANIFEST_DIGEST.to_string(),
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
        request_id: format!("req-pypi-python-interpreter-{executable}"),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            executable.to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-input".to_string(),
        ],
        manifest_sha256: MANIFEST_DIGEST.to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![artifact],
    };

    (policy, intent)
}
