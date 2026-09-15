use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision, sha256_hex,
};

#[test]
fn approved_pip_install_cannot_gain_caller_selected_log_write_authority() {
    for executable in ["pip", "pip3"] {
        let (policy, control_intent) = approved_pip_install(executable);
        let control = admission_decision(&policy, &control_intent);
        assert_eq!(
            control.decision,
            DecisionKind::Allow,
            "the exact approved {executable} install must remain admissible before adding log output authority"
        );

        for log_arguments in [
            vec!["--log=/tmp/wardnet-pip.log"],
            vec!["--log", "/tmp/wardnet-pip.log"],
            vec!["--log-file=/tmp/wardnet-pip.log"],
            vec!["--log-file", "/tmp/wardnet-pip.log"],
            vec!["--local-log=/tmp/wardnet-pip.log"],
            vec!["--local-log", "/tmp/wardnet-pip.log"],
            vec!["--log-f=/tmp/wardnet-pip.log"],
            vec!["--log-f", "/tmp/wardnet-pip.log"],
            vec!["--loc=/tmp/wardnet-pip.log"],
            vec!["--loc", "/tmp/wardnet-pip.log"],
        ] {
            let mut intent = control_intent.clone();
            intent
                .argv
                .extend(log_arguments.iter().map(|argument| (*argument).to_string()));

            let decision = admission_decision(&policy, &intent);
            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} {} grants caller-selected log write authority and must fail closed",
                log_arguments.join(" ")
            );
            assert!(
                decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "alternate_install_root"),
                "{executable} {} must include the stable alternate_install_root reason",
                log_arguments.join(" ")
            );
        }
    }
}

#[test]
fn valid_global_pip_log_options_remain_causal_write_authority_evidence() {
    for executable in ["pip", "pip3"] {
        let (policy, control_intent) = approved_pip_install(executable);

        for global_log_arguments in [
            vec!["--log=/tmp/wardnet-pip.log"],
            vec!["--log", "/tmp/wardnet-pip.log"],
            vec!["--log-file=/tmp/wardnet-pip.log"],
            vec!["--log-file", "/tmp/wardnet-pip.log"],
            vec!["--local-log=/tmp/wardnet-pip.log"],
            vec!["--local-log", "/tmp/wardnet-pip.log"],
            vec!["--log-f", "/tmp/wardnet-pip.log"],
            vec!["--loc=/tmp/wardnet-pip.log"],
        ] {
            let mut intent = control_intent.clone();
            let mut argv = Vec::with_capacity(intent.argv.len() + global_log_arguments.len());
            argv.push(executable.to_string());
            argv.extend(
                global_log_arguments
                    .iter()
                    .map(|argument| (*argument).to_string()),
            );
            argv.extend(control_intent.argv.iter().skip(1).cloned());
            intent.argv = argv;
            let submitted_argv = intent.argv.clone();

            let decision = admission_decision(&policy, &intent);
            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "parser-valid global {executable} {} must fail closed",
                global_log_arguments.join(" ")
            );
            assert!(
                decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "alternate_install_root"),
                "parser-valid global {executable} {} must retain causal log-write evidence: {:?}",
                global_log_arguments.join(" "),
                decision.reason_codes
            );
            assert!(
                !decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "artifact_not_approved"),
                "the log path consumed by pip General Options must not masquerade as an artifact operand: {:?}",
                decision.reason_codes
            );
            assert_eq!(
                decision.command_sha256,
                sha256_hex(submitted_argv.join("\u{1f}").as_bytes()),
                "policy normalization must preserve the exact submitted argv audit identity"
            );
        }
    }
}

fn approved_pip_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
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
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-09-11.2".to_string(),
        allowed_executables: vec![executable.to_string()],
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
        request_id: format!("req-{executable}-log-authority"),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            executable.to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-input".to_string(),
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
