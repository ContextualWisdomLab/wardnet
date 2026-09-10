use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn approved_pip_install_cannot_inherit_unreviewed_keyring_provider_authority() {
    for executable in ["pip", "pip3"] {
        let (policy, control_intent) = approved_pip_install(executable);
        let control = admission_decision(&policy, &control_intent);
        assert_eq!(
            control.decision,
            DecisionKind::Allow,
            "the exact approved {executable} install must remain admissible before adding credential-provider authority"
        );

        let hostile_argv_suffixes = [
            vec!["--keyring-provider=subprocess".to_string()],
            vec!["--keyring-provider=import".to_string()],
            vec!["--keyring-provider".to_string(), "subprocess".to_string()],
            vec!["--k=subprocess".to_string()],
            vec!["--k".to_string(), "import".to_string()],
        ];

        for suffix in hostile_argv_suffixes {
            let mut hostile = control_intent.clone();
            hostile.argv.extend(suffix.clone());

            let decision = admission_decision(&policy, &hostile);
            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} {suffix:?} delegates ambient credential-provider authority outside the reviewed artifact and must fail closed"
            );
            assert!(
                decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "alternate_trust_root"),
                "{executable} {suffix:?} must include the stable alternate_trust_root reason"
            );
        }

        for provider in ["auto", "disabled"] {
            let mut narrowed = control_intent.clone();
            narrowed.argv.push(format!("--keyring-provider={provider}"));

            let decision = admission_decision(&policy, &narrowed);
            assert_eq!(
                decision.decision,
                DecisionKind::Allow,
                "{executable} --keyring-provider={provider} does not expand credential-provider authority beyond the reviewed no-input baseline"
            );
            assert!(
                !decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "alternate_trust_root"),
                "non-expanding keyring mode must not be mislabeled as an alternate trust root"
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
        policy_revision: "2026-09-11.7".to_string(),
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
        request_id: format!("req-{executable}-keyring-provider-authority"),
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
