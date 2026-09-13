use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn yarn_classic_workspace_root_escape_flags_fail_closed() {
    for workspace_root_flag in ["-W", "--ignore-workspace-root-check"] {
        let artifact_argument = "@cwl/example@1.2.3";
        let artifact = ArtifactCoordinate {
            ecosystem: "npm".to_string(),
            name: "@cwl/example".to_string(),
            version: "1.2.3".to_string(),
            registry_url: "https://registry.npmjs.org".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            artifact_argument: artifact_argument.to_string(),
        };
        let policy = AdmissionPolicy {
            policy_id: "enterprise-default".to_string(),
            policy_revision: "2026-09-03.1".to_string(),
            allowed_executables: vec!["yarn".to_string()],
            approved_manifests: vec![ApprovedManifest {
                workspace_id: "ContextualWisdomLab/wardnet".to_string(),
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
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
            request_id: format!("req-yarn-workspace-root-{workspace_root_flag}"),
            actor_id: "agent:codex:test".to_string(),
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            operation: "install".to_string(),
            argv: vec![
                "yarn".to_string(),
                "add".to_string(),
                artifact_argument.to_string(),
                "--ignore-scripts".to_string(),
                workspace_root_flag.to_string(),
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

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "Yarn Classic {workspace_root_flag} must not widen an approved install to the workspace root"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "alternate_install_root"),
            "Yarn Classic {workspace_root_flag} must produce alternate_install_root"
        );
    }
}
