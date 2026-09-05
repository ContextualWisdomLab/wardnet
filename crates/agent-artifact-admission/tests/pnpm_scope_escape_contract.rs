use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn pnpm_workspace_selectors_cannot_expand_the_broker_selected_scope() {
    for scope_arguments in [
        vec!["--filter=@cwl/unreviewed"],
        vec!["-F=@cwl/unreviewed"],
        vec!["--filter-prod=@cwl/unreviewed"],
        vec!["--workspace-root"],
        vec!["-w"],
        vec!["--recursive"],
        vec!["-r"],
        vec!["--include-workspace-root"],
    ] {
        let (policy, intent, label) = pnpm_case(&scope_arguments);
        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{label} must not widen an approved install to caller-selected workspace projects"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "alternate_install_root"),
            "{label} must produce the stable alternate_install_root reason"
        );
    }
}

fn pnpm_case(scope_arguments: &[&str]) -> (AdmissionPolicy, InstallIntent, String) {
    let artifact = ArtifactCoordinate {
        ecosystem: "npm".to_string(),
        name: "@cwl/example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "@cwl/example@1.2.3".to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-09-03.1".to_string(),
        allowed_executables: vec!["pnpm".to_string()],
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
    let mut argv = vec![
        "pnpm".to_string(),
        "add".to_string(),
        artifact.artifact_argument.clone(),
        "--ignore-scripts".to_string(),
    ];
    argv.extend(scope_arguments.iter().map(|argument| (*argument).to_string()));
    let intent = InstallIntent {
        request_id: "req-pnpm-workspace-scope".to_string(),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv,
        manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![artifact],
    };
    let label = format!("pnpm add {}", scope_arguments.join(" "));
    (policy, intent, label)
}
