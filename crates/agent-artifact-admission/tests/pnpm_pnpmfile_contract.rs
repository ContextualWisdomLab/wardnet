use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn pnpm_requires_pnpmfile_suppression_before_dependency_closure_can_be_considered() {
    let (policy, mut intent) = approved_pnpm_case();

    let decision = admission_decision(&policy, &intent);
    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "--ignore-scripts alone is insufficient because pnpm executes .pnpmfile hooks"
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "missing_safety_flag"),
        "missing pnpmfile suppression must use the stable missing_safety_flag reason"
    );

    intent.argv.push("--ignore-pnpmfile".to_string());
    let hardened = admission_decision(&policy, &intent);
    assert_eq!(hardened.decision, DecisionKind::Block);
    assert!(
        !hardened
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "missing_safety_flag"),
        "pnpmfile suppression must satisfy the execution-hook safety requirement"
    );
    assert!(
        hardened
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved"),
        "the remaining block must represent resolver-selected transitive artifacts that v0.1 policy does not authorize"
    );
}

fn approved_pnpm_case() -> (AdmissionPolicy, InstallIntent) {
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
        policy_revision: "2026-09-03.3".to_string(),
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
    let intent = InstallIntent {
        request_id: "req-pnpm-pnpmfile-suppression".to_string(),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            "pnpm".to_string(),
            "add".to_string(),
            artifact.artifact_argument.clone(),
            "--ignore-scripts".to_string(),
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
