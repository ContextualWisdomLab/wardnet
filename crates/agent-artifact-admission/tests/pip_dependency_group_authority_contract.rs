use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";

#[test]
fn pip_install_cannot_import_unreviewed_dependency_group() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv.push("--group=developer-tools".to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{executable} --group must not add pyproject dependency-group members outside the reviewed artifact set"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "{executable} --group must report that dependency-group members are outside reviewed artifact authority"
        );
    }
}

#[test]
fn exact_pip_install_without_dependency_group_remains_allowed() {
    for executable in ["pip", "pip3"] {
        let (policy, intent) = approved_pip_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow, "{executable}");
        assert!(decision.reason_codes.is_empty(), "{executable}");
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
        policy_id: "pypi-reviewed-artifact-authority".to_string(),
        policy_revision: "2026-09-11.2".to_string(),
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
        request_id: format!("req-pip-dependency-group-authority-{executable}"),
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
