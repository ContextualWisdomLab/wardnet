use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";

#[test]
fn pypi_install_without_no_deps_cannot_expand_beyond_the_reviewed_artifact_set() {
    for executable in ["pip", "pip3", "uv"] {
        let (policy, intent) = approved_pypi_install(executable, false);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{executable} must not resolve undeclared transitive artifacts from an approval that binds only the declared artifact set"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "missing_safety_flag"),
            "{executable} must report the missing dependency-cardinality safety flag"
        );
    }
}

#[test]
fn pypi_install_with_no_deps_preserves_the_reviewed_artifact_cardinality() {
    for executable in ["pip", "pip3", "uv"] {
        let (policy, intent) = approved_pypi_install(executable, true);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow, "{executable}");
        assert!(decision.reason_codes.is_empty(), "{executable}");
    }
}

fn approved_pypi_install(
    executable: &str,
    include_no_deps: bool,
) -> (AdmissionPolicy, InstallIntent) {
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
        policy_id: "pypi-exact-artifact-set".to_string(),
        policy_revision: "2026-09-04.1".to_string(),
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

    let mut argv = match executable {
        "uv" => vec![
            "uv".to_string(),
            "pip".to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
        _ => vec![
            executable.to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
    };
    argv.push("--require-hashes".to_string());
    if include_no_deps {
        argv.push("--no-deps".to_string());
    }

    let intent = InstallIntent {
        request_id: format!("req-pypi-cardinality-{executable}"),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv,
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
