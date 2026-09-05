use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ARTIFACT_ARGUMENT: &str = "@cwl/example@1.2.3";

#[test]
fn npm_family_direct_installs_fail_closed_without_reviewed_dependency_closure() {
    for executable in ["npm", "pnpm", "yarn", "bun"] {
        let (policy, intent) = approved_npm_family_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{executable} direct install can resolve transitive artifacts absent from the reviewed direct artifact set"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "{executable} transitive artifacts have no reviewed artifact authority in the v0.1 direct-install contract"
        );
    }
}

fn approved_npm_family_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
    let artifact = ArtifactCoordinate {
        ecosystem: "npm".to_string(),
        name: "@cwl/example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: ARTIFACT_DIGEST.to_string(),
        artifact_argument: ARTIFACT_ARGUMENT.to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "npm-exact-artifact-set".to_string(),
        policy_revision: "2026-09-05.1".to_string(),
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
        "npm" => vec![
            "npm".to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
        "pnpm" => vec![
            "pnpm".to_string(),
            "add".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
        "yarn" => vec![
            "yarn".to_string(),
            "add".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
        "bun" => vec![
            "bun".to_string(),
            "add".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
        _ => unreachable!("test limits executable to npm-family managers"),
    };
    argv.push("--ignore-scripts".to_string());
    if executable == "pnpm" {
        argv.push("--ignore-pnpmfile".to_string());
    }

    let intent = InstallIntent {
        request_id: format!("req-npm-cardinality-{executable}"),
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
