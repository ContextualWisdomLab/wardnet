use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const IMAGE_NAME: &str = "ghcr.io/contextualwisdomlab/wardnet-runtime";

#[test]
fn oci_all_tags_cannot_expand_an_exact_approved_digest_to_a_repository_set() {
    for executable in ["docker", "podman"] {
        for all_tags_flag in [
            "--all-tags",
            "-a",
            "--all-tags=true",
            "--all-tags=TRUE",
            "-a=true",
            "-a=1",
            "-aq",
            "-qa",
        ] {
            let (policy, mut intent) = approved_oci_pull(executable);
            intent.argv.insert(2, all_tags_flag.to_string());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} {all_tags_flag} must not expand one approved digest into every mutable tag in the repository"
            );
            assert!(
                decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "artifact_not_approved"),
                "repository-wide OCI expansion must stay in the artifact-identity reason domain"
            );
        }
    }
}

#[test]
fn explicit_false_all_tags_assignment_preserves_exact_digest_admission() {
    for executable in ["docker", "podman"] {
        for all_tags_flag in ["--all-tags=false", "-a=0"] {
            let (policy, mut intent) = approved_oci_pull(executable);
            intent.argv.insert(2, all_tags_flag.to_string());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Allow,
                "{executable} {all_tags_flag} leaves repository-wide expansion disabled and must not create a false security block"
            );
        }
    }
}

fn approved_oci_pull(executable: &str) -> (AdmissionPolicy, InstallIntent) {
    let artifact_argument = format!("{IMAGE_NAME}@sha256:{DIGEST}");
    let artifact = ArtifactCoordinate {
        ecosystem: "oci".to_string(),
        name: IMAGE_NAME.to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://ghcr.io".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: DIGEST.to_string(),
        artifact_argument: artifact_argument.clone(),
    };
    let policy = AdmissionPolicy {
        policy_id: "oci-all-tags-test".to_string(),
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
    let intent = InstallIntent {
        request_id: format!("req-oci-all-tags-{executable}"),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![executable.to_string(), "pull".to_string(), artifact_argument],
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
