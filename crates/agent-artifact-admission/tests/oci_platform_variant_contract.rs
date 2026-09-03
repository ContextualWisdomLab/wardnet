use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const IMAGE_NAME: &str = "ghcr.io/contextualwisdomlab/wardnet-runtime";

#[test]
fn caller_selected_platform_is_not_authorized_by_an_index_digest() {
    let (policy, mut intent) = approved_oci_pull("docker");
    intent
        .argv
        .insert(2, "--platform=linux/arm64".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved"),
        "a caller-selected OCI platform must require separately approved artifact identity"
    );
}

#[test]
fn podman_platform_selection_is_bound_by_the_same_oci_policy() {
    let (policy, mut intent) = approved_oci_pull("podman");
    intent
        .argv
        .insert(2, "--platform=linux/amd64".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved")
    );
}

#[test]
fn podman_platform_selector_aliases_require_separately_approved_artifact_identity() {
    for selector in ["--arch=arm64", "--os=linux", "--variant=v7"] {
        let (policy, mut intent) = approved_oci_pull("podman");
        intent.argv.insert(2, selector.to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "caller-selected Podman selector {selector} must not inherit approval from an index-level artifact coordinate"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "Podman selector {selector} must remain in the artifact-identity reason domain"
        );
    }
}

#[test]
fn separated_platform_value_does_not_duplicate_artifact_reason() {
    let (policy, mut intent) = approved_oci_pull("docker");
    intent.argv.insert(2, "--platform".to_string());
    intent.argv.insert(3, "linux/arm64".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert_eq!(
        decision
            .reason_codes
            .iter()
            .filter(|reason| reason.as_str() == "artifact_not_approved")
            .count(),
        1,
        "platform hardening must preserve deterministic reason-code de-duplication"
    );
}

#[test]
fn non_pull_oci_command_remains_owned_by_the_existing_command_guard() {
    let (policy, mut intent) = approved_oci_pull("docker");
    intent.argv[1] = "push".to_string();
    intent
        .argv
        .insert(2, "--platform=linux/arm64".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "forbidden_command")
    );
}

#[test]
fn exact_digest_pull_without_caller_selected_platform_remains_allowed() {
    let (policy, intent) = approved_oci_pull("docker");

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn missing_executable_remains_fail_closed_without_panicking_variant_guard() {
    let (policy, mut intent) = approved_oci_pull("docker");
    intent.argv.clear();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "missing_executable")
    );
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
        policy_id: "oci-production".to_string(),
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
        request_id: "req-oci-platform-variant".to_string(),
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
