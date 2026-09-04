use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const IMAGE_NAME: &str = "ghcr.io/contextualwisdomlab/wardnet-runtime";

#[test]
fn podman_cannot_disable_registry_tls_verification() {
    for disabled in ["false", "FALSE", "f", "0"] {
        let (policy, mut intent) = approved_podman_pull();
        intent
            .argv
            .insert(2, format!("--tls-verify={disabled}"));

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "Podman false spelling {disabled} must not disable reviewed registry TLS verification"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "alternate_trust_root"),
            "caller-selected TLS verification disablement must not inherit registry trust from policy"
        );
    }
}

#[test]
fn podman_cannot_select_an_unreviewed_registry_certificate_directory() {
    let (policy, mut intent) = approved_podman_pull();
    intent
        .argv
        .insert(2, "--cert-dir=/tmp/unreviewed-certs".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_trust_root")
    );
}

#[test]
fn podman_cannot_select_an_unreviewed_registry_auth_file() {
    let (policy, mut intent) = approved_podman_pull();
    intent.argv.insert(
        2,
        "--authfile=/tmp/agent-controlled-registry-auth.json".to_string(),
    );

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_trust_root"),
        "caller-selected registry authentication files must not become admission authority"
    );
}

#[test]
fn podman_cannot_supply_registry_credentials_from_untrusted_argv() {
    let (policy, mut intent) = approved_podman_pull();
    intent
        .argv
        .insert(2, "--creds=agent-user:synthetic-secret".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_trust_root"),
        "untrusted argv must not choose the registry principal used to retrieve an approved artifact"
    );
}

#[test]
fn podman_cannot_select_an_unreviewed_image_decryption_key() {
    let (policy, mut intent) = approved_podman_pull();
    intent.argv.insert(
        2,
        "--decryption-key=/tmp/agent-controlled-key.pem:synthetic-passphrase".to_string(),
    );

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_trust_root"),
        "untrusted argv must not choose secret-bearing image decryption material"
    );
}

#[test]
fn explicit_tls_verification_true_does_not_weaken_the_reviewed_registry_trust() {
    let (policy, mut intent) = approved_podman_pull();
    intent.argv.insert(2, "--tls-verify=true".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

fn approved_podman_pull() -> (AdmissionPolicy, InstallIntent) {
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
        policy_id: "oci-transport-production".to_string(),
        policy_revision: "2026-09-04.1".to_string(),
        allowed_executables: vec!["podman".to_string()],
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
        request_id: "req-oci-transport-trust".to_string(),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec!["podman".to_string(), "pull".to_string(), artifact_argument],
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
