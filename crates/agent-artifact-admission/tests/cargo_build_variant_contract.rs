use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const MANIFEST_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ARTIFACT_ARGUMENT: &str = "cwl-example@1.2.3";

#[test]
fn cargo_build_variant_selectors_cannot_change_an_approved_artifact_install() {
    // Cargo documents these selectors as changing the activated feature set or
    // selected build output. The current artifact coordinate does not bind that
    // build variant, so callers must not be able to add one after approval.
    for variant_arguments in [
        vec!["--features=dangerous"],
        vec!["-Fdangerous"],
        vec!["--all-features"],
        vec!["--no-default-features"],
        vec!["--bin=alternate"],
        vec!["--example=diagnostic"],
        vec!["--profile=dev"],
        vec!["--target=wasm32-wasip1"],
        vec!["--debug"],
    ] {
        let policy = approved_cargo_policy();
        let mut argv = vec![
            "cargo".to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
            "--locked".to_string(),
        ];
        argv.extend(variant_arguments.iter().map(|value| (*value).to_string()));
        let intent = approved_cargo_intent(argv);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "unreviewed Cargo build variant {variant_arguments:?} must not change an approved install"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "unbound Cargo build variants must produce the stable artifact_not_approved reason: {variant_arguments:?}"
        );
    }
}

fn approved_cargo_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "cargo-build-variant-test".to_string(),
        policy_revision: "1".to_string(),
        allowed_executables: vec!["cargo".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: MANIFEST_SHA256.to_string(),
        }],
        approved_artifacts: vec![ApprovedArtifact {
            ecosystem: "cargo".to_string(),
            name: "cwl-example".to_string(),
            version: "1.2.3".to_string(),
            registry_url: "https://crates.io".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: ARTIFACT_SHA256.to_string(),
            artifact_argument: ARTIFACT_ARGUMENT.to_string(),
        }],
    }
}

fn approved_cargo_intent(argv: Vec<String>) -> InstallIntent {
    InstallIntent {
        request_id: "req-cargo-build-variant".to_string(),
        actor_id: "agent:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv,
        manifest_sha256: MANIFEST_SHA256.to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![ArtifactCoordinate {
            ecosystem: "cargo".to_string(),
            name: "cwl-example".to_string(),
            version: "1.2.3".to_string(),
            registry_url: "https://crates.io".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: ARTIFACT_SHA256.to_string(),
            artifact_argument: ARTIFACT_ARGUMENT.to_string(),
        }],
    }
}
