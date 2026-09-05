use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const MANIFEST_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ARTIFACT_ARGUMENT: &str = "cwl-example@1.2.3";

#[test]
fn cargo_overwrite_and_tracking_overrides_require_separate_review_authority() {
    // Cargo documents --force as permitting overwrite of existing crates/binaries
    // and --no-track as disabling install metadata and concurrent-install protection.
    // Neither side effect is represented by the approved artifact coordinate.
    for unreviewed_mutation in [
        vec!["--force"],
        vec!["--force=true"],
        vec!["-f"],
        vec!["-fq"],
        vec!["--no-track"],
        vec!["--no-track=true"],
    ] {
        let policy = approved_cargo_policy();
        let mut argv = vec![
            "cargo".to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
            "--locked".to_string(),
        ];
        argv.extend(unreviewed_mutation.iter().map(|value| (*value).to_string()));
        let intent = approved_cargo_intent(argv);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "caller-selected Cargo mutation authority {unreviewed_mutation:?} must fail closed"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "overwrite/tracking authority must use the stable artifact_not_approved reason: {unreviewed_mutation:?}"
        );
    }
}

#[test]
fn reviewed_cargo_install_without_mutation_override_remains_eligible() {
    let policy = approved_cargo_policy();
    let intent = approved_cargo_intent(vec![
        "cargo".to_string(),
        "install".to_string(),
        ARTIFACT_ARGUMENT.to_string(),
        "--locked".to_string(),
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

fn approved_cargo_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "cargo-overwrite-authority-test".to_string(),
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
        request_id: "req-cargo-overwrite-authority".to_string(),
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
