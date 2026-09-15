use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const MANIFEST_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ARTIFACT_ARGUMENT: &str = "cwl-example@1.2.3";

#[test]
fn cargo_target_dir_cannot_escape_the_broker_selected_workspace() {
    for target_dir_arguments in [
        vec!["--target-dir=/tmp/unreviewed-build-output"],
        vec!["--target-dir", "/tmp/unreviewed-build-output"],
    ] {
        let policy = approved_cargo_policy();
        let mut argv = vec![
            "cargo".to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
            "--locked".to_string(),
        ];
        argv.extend(target_dir_arguments.into_iter().map(str::to_string));
        let intent = approved_cargo_intent(argv);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "cargo --target-dir must not redirect build artifacts outside the broker-selected workspace"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "alternate_install_root"),
            "cargo --target-dir must produce the stable alternate_install_root reason"
        );
    }
}

fn approved_cargo_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "cargo-target-dir-test".to_string(),
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
        request_id: "req-cargo-target-dir".to_string(),
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
