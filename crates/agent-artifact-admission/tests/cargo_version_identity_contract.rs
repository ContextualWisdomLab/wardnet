use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const MANIFEST_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn cargo_version_selector_cannot_override_reviewed_artifact_version() {
    for version_selector in ["--version=9.9.9", "--vers=9.9.9"] {
        let artifact_argument = "cwl-example@1.2.3";
        let policy = approved_cargo_policy("1.2.3", artifact_argument);
        let intent = approved_cargo_intent(
            "1.2.3",
            artifact_argument,
            vec![
                "cargo".to_string(),
                "install".to_string(),
                artifact_argument.to_string(),
                version_selector.to_string(),
                "--locked".to_string(),
            ],
        );

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "caller-selected Cargo version selector {version_selector} must not override reviewed artifact identity"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "unreviewed Cargo version selection must report artifact_not_approved"
        );
    }
}

#[test]
fn cargo_positional_package_version_must_match_reviewed_coordinate() {
    let artifact_argument = "cwl-example@9.9.9";
    let policy = approved_cargo_policy("1.2.3", artifact_argument);
    let intent = approved_cargo_intent(
        "1.2.3",
        artifact_argument,
        vec![
            "cargo".to_string(),
            "install".to_string(),
            artifact_argument.to_string(),
            "--locked".to_string(),
        ],
    );

    let decision = admission_decision(&policy, &intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "Cargo crate@version syntax must remain semantically bound to the reviewed name/version coordinate"
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved"),
        "coordinate/argv disagreement must fail with artifact_not_approved"
    );
}

fn approved_cargo_policy(version: &str, artifact_argument: &str) -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "cargo-version-identity-test".to_string(),
        policy_revision: "1".to_string(),
        allowed_executables: vec!["cargo".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: MANIFEST_SHA256.to_string(),
        }],
        approved_artifacts: vec![ApprovedArtifact {
            ecosystem: "cargo".to_string(),
            name: "cwl-example".to_string(),
            version: version.to_string(),
            registry_url: "https://crates.io".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: ARTIFACT_SHA256.to_string(),
            artifact_argument: artifact_argument.to_string(),
        }],
    }
}

fn approved_cargo_intent(
    version: &str,
    artifact_argument: &str,
    argv: Vec<String>,
) -> InstallIntent {
    InstallIntent {
        request_id: "req-cargo-version-identity".to_string(),
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
            version: version.to_string(),
            registry_url: "https://crates.io".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: ARTIFACT_SHA256.to_string(),
            artifact_argument: artifact_argument.to_string(),
        }],
    }
}
