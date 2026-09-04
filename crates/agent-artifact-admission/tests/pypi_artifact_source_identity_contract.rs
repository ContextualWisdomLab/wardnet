use wardnet_agent_artifact_admission::{
    AdmissionPolicy, AdmissionServiceConfig, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate,
    DecisionKind, InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
    validate_service_config,
};

const MANIFEST_SHA256: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_SHA256: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PACKAGE_NAME: &str = "example-package";
const PACKAGE_VERSION: &str = "1.2.3";
const REGISTRY_URL: &str = "https://pypi.org/simple";

#[test]
fn pypi_requirement_cannot_replace_reviewed_index_coordinate() {
    for artifact_argument in [
        "example-package @ https://attacker.invalid/example.zip",
        "git+https://attacker.invalid/example.git@deadbeef",
        "./local-package",
    ] {
        let policy = approved_pypi_policy(artifact_argument);
        let intent = approved_pypi_intent(artifact_argument);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "pip requirement {artifact_argument:?} must not replace the reviewed index name/version coordinate"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "coordinate/requirement disagreement must report artifact_not_approved"
        );
    }
}

#[test]
fn exact_pypi_index_name_and_version_remain_allowed() {
    let artifact_argument = format!("{PACKAGE_NAME}=={PACKAGE_VERSION}");
    let policy = approved_pypi_policy(&artifact_argument);
    let intent = approved_pypi_intent(&artifact_argument);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn service_config_rejects_pypi_requirement_that_disagrees_with_coordinate() {
    let config = AdmissionServiceConfig {
        configuration_version: "1".to_string(),
        bind_address: "127.0.0.1:8787".to_string(),
        max_request_body_bytes: 64 * 1024,
        audit_log_path: "/var/lib/wardnet/agent-artifact-admission.ndjson".to_string(),
        policy: approved_pypi_policy("example-package @ https://attacker.invalid/example.zip"),
    };

    assert!(
        validate_service_config(&config).is_err(),
        "unsafe reviewed index coordinate must fail during configuration admission"
    );
}

fn approved_pypi_policy(artifact_argument: &str) -> AdmissionPolicy {
    AdmissionPolicy {
        policy_id: "pypi-artifact-source-identity-test".to_string(),
        policy_revision: "1".to_string(),
        allowed_executables: vec!["pip".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: MANIFEST_SHA256.to_string(),
        }],
        approved_artifacts: vec![ApprovedArtifact {
            ecosystem: "pypi".to_string(),
            name: PACKAGE_NAME.to_string(),
            version: PACKAGE_VERSION.to_string(),
            registry_url: REGISTRY_URL.to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: ARTIFACT_SHA256.to_string(),
            artifact_argument: artifact_argument.to_string(),
        }],
    }
}

fn approved_pypi_intent(artifact_argument: &str) -> InstallIntent {
    InstallIntent {
        request_id: "req-pypi-artifact-source-identity".to_string(),
        actor_id: "agent:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            "pip".to_string(),
            "install".to_string(),
            artifact_argument.to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
        ],
        manifest_sha256: MANIFEST_SHA256.to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![ArtifactCoordinate {
            ecosystem: "pypi".to_string(),
            name: PACKAGE_NAME.to_string(),
            version: PACKAGE_VERSION.to_string(),
            registry_url: REGISTRY_URL.to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: ARTIFACT_SHA256.to_string(),
            artifact_argument: artifact_argument.to_string(),
        }],
    }
}
