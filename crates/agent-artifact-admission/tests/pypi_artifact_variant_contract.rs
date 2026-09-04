use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PACKAGE_NAME: &str = "example-package";
const PACKAGE_VERSION: &str = "1.2.3";

#[test]
fn caller_selected_wheel_compatibility_tags_require_separately_approved_artifact_identity() {
    for selector in [
        "--platform=manylinux_2_28_x86_64",
        "--python-version=3.13",
        "--implementation=cp",
        "--abi=cp313",
    ] {
        let (policy, mut intent) = approved_pypi_install("pip");
        intent.argv.insert(2, selector.to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "caller-selected PyPI compatibility selector {selector} must not inherit approval from an artifact coordinate that does not bind that selector"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "PyPI selector {selector} must stay in the artifact-identity reason domain"
        );
    }
}

#[test]
fn caller_selected_source_distribution_and_build_backend_controls_are_not_preapproved() {
    for selector in [
        "--no-binary=:all:",
        "--no-build-isolation",
        "--config-settings=backend-mode=unsafe",
        "-Cbackend-mode=unsafe",
    ] {
        let (policy, mut intent) = approved_pypi_install("pip");
        intent.argv.insert(2, selector.to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "caller-selected PyPI build control {selector} must require separately reviewed artifact/build authority"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved")
        );
    }
}

#[test]
fn uv_pip_target_platform_and_build_backend_controls_are_not_preapproved() {
    for selector in [
        "--python-platform=x86_64-unknown-linux-gnu",
        "--no-binary=:all:",
        "--no-build-isolation",
        "--config-settings=backend-mode=unsafe",
        "-Cbackend-mode=unsafe",
    ] {
        let (policy, mut intent) = approved_uv_pypi_install();
        intent.argv.insert(3, selector.to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "uv pip selector {selector} must not inherit approval from a PyPI artifact coordinate that does not bind target-platform or build-backend authority"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "uv pip selector {selector} must stay in the artifact-identity reason domain"
        );
    }
}

#[test]
fn exact_pypi_install_without_caller_selected_variant_remains_allowed() {
    let (policy, intent) = approved_pypi_install("pip");

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn exact_uv_pypi_install_without_caller_selected_variant_remains_allowed() {
    let (policy, intent) = approved_uv_pypi_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

fn approved_pypi_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
    approved_pypi_install_with_argv(vec![
        executable.to_string(),
        "install".to_string(),
        format!("{PACKAGE_NAME}=={PACKAGE_VERSION}"),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
    ])
}

fn approved_uv_pypi_install() -> (AdmissionPolicy, InstallIntent) {
    approved_pypi_install_with_argv(vec![
        "uv".to_string(),
        "pip".to_string(),
        "install".to_string(),
        format!("{PACKAGE_NAME}=={PACKAGE_VERSION}"),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
    ])
}

fn approved_pypi_install_with_argv(argv: Vec<String>) -> (AdmissionPolicy, InstallIntent) {
    let artifact_argument = format!("{PACKAGE_NAME}=={PACKAGE_VERSION}");
    let artifact = ArtifactCoordinate {
        ecosystem: "pypi".to_string(),
        name: PACKAGE_NAME.to_string(),
        version: PACKAGE_VERSION.to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "Example Publisher".to_string(),
        sha256: DIGEST.to_string(),
        artifact_argument: artifact_argument.clone(),
    };
    let policy = AdmissionPolicy {
        policy_id: "pypi-production".to_string(),
        policy_revision: "2026-09-04.1".to_string(),
        allowed_executables: vec![argv[0].clone()],
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
        request_id: "req-pypi-artifact-variant".to_string(),
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
