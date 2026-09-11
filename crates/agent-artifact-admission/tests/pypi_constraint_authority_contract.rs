use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";

#[test]
fn pypi_install_cannot_import_unreviewed_constraint_authority() {
    for (executable, flag) in [
        ("pip", "--constraint=https://attacker.invalid/constraints.txt"),
        ("pip3", "-chttps://attacker.invalid/constraints.txt"),
        (
            "pip",
            "--build-constraint=https://attacker.invalid/build-constraints.txt",
        ),
        ("uv", "--constraint=https://attacker.invalid/constraints.txt"),
        ("uv", "--constraints=https://attacker.invalid/constraints.txt"),
        ("uv", "-chttps://attacker.invalid/constraints.txt"),
        (
            "uv",
            "--build-constraint=https://attacker.invalid/build-constraints.txt",
        ),
        (
            "uv",
            "--build-constraints=https://attacker.invalid/build-constraints.txt",
        ),
        ("uv", "-bhttps://attacker.invalid/build-constraints.txt"),
    ] {
        let (policy, mut intent) = approved_pypi_install(executable);
        intent.argv.push(flag.to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{executable} {flag} must not let an unreviewed constraints document influence the approved artifact/build identity"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "{executable} {flag} must report that the external constraint authority is outside the reviewed artifact set"
        );
    }
}

#[test]
fn direct_exact_pypi_install_without_constraint_authority_remains_allowed() {
    for executable in ["pip", "pip3", "uv"] {
        let (policy, intent) = approved_pypi_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow, "{executable}");
        assert!(decision.reason_codes.is_empty(), "{executable}");
    }
}

fn approved_pypi_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
    let artifact = ArtifactCoordinate {
        ecosystem: "pypi".to_string(),
        name: "cwl-example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: ARTIFACT_DIGEST.to_string(),
        artifact_argument: ARTIFACT_ARGUMENT.to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "pypi-reviewed-artifact-authority".to_string(),
        policy_revision: "2026-09-11.1".to_string(),
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
        "uv" => vec![
            "uv".to_string(),
            "pip".to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
        _ => vec![
            executable.to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
        ],
    };
    argv.push("--require-hashes".to_string());
    argv.push("--no-deps".to_string());
    if matches!(executable, "pip" | "pip3") {
        argv.push("--no-input".to_string());
    }

    let intent = InstallIntent {
        request_id: format!("req-pypi-constraint-authority-{executable}"),
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
