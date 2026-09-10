use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

const BREAK_SYSTEM_PACKAGES_OPTIONS: &[&str] = &[
    "--br",
    "--bre",
    "--brea",
    "--break",
    "--break-",
    "--break-s",
    "--break-sy",
    "--break-sys",
    "--break-syst",
    "--break-syste",
    "--break-system",
    "--break-system-",
    "--break-system-p",
    "--break-system-pa",
    "--break-system-pac",
    "--break-system-pack",
    "--break-system-packa",
    "--break-system-packag",
    "--break-system-package",
    "--break-system-packages",
];

#[test]
fn approved_pip_install_cannot_disable_externally_managed_environment_protection() {
    for executable in ["pip", "pip3"] {
        let (policy, control_intent) = approved_pip_install(executable);
        let control = admission_decision(&policy, &control_intent);
        assert_eq!(
            control.decision,
            DecisionKind::Allow,
            "the exact approved {executable} install must remain admissible before adding the externally-managed override"
        );

        for override_option in BREAK_SYSTEM_PACKAGES_OPTIONS {
            let mut hostile = control_intent.clone();
            hostile.argv.push((*override_option).to_string());

            let decision = admission_decision(&policy, &hostile);
            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} {override_option} disables pip's externally-managed installation protection and must fail closed"
            );
            assert!(
                decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason.as_str() == "missing_safety_flag"),
                "{executable} {override_option} must include the stable missing_safety_flag reason"
            );
        }
    }
}

fn approved_pip_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
    let artifact = ArtifactCoordinate {
        ecosystem: "pypi".to_string(),
        name: "cwl-example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "cwl-example==1.2.3".to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-09-11.4".to_string(),
        allowed_executables: vec![executable.to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
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
        request_id: format!("req-{executable}-break-system-packages-authority"),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            executable.to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
        ],
        manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![artifact],
    };
    (policy, intent)
}
