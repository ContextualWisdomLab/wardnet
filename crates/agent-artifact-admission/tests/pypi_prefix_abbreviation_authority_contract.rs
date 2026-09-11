use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
};

#[test]
fn approved_direct_pip_install_cannot_select_prefix_through_optparse_abbreviation() {
    for executable in ["pip", "pip3"] {
        let (policy, control_intent) = approved_pip_install(executable);
        let control = admission_decision(&policy, &control_intent);
        assert_eq!(
            control.decision,
            DecisionKind::Allow,
            "the exact approved {executable} install must remain admissible before adding prefix authority"
        );

        let mut hostile = control_intent.clone();
        hostile
            .argv
            .push("--prefi=/tmp/wardnet-pip-prefix".to_string());
        let decision = admission_decision(&policy, &hostile);
        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{executable} --prefi=... is pip's accepted unambiguous --prefix prefix and must not escape the reviewed install root"
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateInstallRoot),
            "{executable} --prefi=... must carry stable alternate_install_root evidence; got {:?}",
            decision.reason_codes
        );

        let mut ambiguous = control_intent.clone();
        ambiguous
            .argv
            .push("--pref=/tmp/wardnet-pip-prefix".to_string());
        let ambiguous_decision = admission_decision(&policy, &ambiguous);
        assert_eq!(
            ambiguous_decision.decision,
            DecisionKind::Allow,
            "Wardnet must not invent ambiguous pip optparse prefix --pref as --prefix"
        );
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
        policy_revision: "2026-09-12.prefix-abbreviation-red".to_string(),
        allowed_executables: vec![executable.to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: "ContextualWisdomLab/wardnet".to_string(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
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
        request_id: format!("req-{executable}-prefix-abbreviation-authority"),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            executable.to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-input".to_string(),
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
