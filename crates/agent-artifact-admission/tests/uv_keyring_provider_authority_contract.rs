use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn approved_uv_install_cannot_delegate_credentials_to_keyring_subprocess() {
    let (policy, control_intent) = approved_uv_install();
    let control = admission_decision(&policy, &control_intent);
    assert_eq!(
        control.decision,
        DecisionKind::Allow,
        "the exact reviewed uv pip install must remain admissible before adding credential-helper authority"
    );

    let mut hostile = control_intent;
    hostile
        .argv
        .push("--keyring-provider=subprocess".to_string());

    assert_alternate_trust_root_block(&policy, &hostile);
}

#[test]
fn separate_uv_subprocess_provider_carries_credential_authority_reason() {
    let (policy, mut hostile) = approved_uv_install();
    hostile
        .argv
        .extend(["--keyring-provider".to_string(), "subprocess".to_string()]);

    assert_alternate_trust_root_block(&policy, &hostile);
}

#[test]
fn unknown_non_disabled_uv_keyring_provider_fails_closed() {
    let (policy, mut hostile) = approved_uv_install();
    hostile.argv.push("--keyring-provider=import".to_string());

    assert_alternate_trust_root_block(&policy, &hostile);
}

#[test]
fn explicit_disabled_uv_keyring_provider_preserves_reviewed_baseline() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--keyring-provider=disabled".to_string());

    let decision = admission_decision(&policy, &intent);
    assert_eq!(
        decision.decision,
        DecisionKind::Allow,
        "explicitly retaining uv's disabled keyring baseline must not expand credential authority"
    );
}

fn assert_alternate_trust_root_block(policy: &AdmissionPolicy, intent: &InstallIntent) {
    let decision = admission_decision(policy, intent);
    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "any caller-selected non-disabled uv keyring provider must fail closed instead of inheriting new credential-helper authority after a client capability change"
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_trust_root"),
        "uv keyring-provider expansion must carry the stable alternate_trust_root reason"
    );
}

fn approved_uv_install() -> (AdmissionPolicy, InstallIntent) {
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
        policy_revision: "2026-09-11.9".to_string(),
        allowed_executables: vec!["uv".to_string()],
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
        request_id: "req-uv-keyring-provider-authority".to_string(),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            "uv".to_string(),
            "pip".to_string(),
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
