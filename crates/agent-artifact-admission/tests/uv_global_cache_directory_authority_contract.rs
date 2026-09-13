use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

#[test]
fn uv_global_cache_directory_preserves_causal_authority_evidence() {
    let (policy, baseline) = approved_uv_install();
    let control = admission_decision(&policy, &baseline);
    assert_eq!(
        control.decision,
        DecisionKind::Allow,
        "the exact reviewed uv pip install must remain admissible"
    );

    for cache_selector in [
        vec!["--cache-dir".to_string(), "/tmp/wardnet-uv-cache".to_string()],
        vec!["--cache-dir=/tmp/wardnet-uv-cache".to_string()],
    ] {
        let mut hostile = baseline.clone();
        hostile.argv = vec!["uv".to_string()];
        hostile.argv.extend(cache_selector);
        hostile.argv.extend([
            "pip".to_string(),
            "install".to_string(),
            "cwl-example==1.2.3".to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-python-downloads".to_string(),
        ]);

        let decision = admission_decision(&policy, &hostile);
        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ForbiddenCommand),
            "reviewed uv global-option grammar must remain outside the deliberately narrow supported install command: {:?}",
            decision.reason_codes
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateInstallRoot),
            "caller-selected uv cache-directory authority must remain visible as causal evidence: {:?}",
            decision.reason_codes
        );
        assert_eq!(
            decision.command_sha256,
            sha256_hex(hostile.argv.join("\u{1f}").as_bytes()),
            "audit identity must remain bound to the exact submitted argv"
        );
    }
}

#[test]
fn uv_global_cache_directory_does_not_inherit_near_spelling() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "--cache-di=/tmp/wardnet-uv-cache".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "cwl-example==1.2.3".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
        "--no-python-downloads".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);
    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot),
        "uv must not invent cache-directory authority for an unrelated near spelling: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
    );
}

#[test]
fn uv_non_install_cache_directory_does_not_gain_install_authority_evidence() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv = vec![
        "uv".to_string(),
        "--cache-dir".to_string(),
        "/tmp/wardnet-uv-cache".to_string(),
        "pip".to_string(),
        "sync".to_string(),
        "requirements.txt".to_string(),
    ];

    let decision = admission_decision(&policy, &intent);
    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        !decision
            .reason_codes
            .contains(&ReasonCode::AlternateInstallRoot),
        "non-install uv grammar must not inherit pip-install cache-directory authority evidence: {:?}",
        decision.reason_codes
    );
    assert_eq!(
        decision.command_sha256,
        sha256_hex(intent.argv.join("\u{1f}").as_bytes())
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
        policy_revision: "2026-09-13.1".to_string(),
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
        request_id: "req-uv-global-cache-directory-authority".to_string(),
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
            "--no-python-downloads".to_string(),
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
