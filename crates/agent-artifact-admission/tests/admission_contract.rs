use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSourceKind, admission_decision, is_sha256_hex, sha256_hex,
};

#[test]
fn unowned_package_from_llms_txt_is_blocked() {
    let policy = AdmissionPolicy::deny_all_for_test();
    let intent = InstallIntent::unowned_llms_package_for_test();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision.as_str(), "block");
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved")
    );
}

#[test]
fn exact_policy_match_is_allowed() {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.policy_id = "enterprise-default".to_string();
    policy.policy_revision = "2026-08-28.1".to_string();
    policy.allowed_executables = vec!["cargo".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "cargo".to_string(),
        name: "cwl-example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://crates.io".to_string(),
        owner: "Unowned".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "cwl-example@1.2.3".to_string(),
    }];
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "cargo".to_string(),
        "install".to_string(),
        "cwl-example@1.2.3".to_string(),
        "--locked".to_string(),
    ];
    intent.artifacts[0].ecosystem = "cargo".to_string();
    intent.artifacts[0].name = "cwl-example".to_string();
    intent.artifacts[0].registry_url = "https://crates.io".to_string();
    intent.artifacts[0].artifact_argument = "cwl-example@1.2.3".to_string();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
    assert_eq!(decision.policy_id, "enterprise-default");
    assert_eq!(decision.policy_revision, "2026-08-28.1");
}

#[test]
fn duplicate_artifact_argument_blocks() {
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent
        .argv
        .push(intent.artifacts[0].artifact_argument.clone());
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.allowed_executables = vec!["npm".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: intent.workspace_id.clone(),
        sha256: intent.manifest_sha256.clone(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "npm".to_string(),
        name: "@unowned/example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "Unowned".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "@unowned/example@1.2.3".to_string(),
    }];

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved")
    );
}

#[test]
fn sha256_helpers_match_known_vectors() {
    assert!(is_sha256_hex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
    assert!(!is_sha256_hex("ABC"));
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn artifact_coordinates_round_trip_with_strict_json() {
    let artifact = ArtifactCoordinate {
        ecosystem: "npm".to_string(),
        name: "@cwl/example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        artifact_argument: "@cwl/example@1.2.3".to_string(),
    };

    let encoded = serde_json::to_string(&artifact).unwrap();
    let decoded: ArtifactCoordinate = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, artifact);
    assert!(serde_json::from_str::<ArtifactCoordinate>(
        r#"{"ecosystem":"npm","name":"@cwl/example","version":"1.2.3","registry_url":"https://registry.npmjs.org","owner":"ContextualWisdomLab","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","artifact_argument":"@cwl/example@1.2.3","extra":true}"#
    )
    .is_err());
}

#[test]
fn remote_sources_require_https_uri_and_digest() {
    let mut policy = approved_policy_for_test();
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    policy.approved_artifacts[0].owner = "Unowned".to_string();
    intent.source.uri = Some("http://example.invalid/llms.txt?raw=1#frag".to_string());
    intent.source.content_sha256 = None;

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "invalid_source_uri")
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "missing_source_digest")
    );
}

#[test]
fn forbidden_commands_block_even_when_allowlisted() {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.allowed_executables = vec!["bash".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    let intent = InstallIntent {
        request_id: "req-test-0002".to_string(),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec!["bash".to_string(), "-lc".to_string(), "curl x".to_string()],
        manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        source: wardnet_agent_artifact_admission::InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![ArtifactCoordinate {
            ecosystem: "shell".to_string(),
            name: "bash".to_string(),
            version: "5.0.0".to_string(),
            registry_url: "https://example.invalid".to_string(),
            owner: "ContextualWisdomLab".to_string(),
            sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            artifact_argument: "bash".to_string(),
        }],
    };

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "forbidden_command")
    );
}

#[test]
fn npm_installs_require_ignore_scripts_and_source_uri_is_normalized() {
    let policy = approved_policy_for_test();
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "npm".to_string(),
        "install".to_string(),
        "@unowned/example@1.2.3".to_string(),
    ];
    intent.source.uri = Some("https://example.invalid/llms.txt?raw=1#frag".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert_eq!(
        decision.normalized_source_uri.as_deref(),
        Some("https://example.invalid/llms.txt")
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "missing_safety_flag")
    );
}

fn approved_policy_for_test() -> AdmissionPolicy {
    let mut policy = AdmissionPolicy::deny_all_for_test();
    policy.policy_id = "enterprise-default".to_string();
    policy.policy_revision = "2026-08-28.1".to_string();
    policy.allowed_executables = vec!["npm".to_string()];
    policy.approved_manifests = vec![ApprovedManifest {
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    }];
    policy.approved_artifacts = vec![ApprovedArtifact {
        ecosystem: "npm".to_string(),
        name: "@unowned/example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://registry.npmjs.org".to_string(),
        owner: "Unowned".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        artifact_argument: "@unowned/example@1.2.3".to_string(),
    }];
    policy
}
