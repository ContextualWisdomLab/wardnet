use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision, sha256_hex,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";

#[test]
fn baseline_uv_pip_install_with_exact_dependency_guard_remains_allowed() {
    let (policy, intent) = approved_uv_intent(vec![
        "uv",
        "pip",
        "install",
        ARTIFACT_ARGUMENT,
        "--require-hashes",
        "--no-deps",
        "--no-python-downloads",
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
    assert_eq!(decision.command_sha256, submitted_command_sha256(&intent));
}

#[test]
fn uv_global_options_preserve_missing_dependency_set_guard_evidence() {
    let (policy, intent) = approved_uv_intent(vec![
        "uv",
        "--color",
        "never",
        "pip",
        "install",
        ARTIFACT_ARGUMENT,
        "--require-hashes",
        "--no-python-downloads",
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(has_reason(&decision.reason_codes, "forbidden_command"));
    assert!(
        has_reason(&decision.reason_codes, "missing_safety_flag"),
        "global uv options must not erase missing --no-deps evidence"
    );
    assert_eq!(decision.command_sha256, submitted_command_sha256(&intent));
}

#[test]
fn uv_global_options_with_exact_dependency_guard_do_not_emit_false_missing_flag() {
    let (policy, intent) = approved_uv_intent(vec![
        "uv",
        "--color",
        "never",
        "pip",
        "install",
        ARTIFACT_ARGUMENT,
        "--require-hashes",
        "--no-deps",
        "--no-python-downloads",
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(has_reason(&decision.reason_codes, "forbidden_command"));
    assert!(
        !has_reason(&decision.reason_codes, "missing_safety_flag"),
        "an exact --no-deps guard must not acquire false missing-safety evidence"
    );
    assert_eq!(decision.command_sha256, submitted_command_sha256(&intent));
}

#[test]
fn uv_global_options_on_pip_sync_do_not_acquire_install_dependency_set_evidence() {
    let (policy, intent) = approved_uv_intent(vec![
        "uv",
        "--color",
        "never",
        "pip",
        "sync",
        ARTIFACT_ARGUMENT,
        "--require-hashes",
        "--no-python-downloads",
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(has_reason(&decision.reason_codes, "forbidden_command"));
    assert!(
        !has_reason(&decision.reason_codes, "missing_safety_flag"),
        "uv pip sync must not be classified as a pip-install dependency-cardinality path"
    );
    assert_eq!(decision.command_sha256, submitted_command_sha256(&intent));
}

fn has_reason(reasons: &[wardnet_agent_artifact_admission::ReasonCode], expected: &str) -> bool {
    reasons.iter().any(|reason| reason.as_str() == expected)
}

fn submitted_command_sha256(intent: &InstallIntent) -> String {
    sha256_hex(intent.argv.join("\u{1f}").as_bytes())
}

fn approved_uv_intent(argv: Vec<&str>) -> (AdmissionPolicy, InstallIntent) {
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
        policy_id: "uv-global-dependency-cardinality".to_string(),
        policy_revision: "2026-09-13.1".to_string(),
        allowed_executables: vec!["uv".to_string()],
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
        request_id: "req-uv-global-dependency-cardinality".to_string(),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: argv.into_iter().map(str::to_string).collect(),
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
