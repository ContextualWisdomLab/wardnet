use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, DecisionKind, InstallIntent, ReasonCode,
    admission_decision,
};

#[test]
fn reviewed_uv_install_without_transport_override_remains_admissible() {
    let (policy, intent) = approved_uv_install();

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn uv_equals_form_cannot_disable_tls_for_an_approved_artifact_source() {
    for host in [
        "pypi.org",
        "files.pythonhosted.org",
        "pypi.org:443",
        "https://pypi.org",
        "*",
    ] {
        for insert_before_artifact in [true, false] {
            let (policy, mut intent) = approved_uv_install();
            let flag = format!("--allow-insecure-host={host}");
            if insert_before_artifact {
                intent.argv.insert(3, flag);
            } else {
                intent.argv.push(flag);
            }

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "approved coordinates must not authorize the caller's TLS override for {host}"
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::AlternateTrustRoot),
                "TLS authority must be classified explicitly: {:?}",
                decision.reason_codes
            );
        }
    }
}

#[test]
fn uv_separate_value_is_classified_as_a_transport_trust_override() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.push("--allow-insecure-host".to_string());
    intent.argv.push("pypi.org".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "an extra operand rejection alone must not hide the TLS override: {:?}",
        decision.reason_codes
    );
}

#[test]
fn repeated_uv_transport_overrides_produce_one_trust_reason() {
    let (policy, mut intent) = approved_uv_install();
    intent.argv.extend([
        "--allow-insecure-host=pypi.org".to_string(),
        "--trusted-host=files.pythonhosted.org".to_string(),
        "--allow-insecure-host=pypi.org".to_string(),
    ]);

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert_eq!(
        decision
            .reason_codes
            .iter()
            .filter(|reason| **reason == ReasonCode::AlternateTrustRoot)
            .count(),
        1
    );
}

fn approved_uv_install() -> (AdmissionPolicy, InstallIntent) {
    let mut intent = InstallIntent::unowned_llms_package_for_test();
    intent.argv = vec![
        "uv".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "example-package==1.2.3".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
    ];
    let artifact = intent
        .artifacts
        .first_mut()
        .expect("test helper supplies one artifact");
    artifact.ecosystem = "pypi".to_string();
    artifact.name = "example-package".to_string();
    artifact.version = "1.2.3".to_string();
    artifact.registry_url = "https://pypi.org/simple".to_string();
    artifact.owner = "Example".to_string();
    artifact.artifact_argument = "example-package==1.2.3".to_string();
    let approved_artifact = ApprovedArtifact {
        ecosystem: artifact.ecosystem.clone(),
        name: artifact.name.clone(),
        version: artifact.version.clone(),
        registry_url: artifact.registry_url.clone(),
        owner: artifact.owner.clone(),
        sha256: artifact.sha256.clone(),
        artifact_argument: artifact.artifact_argument.clone(),
    };
    let policy = AdmissionPolicy {
        policy_id: "uv-transport-trust".to_string(),
        policy_revision: "2026-09-10.1".to_string(),
        allowed_executables: vec!["uv".to_string()],
        approved_manifests: vec![ApprovedManifest {
            workspace_id: intent.workspace_id.clone(),
            sha256: intent.manifest_sha256.clone(),
        }],
        approved_artifacts: vec![approved_artifact],
    };
    (policy, intent)
}
