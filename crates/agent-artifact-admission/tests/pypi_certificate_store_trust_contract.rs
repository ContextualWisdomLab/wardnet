use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";

#[test]
fn reviewed_pip_install_without_certificate_override_remains_admissible() {
    for executable in ["pip", "pip3"] {
        let (policy, intent) = approved_pip_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow, "{executable}");
        assert!(decision.reason_codes.is_empty(), "{executable}");
    }
}

#[test]
fn pip_certificate_bundle_override_cannot_inherit_artifact_approval() {
    for executable in ["pip", "pip3"] {
        for certificate_bundle in [
            "/tmp/attacker-ca.pem",
            "./workspace-ca.pem",
            "/etc/ssl/private/alternate.pem",
        ] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv.push(format!("--cert={certificate_bundle}"));

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} must not let an approved package coordinate authorize a caller-selected certificate store"
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::AlternateTrustRoot),
                "certificate-store authority must be classified explicitly: {:?}",
                decision.reason_codes
            );
        }
    }
}

#[test]
fn pip_certificate_bundle_unambiguous_prefix_is_explicit_trust_authority() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv.push("--ce=/tmp/attacker-ca.pem".to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block, "{executable}");
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "pip's accepted --ce certificate-store prefix must remain explicit trust-authority evidence: {:?}",
            decision.reason_codes
        );
    }
}

#[test]
fn pip_separate_certificate_prefix_value_is_explicit_trust_authority() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv.push("--ce".to_string());
        intent.argv.push("/tmp/attacker-ca.pem".to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block, "{executable}");
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "pip's separate-value --ce prefix must be classified as trust authority independently of operand validation: {:?}",
            decision.reason_codes
        );
    }
}

#[test]
fn pip_separate_certificate_value_is_classified_as_alternate_trust_authority() {
    let (policy, mut intent) = approved_pip_install("pip");
    intent.argv.push("--cert".to_string());
    intent.argv.push("/tmp/attacker-ca.pem".to_string());

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Block);
    assert!(
        decision
            .reason_codes
            .contains(&ReasonCode::AlternateTrustRoot),
        "an extra-operand rejection alone must not hide the certificate-store override: {:?}",
        decision.reason_codes
    );
}

#[test]
fn repeated_pip_certificate_overrides_emit_one_trust_reason() {
    let (policy, mut intent) = approved_pip_install("pip");
    intent.argv.extend([
        "--cert=/tmp/first.pem".to_string(),
        "--cert=/tmp/second.pem".to_string(),
        "--trusted-host=pypi.org".to_string(),
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

fn approved_pip_install(executable: &str) -> (AdmissionPolicy, InstallIntent) {
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
        policy_id: "pypi-certificate-store-trust".to_string(),
        policy_revision: "2026-09-10.1".to_string(),
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
    let intent = InstallIntent {
        request_id: format!("req-pypi-cert-{executable}"),
        actor_id: "agent:wardnet:admission".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv: vec![
            executable.to_string(),
            "install".to_string(),
            ARTIFACT_ARGUMENT.to_string(),
            "--require-hashes".to_string(),
            "--no-deps".to_string(),
            "--no-input".to_string(),
        ],
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
