use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";

#[test]
fn approved_pip_install_without_proxy_override_remains_allowed() {
    for executable in ["pip", "pip3"] {
        let (policy, intent) = approved_pip_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Allow,
            "{executable} baseline must remain admissible"
        );
        assert!(decision.reason_codes.is_empty());
    }
}

#[test]
fn pip_global_proxy_before_install_fails_closed_without_artifact_pollution() {
    for executable in ["pip", "pip3"] {
        for proxy_arguments in [
            vec![
                "--proxy".to_string(),
                "http://attacker.invalid:8080".to_string(),
            ],
            vec![
                "--prox".to_string(),
                "http://attacker.invalid:8080".to_string(),
            ],
            vec!["--proxy=http://attacker.invalid:8080".to_string()],
            vec!["--prox=http://attacker.invalid:8080".to_string()],
        ] {
            let (policy, mut intent) = approved_pip_install(executable);
            let install_arguments = intent.argv.split_off(1);
            intent.argv.extend(proxy_arguments.clone());
            intent.argv.extend(install_arguments);
            let submitted_command_sha256 = sha256_hex(intent.argv.join("\u{1f}").as_bytes());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} must reject parser-valid global proxy authority before install: {:?}",
                proxy_arguments
            );
            assert_eq!(
                decision.reason_codes,
                vec![ReasonCode::AlternateTrustRoot],
                "global proxy authority must produce only its causal trust-authority evidence: {:?}",
                decision.reason_codes
            );
            assert_eq!(
                decision.command_sha256, submitted_command_sha256,
                "policy normalization must not rewrite submitted-command evidence"
            );
        }
    }
}

#[test]
fn pip_global_proxy_value_does_not_hide_a_genuine_extra_artifact() {
    for executable in ["pip", "pip3"] {
        for proxy_option in ["--proxy", "--prox"] {
            let (policy, mut intent) = approved_pip_install(executable);
            let install_arguments = intent.argv.split_off(1);
            intent.argv.push(proxy_option.to_string());
            intent.argv.push("http://attacker.invalid:8080".to_string());
            intent.argv.extend(install_arguments);
            intent.argv.push("attacker-package==9.9.9".to_string());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(decision.decision, DecisionKind::Block);
            assert_eq!(
                decision.reason_codes.len(),
                2,
                "global proxy normalization must consume only the reviewed proxy value: {:?}",
                decision.reason_codes
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::AlternateTrustRoot),
                "global {proxy_option:?} must retain proxy/trust-authority evidence: {:?}",
                decision.reason_codes
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::ArtifactNotApproved),
                "a real undeclared package must remain visible after global proxy normalization: {:?}",
                decision.reason_codes
            );
        }
    }
}

#[test]
fn unreviewed_pip_global_option_is_not_hidden_by_proxy_normalization() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        let install_arguments = intent.argv.split_off(1);
        intent.argv.extend([
            "--timeout".to_string(),
            "1".to_string(),
        ]);
        intent.argv.extend(install_arguments);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision.reason_codes.contains(&ReasonCode::ForbiddenCommand),
            "unreviewed global option grammar must remain outside the supported command path: {:?}",
            decision.reason_codes
        );
        assert!(
            decision.reason_codes.contains(&ReasonCode::ArtifactNotApproved),
            "an arbitrary global option value must not be silently consumed as proxy syntax: {:?}",
            decision.reason_codes
        );
    }
}

#[test]
fn pip_proxy_override_cannot_inherit_artifact_approval() {
    for executable in ["pip", "pip3"] {
        for proxy_option in [
            "--proxy=http://attacker.invalid:8080",
            "--prox=http://attacker.invalid:8080",
        ] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv.push(proxy_option.to_string());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} must not let accepted proxy selector {proxy_option:?} inherit approved artifact authority"
            );
            assert_eq!(
                decision.reason_codes,
                vec![ReasonCode::AlternateTrustRoot],
                "attached proxy routing authority {proxy_option:?} must produce only its causal trust-authority evidence"
            );
        }
    }
}

#[test]
fn pip_separate_proxy_value_is_not_misclassified_as_an_artifact() {
    for executable in ["pip", "pip3"] {
        for proxy_option in ["--proxy", "--prox"] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv.push(proxy_option.to_string());
            intent.argv.push("http://attacker.invalid:8080".to_string());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} separate proxy syntax {proxy_option:?} must fail closed"
            );
            assert_eq!(
                decision.reason_codes,
                vec![ReasonCode::AlternateTrustRoot],
                "the value consumed by {proxy_option:?} is proxy authority, not a second package artifact"
            );
        }
    }
}

#[test]
fn genuine_extra_artifact_remains_visible_beside_separate_proxy_authority() {
    for executable in ["pip", "pip3"] {
        for proxy_option in ["--proxy", "--prox"] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv.push(proxy_option.to_string());
            intent.argv.push("http://attacker.invalid:8080".to_string());
            intent.argv.push("attacker-package==9.9.9".to_string());

            let decision = admission_decision(&policy, &intent);

            assert_eq!(decision.decision, DecisionKind::Block);
            assert_eq!(
                decision.reason_codes.len(),
                2,
                "a consumed proxy value must add no spurious reason while a real extra package remains visible: {:?}",
                decision.reason_codes
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::AlternateTrustRoot),
                "separate {proxy_option:?} must retain its causal proxy/trust-authority reason: {:?}",
                decision.reason_codes
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::ArtifactNotApproved),
                "a genuine undeclared package must remain visible independently of the consumed proxy value: {:?}",
                decision.reason_codes
            );
        }
    }
}

#[test]
fn pip_no_proxy_env_cannot_disable_reviewed_runtime_proxy_selection() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv.push("--no-proxy-env".to_string());

        let decision = admission_decision(&policy, &intent);

        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{executable} must not let caller argv disable runtime proxy selection"
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "proxy-environment suppression must be classified explicitly: {:?}",
            decision.reason_codes
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
        sha256: ARTIFACT_DIGEST.to_string(),
        artifact_argument: ARTIFACT_ARGUMENT.to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "pypi-proxy-authority".to_string(),
        policy_revision: "2026-09-12.1".to_string(),
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
        request_id: format!("req-pypi-proxy-{executable}"),
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
