use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn package_managers_cannot_escape_the_broker_selected_install_root() {
    let cases = [
        install_case(
            "npm",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &["install", "@cwl/example@1.2.3", "--ignore-scripts", "--global"],
        ),
        install_case(
            "pnpm",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &["add", "@cwl/example@1.2.3", "--ignore-scripts", "-g"],
        ),
        install_case(
            "yarn",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &["add", "@cwl/example@1.2.3", "--ignore-scripts", "--global"],
        ),
        install_case(
            "bun",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &["add", "@cwl/example@1.2.3", "--ignore-scripts", "--prefix=/tmp/escape"],
        ),
        install_case(
            "pip",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &["install", "cwl-example==1.2.3", "--require-hashes", "--target=/tmp/escape"],
        ),
        install_case(
            "pip3",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &["install", "cwl-example==1.2.3", "--require-hashes", "--user"],
        ),
        install_case(
            "uv",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &[
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "--prefix=/tmp/escape",
            ],
        ),
        install_case(
            "cargo",
            "cargo",
            "cwl-example",
            "cwl-example@1.2.3",
            "https://crates.io",
            &["install", "cwl-example@1.2.3", "--locked", "--root=/tmp/escape"],
        ),
    ];

    for (policy, intent, label) in cases {
        assert_alternate_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn uv_environment_selection_cannot_escape_the_broker_selected_install_root() {
    for extra_arguments in [
        vec!["--system"],
        vec!["--python=/tmp/escape/bin/python"],
        vec!["--python", "/tmp/escape/bin/python"],
        vec!["-p", "/tmp/escape/bin/python"],
    ] {
        let mut arguments = vec!["pip", "install", "cwl-example==1.2.3", "--require-hashes"];
        arguments.extend(extra_arguments);
        let (policy, intent, label) = install_case(
            "uv",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &arguments,
        );

        assert_alternate_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn uv_index_selection_cannot_override_the_approved_registry() {
    for extra_arguments in [
        vec!["--index", "https://packages.example.invalid/simple"],
        vec!["--index=https://packages.example.invalid/simple"],
        vec!["--default-index", "https://packages.example.invalid/simple"],
        vec!["--default-index=https://packages.example.invalid/simple"],
    ] {
        let mut arguments = vec!["pip", "install", "cwl-example==1.2.3", "--require-hashes"];
        arguments.extend(extra_arguments);
        let (policy, intent, label) = install_case(
            "uv",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &arguments,
        );

        assert_alternate_trust_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn cargo_source_selection_cannot_override_the_approved_registry() {
    for extra_arguments in [
        vec!["--git", "https://example.invalid/unreviewed.git"],
        vec!["--git=https://example.invalid/unreviewed.git"],
        vec!["--path", "/tmp/unreviewed-crate"],
        vec!["--path=/tmp/unreviewed-crate"],
    ] {
        let mut arguments = vec!["install", "cwl-example@1.2.3", "--locked"];
        arguments.extend(extra_arguments);
        let (policy, intent, label) = install_case(
            "cargo",
            "cargo",
            "cwl-example",
            "cwl-example@1.2.3",
            "https://crates.io",
            &arguments,
        );

        assert_alternate_trust_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn cargo_inline_configuration_cannot_override_install_root() {
    for extra_arguments in [
        vec!["--config=install.root='/tmp/escape'"],
        vec!["--config", "install.root='/tmp/escape'"],
    ] {
        let mut arguments = vec!["install", "cwl-example@1.2.3", "--locked"];
        arguments.extend(extra_arguments);
        let (policy, intent, label) = install_case(
            "cargo",
            "cargo",
            "cwl-example",
            "cwl-example@1.2.3",
            "https://crates.io",
            &arguments,
        );

        assert_alternate_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn npm_location_global_spellings_are_blocked() {
    for location_arguments in [
        vec!["--location=global"],
        vec!["--location", "GLOBAL"],
    ] {
        let mut arguments = vec!["install", "@cwl/example@1.2.3", "--ignore-scripts"];
        arguments.extend(location_arguments);
        let (policy, intent, label) = install_case(
            "npm",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &arguments,
        );

        assert_alternate_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn npm_workspace_selection_cannot_expand_the_broker_selected_install_scope() {
    for workspace_arguments in [
        vec!["--workspace", "packages/unreviewed"],
        vec!["--workspace=packages/unreviewed"],
        vec!["-w", "packages/unreviewed"],
        vec!["-w=packages/unreviewed"],
        vec!["--workspaces"],
        vec!["--workspaces=true"],
    ] {
        let mut arguments = vec!["install", "@cwl/example@1.2.3", "--ignore-scripts"];
        arguments.extend(workspace_arguments);
        let (policy, intent, label) = install_case(
            "npm",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &arguments,
        );

        assert_alternate_root_blocked(&policy, &intent, &label);
    }
}

#[test]
fn undeclared_artifact_operands_cannot_hitchhike_on_approved_installs() {
    let extra_digest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let cases = [
        install_case(
            "npm",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &[
                "install",
                "@cwl/example@1.2.3",
                "--ignore-scripts",
                "@attacker/extra@9.9.9",
            ],
        ),
        install_case(
            "pnpm",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &[
                "add",
                "@cwl/example@1.2.3",
                "--ignore-scripts",
                "@attacker/extra@9.9.9",
            ],
        ),
        install_case(
            "yarn",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &[
                "add",
                "@cwl/example@1.2.3",
                "--ignore-scripts",
                "@attacker/extra@9.9.9",
            ],
        ),
        install_case(
            "bun",
            "npm",
            "@cwl/example",
            "@cwl/example@1.2.3",
            "https://registry.npmjs.org",
            &[
                "add",
                "@cwl/example@1.2.3",
                "--ignore-scripts",
                "@attacker/extra@9.9.9",
            ],
        ),
        install_case(
            "pip",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &[
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "attacker-extra==9.9.9",
            ],
        ),
        install_case(
            "pip3",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &[
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "attacker-extra==9.9.9",
            ],
        ),
        install_case(
            "uv",
            "pypi",
            "cwl-example",
            "cwl-example==1.2.3",
            "https://pypi.org/simple",
            &[
                "pip",
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "attacker-extra==9.9.9",
            ],
        ),
        install_case(
            "cargo",
            "cargo",
            "cwl-example",
            "cwl-example@1.2.3",
            "https://crates.io",
            &[
                "install",
                "cwl-example@1.2.3",
                "--locked",
                "attacker-extra@9.9.9",
            ],
        ),
        install_case(
            "docker",
            "oci",
            "ghcr.io/contextualwisdomlab/example",
            "ghcr.io/contextualwisdomlab/example@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "https://ghcr.io",
            &[
                "pull",
                "ghcr.io/contextualwisdomlab/example@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "ghcr.io/attacker/extra@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ],
        ),
        install_case(
            "podman",
            "oci",
            "ghcr.io/contextualwisdomlab/example",
            "ghcr.io/contextualwisdomlab/example@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "https://ghcr.io",
            &[
                "pull",
                "ghcr.io/contextualwisdomlab/example@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "ghcr.io/attacker/extra@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ],
        ),
    ];

    assert_eq!(extra_digest.len(), 64);
    for (policy, intent, label) in cases {
        let decision = admission_decision(&policy, &intent);
        assert_eq!(
            decision.decision,
            DecisionKind::Block,
            "{label} must not execute an undeclared positional artifact"
        );
        assert!(
            decision
                .reason_codes
                .iter()
                .any(|reason| reason.as_str() == "artifact_not_approved"),
            "{label} must produce the stable artifact_not_approved reason"
        );
    }
}

#[test]
fn container_pull_is_not_misclassified_as_an_install_root_escape() {
    let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let artifact_argument = format!("ghcr.io/contextualwisdomlab/example@sha256:{digest}");
    let (policy, intent, _) = install_case(
        "docker",
        "oci",
        "ghcr.io/contextualwisdomlab/example",
        &artifact_argument,
        "https://ghcr.io",
        &["pull", &artifact_argument],
    );

    let decision = admission_decision(&policy, &intent);

    assert_eq!(decision.decision, DecisionKind::Allow);
    assert!(!decision
        .reason_codes
        .iter()
        .any(|reason| reason.as_str() == "alternate_install_root"));
}

fn assert_alternate_root_blocked(policy: &AdmissionPolicy, intent: &InstallIntent, label: &str) {
    let decision = admission_decision(policy, intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "{label} must not turn an approved artifact into a global or alternate-root install"
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_install_root"),
        "{label} must produce the stable alternate_install_root reason"
    );
}

fn assert_alternate_trust_root_blocked(
    policy: &AdmissionPolicy,
    intent: &InstallIntent,
    label: &str,
) {
    let decision = admission_decision(policy, intent);

    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "{label} must not replace or supplement the reviewed artifact registry"
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "alternate_trust_root"),
        "{label} must produce the stable alternate_trust_root reason"
    );
}

fn install_case(
    executable: &str,
    ecosystem: &str,
    name: &str,
    artifact_argument: &str,
    registry_url: &str,
    arguments: &[&str],
) -> (AdmissionPolicy, InstallIntent, String) {
    let artifact = ArtifactCoordinate {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: "1.2.3".to_string(),
        registry_url: registry_url.to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        artifact_argument: artifact_argument.to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-09-02.1".to_string(),
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
    let mut argv = Vec::with_capacity(arguments.len() + 1);
    argv.push(executable.to_string());
    argv.extend(arguments.iter().map(|argument| (*argument).to_string()));
    let intent = InstallIntent {
        request_id: format!("req-install-root-{executable}"),
        actor_id: "agent:codex:test".to_string(),
        workspace_id: "ContextualWisdomLab/wardnet".to_string(),
        operation: "install".to_string(),
        argv,
        manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        source: InstructionSource {
            kind: InstructionSourceKind::ReviewedConfig,
            uri: None,
            content_sha256: None,
        },
        artifacts: vec![artifact],
    };
    let label = format!("{executable} {}", arguments.join(" "));
    (policy, intent, label)
}
