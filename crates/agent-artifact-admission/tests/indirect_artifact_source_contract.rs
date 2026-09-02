use wardnet_agent_artifact_admission::{
    AdmissionPolicy, ApprovedArtifact, ApprovedManifest, ArtifactCoordinate, DecisionKind,
    InstallIntent, InstructionSource, InstructionSourceKind, admission_decision,
};

#[test]
fn pip_family_cannot_source_undeclared_artifacts_from_files_or_editable_paths() {
    let cases: &[(&str, &[&str])] = &[
        (
            "pip",
            &["install", "cwl-example==1.2.3", "--require-hashes", "-r", "requirements.txt"],
        ),
        (
            "pip3",
            &[
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "--requirement=requirements.txt",
            ],
        ),
        (
            "pip",
            &["install", "cwl-example==1.2.3", "--require-hashes", "-e", "./unreviewed"],
        ),
        (
            "pip3",
            &[
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "--editable=./unreviewed",
            ],
        ),
        (
            "pip",
            &[
                "install",
                "cwl-example==1.2.3",
                "--require-hashes",
                "--requirements-from-script=unreviewed.py",
            ],
        ),
    ];

    for (executable, arguments) in cases {
        assert_indirect_source_blocked(executable, arguments);
    }
}

#[test]
fn uv_pip_cannot_source_undeclared_artifacts_from_files_groups_or_editable_paths() {
    let cases: &[&[&str]] = &[
        &["pip", "install", "cwl-example==1.2.3", "--require-hashes", "-r", "requirements.txt"],
        &[
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--require-hashes",
            "--requirements=requirements.txt",
        ],
        &["pip", "install", "cwl-example==1.2.3", "--require-hashes", "-e", "./unreviewed"],
        &[
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--require-hashes",
            "--editable=./unreviewed",
        ],
        &["pip", "install", "cwl-example==1.2.3", "--require-hashes", "--group", "unreviewed"],
        &["pip", "install", "cwl-example==1.2.3", "--require-hashes", "--group=unreviewed"],
        &[
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--require-hashes",
            "--project",
            "./unreviewed",
            "--group",
            "runtime",
        ],
        &[
            "pip",
            "install",
            "cwl-example==1.2.3",
            "--require-hashes",
            "--project=./unreviewed",
            "--group=runtime",
        ],
    ];

    for arguments in cases {
        assert_indirect_source_blocked("uv", arguments);
    }
}

fn assert_indirect_source_blocked(executable: &str, arguments: &[&str]) {
    let artifact = ArtifactCoordinate {
        ecosystem: "pypi".to_string(),
        name: "cwl-example".to_string(),
        version: "1.2.3".to_string(),
        registry_url: "https://pypi.org/simple".to_string(),
        owner: "ContextualWisdomLab".to_string(),
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        artifact_argument: "cwl-example==1.2.3".to_string(),
    };
    let policy = AdmissionPolicy {
        policy_id: "enterprise-default".to_string(),
        policy_revision: "2026-09-02.2".to_string(),
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
        request_id: format!("req-indirect-source-{executable}"),
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

    let decision = admission_decision(&policy, &intent);
    assert_eq!(
        decision.decision,
        DecisionKind::Block,
        "{executable} {} must not source undeclared artifacts",
        arguments.join(" ")
    );
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == "artifact_not_approved"),
        "indirect package sources must use the stable artifact_not_approved reason"
    );
}
