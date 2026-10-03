//! Repository contract for isolated self-hosted runner selection.
//!
//! Runner labels are routing requirements, not proof of isolation or capacity.
//! General CI executes repository code and must not select privileged control,
//! scanner or inference-host pools. Provisioning and actual job receipts remain
//! separate acceptance obligations.

use std::fs;
use std::path::Path;

const ISOLATED_RUNNER: &str = "[self-hosted, Linux, X64, cwlab-ci-isolated]";
const RUNNER_BACKED_WORKFLOWS: &[&str] = &[
    ".github/workflows/ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/scorecard-analysis.yml",
];

#[test]
fn every_local_workflow_requires_the_isolated_self_hosted_pool() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = repository.join(".github/workflows");
    let mut observed = Vec::new();
    for file in fs::read_dir(directory).unwrap() {
        let path = file.unwrap().path();
        if !matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let workflow = fs::read_to_string(&path).unwrap();
        let runners: Vec<_> = workflow
            .lines()
            .filter_map(|line| line.trim().strip_prefix("runs-on:"))
            .map(str::trim)
            .collect();
        assert!(
            !runners.is_empty(),
            "{} must have a concrete runner",
            path.display()
        );
        assert!(
            runners.iter().all(|runner| *runner == ISOLATED_RUNNER),
            "{} must select only {ISOLATED_RUNNER}; found {runners:?}",
            path.display()
        );
        observed.push(
            path.strip_prefix(repository)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }
    observed.sort();
    assert_eq!(
        observed,
        RUNNER_BACKED_WORKFLOWS
            .iter()
            .map(|path| path.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn checkout_credentials_are_not_persisted_on_self_hosted_workers() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in RUNNER_BACKED_WORKFLOWS {
        let workflow = fs::read_to_string(repository.join(relative)).unwrap();
        assert_eq!(workflow.matches("actions/checkout@").count(), 1);
        assert_eq!(
            workflow.matches("persist-credentials: false").count(),
            1,
            "{relative} must not leave checkout credentials in the workspace"
        );
    }
}
