//! Repository contract for deterministic GitHub-hosted runner selection.
//!
//! Wardnet's required pull-request workflows must not depend on GitHub's floating
//! `ubuntu-latest` alias. A floating image can change independently of the
//! repository and, during hosted-runner transitions, can leave exact-head jobs
//! queued before checkout. Pinning the Ubuntu image makes runner acquisition a
//! reviewed repository change while preserving GitHub-hosted execution.

use std::fs;
use std::path::Path;

const PINNED_UBUNTU_RUNNER: &str = "ubuntu-24.04";
const FLOATING_UBUNTU_RUNNER: &str = "ubuntu-latest";

const RUNNER_BACKED_WORKFLOWS: &[&str] = &[
    ".github/workflows/ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/scorecard-analysis.yml",
];

#[test]
fn runner_backed_workflows_pin_the_hosted_ubuntu_image() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));

    for relative in RUNNER_BACKED_WORKFLOWS {
        let path = repository.join(relative);
        let workflow = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        assert!(
            !workflow.contains(FLOATING_UBUNTU_RUNNER),
            "{relative} must not use the floating {FLOATING_UBUNTU_RUNNER} runner alias"
        );

        let runners = workflow
            .lines()
            .filter_map(|line| line.trim().strip_prefix("runs-on:"))
            .map(str::trim)
            .collect::<Vec<_>>();
        assert!(
            !runners.is_empty(),
            "{relative} must define at least one runs-on value"
        );
        assert!(
            runners
                .iter()
                .all(|runner| *runner == PINNED_UBUNTU_RUNNER),
            "{relative} must use {PINNED_UBUNTU_RUNNER} for every runs-on value; found {runners:?}"
        );
    }
}
