//! Contracts for the exact Rust coverage workflow.

const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");

#[test]
fn coverage_export_reaches_the_exact_line_and_branch_gate() {
    let step_name = "- name: Enforce 100% production line and branch coverage";
    assert_eq!(
        CI_WORKFLOW.matches(step_name).count(),
        1,
        "CI must define exactly one authoritative production coverage step"
    );
    let coverage_step = CI_WORKFLOW
        .split_once(step_name)
        .map(|(_, step)| step)
        .expect("CI must retain the production coverage step");

    assert!(
        !coverage_step.contains("--fail-under-lines"),
        "llvm-cov must emit JSON before the repository-owned exact gate evaluates it"
    );
    for contract in [
        "toolchain: nightly-2026-08-06",
        "cargo install cargo-llvm-cov --version 0.8.7 --locked",
    ] {
        assert!(
            CI_WORKFLOW.contains(contract),
            "CI must retain the pinned coverage dependency contract {contract}"
        );
    }
    for contract in [
        "cargo +nightly-2026-08-06 llvm-cov",
        "--locked \\",
        "--branch \\",
        "--all-features \\",
        "--workspace \\",
        "--json \\",
        "--summary-only \\",
        "--output-path coverage.json",
        "report.get(\"data\")",
        "export.get(\"totals\")",
        "metrics = (\"lines\", \"branches\")",
        "if covered != count:",
        "coverage gate failed:",
    ] {
        assert!(
            coverage_step.contains(contract),
            "the exact line-and-branch coverage contract must retain {contract}"
        );
    }
}
