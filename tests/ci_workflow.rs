//! Contracts for the exact Rust coverage workflow.

const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");

#[test]
fn coverage_export_reaches_the_exact_line_and_branch_gate() {
    assert!(
        !CI_WORKFLOW.contains("--fail-under-lines"),
        "llvm-cov must emit JSON before the repository-owned exact gate evaluates it"
    );
    for contract in [
        "metrics = (\\\"lines\\\", \\\"branches\\\")",
        "if covered != count:",
        "coverage gate failed:",
    ] {
        assert!(
            CI_WORKFLOW.contains(contract),
            "the exact line-and-branch coverage contract must retain {contract}"
        );
    }
}
