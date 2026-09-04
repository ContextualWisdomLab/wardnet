use std::{fs, path::PathBuf};

fn workflow_text(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".github/workflows")
            .join(name),
    )
    .unwrap()
}

#[test]
fn local_pr_workflows_cancel_only_superseded_heads_of_the_same_pull_request() {
    for (name, expected_group) in [
        (
            "ci.yml",
            "group: wardnet-ci-${{ github.repository }}-${{ github.event_name == 'pull_request' && (github.event.action == 'opened' || github.event.action == 'synchronize') && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
        ),
        (
            "fuzz.yml",
            "group: wardnet-fuzz-${{ github.repository }}-${{ github.event_name == 'pull_request' && (github.event.action == 'opened' || github.event.action == 'synchronize') && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
        ),
    ] {
        let workflow = workflow_text(name);
        assert!(workflow.contains(expected_group));
        assert!(!workflow.contains("group: ${{ github.workflow }}"));
        assert!(workflow.contains(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' && github.event.action == 'synchronize' }}"
        ));
        assert!(workflow.contains(
            "types: [opened, synchronize, reopened, ready_for_review]"
        ));
        assert!(!workflow.contains("converted_to_draft"));
        assert!(!workflow.contains("closed]"));
        assert!(workflow.contains(
            "if: ${{ github.event_name != 'pull_request' || github.event.pull_request.draft == false }}"
        ));
    }
}

#[test]
fn fuzz_keeps_path_filtered_validation_without_state_transition_cancellation() {
    let workflow = workflow_text("fuzz.yml");
    assert!(workflow.contains("    paths:\n"));
    for path in [
        "src/**",
        "crates/**",
        "fuzz/**",
        ".github/workflows/fuzz.yml",
    ] {
        assert!(workflow.contains(path));
    }
}

#[test]
fn fuzz_uses_one_runner_for_all_bounded_targets() {
    let workflow = workflow_text("fuzz.yml");
    assert!(!workflow.contains("\n    strategy:\n"));
    assert!(!workflow.contains("Set fuzz duration"));
    for target in [
        "fuzz_score_request",
        "fuzz_appdata_json",
        "fuzz_parse_admin_tokens",
        "fuzz_dnsbl_zone",
    ] {
        assert!(workflow.contains(target));
    }
}

#[test]
fn central_required_workflows_are_not_copied_locally() {
    let workflow_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    for name in [
        "pr-governance.yml",
        "dependency-review.yml",
        "close-empty-pr.yml",
        "codeql-pr.yml",
        "security-scan.yml",
        "sast-semgrep.yml",
        "strix.yml",
        "opencode-review.yml",
        "noema-review.yml",
    ] {
        assert!(!workflow_directory.join(name).exists());
    }
}

#[test]
fn local_scorecard_preserves_non_pr_security_evidence() {
    let workflow = workflow_text("scorecard-analysis.yml");
    assert!(workflow.contains("branch_protection_rule:"));
    assert!(workflow.contains("schedule:"));
    assert!(workflow.contains("push:"));
    assert!(!workflow.contains("pull_request:"));
    assert!(workflow.contains("# v2.4.4"));
}
