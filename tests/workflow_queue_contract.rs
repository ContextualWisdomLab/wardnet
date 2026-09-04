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
    for name in ["ci.yml", "fuzz.yml"] {
        let workflow = workflow_text(name);
        assert!(workflow.contains(
            "group: ${{ github.workflow }}-${{ github.repository }}-${{ github.event.pull_request.number || github.run_id }}"
        ));
        assert!(
            workflow.contains("cancel-in-progress: ${{ github.event_name == 'pull_request' }}")
        );
        assert!(workflow.contains(
            "types: [opened, synchronize, reopened, ready_for_review, converted_to_draft, closed]"
        ));
        assert!(workflow.contains("github.event.pull_request.draft == false"));
        assert!(workflow.contains("github.event.action != 'closed'"));
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
