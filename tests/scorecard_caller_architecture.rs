use std::{fs, path::PathBuf};

const CENTRAL_SCORECARD_MERGE_SHA: &str = "51b812d181989ed28366b5850d1a34f51df10187";

fn scorecard_workflow_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".github/workflows/scorecard-analysis.yml");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "default-branch Scorecard caller must exist at {}: {error}",
            path.display()
        )
    })
}

#[test]
fn default_branch_scorecard_is_a_thin_immutable_caller() {
    let workflow = scorecard_workflow_source();
    let immutable_owner = format!(
        "uses: ContextualWisdomLab/.github/.github/workflows/scorecard-analysis.yml@{CENTRAL_SCORECARD_MERGE_SHA}"
    );

    assert!(
        workflow.contains(&immutable_owner),
        "Scorecard must delegate to the immutable protected central merge SHA"
    );
    assert!(
        workflow.contains("branch_protection_rule:"),
        "branch-protection posture changes must continue refreshing Scorecard evidence"
    );
    assert!(
        workflow.contains("branches: [main]") || workflow.contains("branches: [\"main\"]"),
        "protected main pushes must continue refreshing Scorecard evidence"
    );
    assert!(
        workflow.contains("31 9 * * 2"),
        "Wardnet's established weekly Scorecard schedule must be preserved"
    );
    for permission in [
        "security-events: write",
        "id-token: write",
        "contents: read",
        "issues: read",
        "pull-requests: read",
        "checks: read",
    ] {
        assert!(
            workflow.contains(permission),
            "reusable Scorecard caller is missing required permission {permission}"
        );
    }

    assert!(
        !workflow.contains("runs-on:"),
        "the leaf caller must not own a runner contract"
    );
    assert!(
        !workflow.contains("steps:"),
        "the leaf caller must not copy central implementation steps"
    );
    assert!(
        !workflow.contains("ossf/scorecard-action@")
            && !workflow.contains("github/codeql-action/upload-sarif@"),
        "Scorecard implementation must remain in the canonical .github owner"
    );
    assert!(
        !workflow.contains("concurrency:") && !workflow.contains("cancel-in-progress:"),
        "the leaf caller must not override the central same-ref concurrency contract"
    );
}
