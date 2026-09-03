use std::fs;

fn release_workflow() -> String {
    fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow must exist before Wardnet can publish immutable evidence")
}

fn require(workflow: &str, needle: &str) {
    assert!(
        workflow.contains(needle),
        "release workflow must contain {needle:?}"
    );
}

#[test]
fn release_workflow_binds_reviewed_source_to_verifiable_evidence() {
    let workflow = release_workflow();

    for required in [
        "pull_request:",
        "workflow_dispatch:",
        "GITHUB_REF_PROTECTED",
        "refs/heads/main",
        "cargo fmt --check",
        "cargo test --locked --workspace",
        "cargo clippy --locked --workspace --all-targets -- -D warnings",
        "cargo build --locked --release",
        "cargo metadata --locked --format-version=1",
        "sha256sum",
        "spdx-json",
        "actions/attest@",
        "sbom-path:",
        "actions/upload-artifact@",
        "persist-credentials: false",
    ] {
        require(&workflow, required);
    }

    assert!(
        !workflow.contains("@main") && !workflow.contains("@master"),
        "release actions must be pinned to immutable revisions"
    );
}
