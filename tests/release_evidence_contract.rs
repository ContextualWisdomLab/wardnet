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

fn section<'a>(workflow: &'a str, start: &str, end: &str) -> &'a str {
    let start_offset = workflow
        .find(start)
        .unwrap_or_else(|| panic!("release workflow must contain section start {start:?}"));
    let end_offset = workflow[start_offset..]
        .find(end)
        .unwrap_or_else(|| panic!("release workflow must contain section end {end:?}"));
    &workflow[start_offset..start_offset + end_offset]
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
        "install -m 0644 Cargo.toml",
        "install -m 0644 Cargo.lock",
        "install -m 0644 rust-toolchain.toml",
        "PACKAGE_DIR=$package",
        "path: ${{ env.PACKAGE_DIR }}",
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

#[test]
fn pull_request_release_build_cannot_mint_attestation_identity() {
    let workflow = release_workflow();
    let build_job = section(
        &workflow,
        "  release-evidence:\n",
        "  attest-release-evidence:\n",
    );

    for forbidden in [
        "id-token: write",
        "attestations: write",
        "artifact-metadata: write",
        "actions/attest@",
    ] {
        assert!(
            !build_job.contains(forbidden),
            "the PR-executable release build job must not carry attestation authority {forbidden:?}"
        );
    }

    let attest_job = workflow
        .split_once("  attest-release-evidence:\n")
        .map(|(_, body)| body)
        .expect("release workflow must isolate protected-main attestation in a separate job");
    for required in [
        "if: github.event_name == 'workflow_dispatch'",
        "needs: release-evidence",
        "id-token: write",
        "attestations: write",
        "actions/download-artifact@",
        "actions/attest@",
    ] {
        assert!(
            attest_job.contains(required),
            "protected-main attestation job must contain {required:?}"
        );
    }
    assert!(
        !attest_job.contains("artifact-metadata: write"),
        "binary/SBOM attestations without linked-artifact registry publishing must not request artifact-metadata write authority"
    );
}

#[test]
fn job_level_configuration_does_not_use_runner_only_context() {
    let workflow = release_workflow();
    let attest_header = section(
        &workflow,
        "  attest-release-evidence:\n",
        "    steps:\n",
    );

    assert!(
        !attest_header.contains("${{ runner."),
        "runner context is step/runtime scoped and must not be referenced from job-level env"
    );
}
