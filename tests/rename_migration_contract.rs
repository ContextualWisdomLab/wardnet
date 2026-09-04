//! Regression contract for the Wardnet rename deployment migration.

use std::fs;
use std::path::Path;

fn repo_file(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

#[test]
fn rename_preserves_local_state_exclusion_and_primary_credentials_name() {
    let dockerignore = repo_file(".dockerignore");
    let claude = repo_file("CLAUDE.md");

    assert!(dockerignore.lines().any(|line| line == "wardnet-state.local.json"));
    assert!(dockerignore.lines().any(|line| line == "waf-ids-state.local.json"));
    assert!(claude.contains(
        "`WARDNET_CREDENTIALS_PATH` (optional JSON bootstrap file for process-local"
    ));
    assert!(claude.contains("`WAF_IDS_CREDENTIALS_PATH` remains a legacy fallback"));
}

#[test]
fn rename_documents_state_and_secret_cutover_before_new_deployment() {
    let migration = repo_file("docs/migrations/wardnet-rename.md");

    for required in [
        "/var/lib/waf-ids-ai-soc",
        "/var/lib/wardnet",
        "waf_ids_state",
        "wardnet_state",
        "waf-ids-ai-soc-state",
        "wardnet-state",
        "waf-ids-ai-soc-admin",
        "wardnet-admin",
        "ADMIN_TOKEN",
    ] {
        assert!(
            migration.contains(required),
            "migration guide must preserve the old/new deployment identity {required}"
        );
    }

    let state_copy = migration
        .find("Copy existing state before starting Wardnet")
        .expect("migration guide must require state migration before startup");
    let deployment_apply = migration
        .find("apply `deploy/kubernetes/wardnet.yaml`")
        .expect("migration guide must name the final Kubernetes apply step");
    assert!(state_copy < deployment_apply);
}

#[test]
fn deployment_regression_tracks_the_renamed_manifest_and_secret() {
    let deployment_test = repo_file("tests/deployment_manifest.rs");

    assert!(deployment_test.contains(
        "include_str!(\"../deploy/kubernetes/wardnet.yaml\")"
    ));
    assert!(!deployment_test.contains(
        "include_str!(\"../deploy/kubernetes/waf-ids-ai-soc.yaml\")"
    ));
    assert!(deployment_test.contains("namespace: \"wardnet\""));
    assert!(deployment_test.contains("secret_name: \"wardnet-admin\""));
}
