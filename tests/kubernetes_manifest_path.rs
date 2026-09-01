//! Repository path contract for the production Kubernetes manifest.

use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST: &str = include_str!("../deploy/kubernetes/wardnet.yaml");
const CURRENT_MANIFEST_PATH: &str = "deploy/kubernetes/wardnet.yaml";

/// Build the retired filename without embedding it as a searchable repository reference.
fn legacy_manifest_path() -> String {
    ["deploy/kubernetes/", "waf-ids-ai-soc", ".yaml"].concat()
}

/// Collect source-controlled text candidates while excluding generated and VCS directories.
fn repository_text_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("repository directory must be readable") {
            let entry = entry.expect("repository entry must be readable");
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if name != ".git" && name != "target" {
                    pending.push(path);
                }
                continue;
            }
            if matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("md" | "rs" | "toml" | "yml" | "yaml" | "sh")
            ) {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn production_manifest_uses_the_wardnet_path_only() {
    let legacy = legacy_manifest_path();
    assert!(Path::new(CURRENT_MANIFEST_PATH).is_file());
    assert!(!Path::new(&legacy).exists(), "retired manifest path still exists");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in repository_text_files(root) {
        let contents = fs::read_to_string(&path).expect("tracked text candidate must be UTF-8");
        assert!(
            !contents.contains(&legacy),
            "retired Kubernetes manifest path remains referenced by {}",
            path.display()
        );
    }
}

#[test]
fn renamed_manifest_preserves_external_secret_hardening() {
    assert!(!MANIFEST.lines().any(|line| line.trim() == "kind: Secret"));
    assert!(!MANIFEST.contains("replace-with-secret-manager-sync"));
    assert!(MANIFEST.contains("secretKeyRef:"));
    assert!(MANIFEST.contains("optional: false"));
}
