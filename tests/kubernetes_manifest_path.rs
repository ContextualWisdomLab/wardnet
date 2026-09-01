//! Repository contract for the canonical Kubernetes deployment manifest path.

use std::fs;
use std::path::{Path, PathBuf};

/// Text source extensions whose contents may carry repository path references.
const TEXT_EXTENSIONS: &[&str] = &[
    "css", "html", "js", "json", "jsx", "md", "py", "rs", "sh", "toml", "ts", "tsx",
    "txt", "yaml", "yml",
];

/// Files allowed to mention the retired path as migration history or a negative
/// regression fixture. Operational source and documentation must use the new path.
const LEGACY_REFERENCE_ALLOWLIST: &[&str] = &[
    "CHANGELOG.md",
    "docs/deployment/production.md",
    "tests/deployment_manifest.rs",
];

/// Walk text-bearing source files without relying on platform-specific tooling.
fn text_source_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            if candidate.is_dir() {
                if candidate.file_name().is_some_and(|name| name == ".git" || name == "target") {
                    continue;
                }
                pending.push(candidate);
                continue;
            }
            if candidate
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| TEXT_EXTENSIONS.contains(&extension))
            {
                files.push(candidate);
            }
        }
    }

    files
}

#[test]
fn kubernetes_manifest_uses_the_wardnet_filename_only() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let deployment_directory = repository.join("deploy/kubernetes");
    let canonical_name = ["wardnet", ".yaml"].concat();
    let legacy_name = ["waf-ids-ai-soc", ".yaml"].concat();

    assert!(
        deployment_directory.join(&canonical_name).is_file(),
        "the hardened production manifest must be published as deploy/kubernetes/{canonical_name}"
    );
    assert!(
        !deployment_directory.join(&legacy_name).exists(),
        "the pre-rename Kubernetes manifest path must be removed"
    );

    let legacy_reference = ["deploy/kubernetes/", legacy_name.as_str()].concat();
    let stale_references = text_source_files(repository)
        .into_iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(repository).unwrap_or(&path);
            if LEGACY_REFERENCE_ALLOWLIST
                .iter()
                .any(|allowed| relative == Path::new(allowed))
            {
                return None;
            }
            let content = fs::read_to_string(&path).ok()?;
            content
                .contains(&legacy_reference)
                .then(|| relative.display().to_string())
        })
        .collect::<Vec<_>>();

    assert!(
        stale_references.is_empty(),
        "the legacy Kubernetes manifest path is still referenced by: {}",
        stale_references.join(", ")
    );
}
