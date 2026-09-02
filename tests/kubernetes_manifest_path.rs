//! Repository contract for the canonical Kubernetes deployment manifest path.

use std::fs;
use std::path::{Path, PathBuf};

/// Text source extensions whose contents may carry repository path references.
const TEXT_EXTENSIONS: &[&str] = &[
    "css", "html", "js", "json", "jsx", "md", "py", "rs", "sh", "toml", "ts", "tsx", "txt", "yaml",
    "yml",
];

/// Files whose legacy-path references are necessarily historical or negative fixtures.
///
/// Operational documentation is intentionally excluded from this file-level allowlist:
/// migration guidance must justify each legacy-path occurrence on the exact line where it
/// appears so a later copy/paste command cannot silently escape the repository contract.
const LEGACY_REFERENCE_FILE_ALLOWLIST: &[&str] = &["CHANGELOG.md", "tests/deployment_manifest.rs"];

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
                if candidate
                    .file_name()
                    .is_some_and(|name| name == ".git" || name == "target")
                {
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

/// Decide whether one legacy-path occurrence is explicit migration history rather than
/// an operational reference that could be copied into a deployment command.
fn legacy_reference_is_allowed(
    relative: &Path,
    line: &str,
    legacy_reference: &str,
    canonical_reference: &str,
) -> bool {
    if LEGACY_REFERENCE_FILE_ALLOWLIST
        .iter()
        .any(|allowed| relative == Path::new(allowed))
    {
        return true;
    }

    if relative != Path::new("docs/deployment/production.md") {
        return false;
    }

    let normalized = line.to_ascii_lowercase();
    let explicit_migration = normalized.contains("path changed from")
        && line.contains(legacy_reference)
        && line.contains(canonical_reference);
    let explicit_rollback = normalized.contains("rollback")
        && normalized.contains("repository version before this path migration")
        && line.contains(legacy_reference);

    explicit_migration || explicit_rollback
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
    let canonical_reference = ["deploy/kubernetes/", canonical_name.as_str()].concat();
    let stale_references = text_source_files(repository)
        .into_iter()
        .flat_map(|path| {
            let relative = path.strip_prefix(repository).unwrap_or(&path).to_path_buf();
            let content = fs::read_to_string(&path).unwrap_or_default();
            let legacy_reference = legacy_reference.clone();
            let canonical_reference = canonical_reference.clone();

            content
                .lines()
                .enumerate()
                .filter_map(move |(index, line)| {
                    (line.contains(&legacy_reference)
                        && !legacy_reference_is_allowed(
                            &relative,
                            line,
                            &legacy_reference,
                            &canonical_reference,
                        ))
                    .then(|| format!("{}:{}", relative.display(), index + 1))
                })
        })
        .collect::<Vec<_>>();

    assert!(
        stale_references.is_empty(),
        "the legacy Kubernetes manifest path is still referenced outside explicit migration history by: {}",
        stale_references.join(", ")
    );
}

#[test]
fn production_guide_allows_only_explicit_legacy_path_history() {
    let relative = Path::new("docs/deployment/production.md");
    let legacy_reference = ["deploy/kubernetes/", "waf-ids-ai-soc", ".yaml"].concat();
    let canonical_reference = ["deploy/kubernetes/", "wardnet", ".yaml"].concat();
    let migration_history = format!(
        "The repository path changed from `{legacy_reference}` to `{canonical_reference}`."
    );
    let rollback_history = format!(
        "Rollback to a repository version before this path migration uses `{legacy_reference}`."
    );
    let stale_apply_command = format!("kubectl apply -f {legacy_reference}");
    let stale_gitops_instruction = format!("Copy {legacy_reference} into the GitOps repository.");

    assert!(legacy_reference_is_allowed(
        relative,
        &migration_history,
        &legacy_reference,
        &canonical_reference,
    ));
    assert!(legacy_reference_is_allowed(
        relative,
        &rollback_history,
        &legacy_reference,
        &canonical_reference,
    ));
    assert!(!legacy_reference_is_allowed(
        relative,
        &stale_apply_command,
        &legacy_reference,
        &canonical_reference,
    ));
    assert!(!legacy_reference_is_allowed(
        relative,
        &stale_gitops_instruction,
        &legacy_reference,
        &canonical_reference,
    ));
}
