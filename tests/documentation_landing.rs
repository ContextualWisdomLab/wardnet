//! Repository contract for links published by the GitHub Pages landing source.

use std::fs;
use std::path::Path;

const REPOSITORY_ROOT_README_URL: &str = "https://github.com/ContextualWisdomLab/wardnet#readme";
const REPOSITORY_BLOB_PREFIX: &str = "https://github.com/ContextualWisdomLab/wardnet/blob/main/";
const REPOSITORY_TREE_PREFIX: &str = "https://github.com/ContextualWisdomLab/wardnet/tree/main/";

fn repository_target(target: &str) -> Option<(&str, bool)> {
    if let Some(relative) = target.strip_prefix(REPOSITORY_BLOB_PREFIX) {
        Some((relative, false))
    } else if let Some(relative) = target.strip_prefix(REPOSITORY_TREE_PREFIX) {
        Some((relative, true))
    } else {
        None
    }
}

fn validated_repository_relative_path(relative: &str) -> &Path {
    Path::new(relative)
}

#[test]
fn repository_root_readme_target_is_checked() {
    assert_eq!(
        repository_target(REPOSITORY_ROOT_README_URL),
        Some(("README.md", false))
    );
}

#[test]
#[should_panic(expected = "must stay inside repository")]
fn repository_link_rejects_parent_escape() {
    let _ = validated_repository_relative_path("../outside.md");
}

#[test]
fn pages_landing_repository_links_resolve_in_source_tree() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let landing = fs::read_to_string(repository.join("docs/index.md"))
        .expect("docs/index.md must remain readable as the Pages landing source");

    for target in landing
        .split("](")
        .skip(1)
        .filter_map(|candidate| candidate.split(')').next())
    {
        if let Some((relative, is_directory)) = repository_target(target) {
            let candidate = repository.join(validated_repository_relative_path(relative));
            if is_directory {
                assert!(
                    candidate.is_dir(),
                    "Pages landing links to a missing repository directory: {relative}"
                );
            } else {
                assert!(
                    candidate.is_file(),
                    "Pages landing links to a missing repository file: {relative}"
                );
            }
        }
    }
}
