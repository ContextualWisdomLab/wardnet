//! Repository contract for links published by the GitHub Pages landing source.

use std::fs;
use std::path::Path;

const REPOSITORY_BLOB_PREFIX: &str = "https://github.com/ContextualWisdomLab/wardnet/blob/main/";
const REPOSITORY_TREE_PREFIX: &str = "https://github.com/ContextualWisdomLab/wardnet/tree/main/";

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
        if let Some(relative) = target.strip_prefix(REPOSITORY_BLOB_PREFIX) {
            assert!(
                repository.join(relative).is_file(),
                "Pages landing links to a missing repository file: {relative}"
            );
        } else if let Some(relative) = target.strip_prefix(REPOSITORY_TREE_PREFIX) {
            assert!(
                repository.join(relative).is_dir(),
                "Pages landing links to a missing repository directory: {relative}"
            );
        }
    }
}
