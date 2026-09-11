use std::{fs, path::Path};

#[test]
fn codegraph_guidance_matches_repository_state() {
    let guidance = fs::read_to_string("AGENTS.md").expect("AGENTS.md must be readable");
    let normalized_guidance = guidance.to_ascii_lowercase();
    let codegraph_present = Path::new(".codegraph").exists();

    if codegraph_present {
        assert!(
            !guidance.contains("There is no `.codegraph/` index in this repo"),
            "AGENTS.md must not deny the live .codegraph repository capability"
        );
        assert!(
            normalized_guidance.contains("prefer codegraph"),
            "AGENTS.md must direct agents to the repository's CodeGraph capability"
        );
    }
}
