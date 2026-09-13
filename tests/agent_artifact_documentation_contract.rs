use std::fs;

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

#[test]
fn agent_artifact_admission_stays_in_code_current_operator_and_architecture_docs() {
    let architecture = read_repo_file("docs/architecture.md");
    assert!(
        architecture.contains("Agent Artifact Admission"),
        "architecture must name the Wardnet-owned Agent Artifact Admission bounded context"
    );
    assert!(
        architecture.contains("crates/agent-artifact-admission"),
        "architecture must identify the shipped Agent Artifact Admission crate"
    );
    for foreign_owner in [
        "quarantine-sandbox-runtime",
        "EgressWeave",
        "contextual-orchestrator",
        "appguardrail",
    ] {
        assert!(
            architecture.contains(foreign_owner),
            "architecture must preserve the external-owner boundary for {foreign_owner}"
        );
    }

    let claude = read_repo_file("CLAUDE.md");
    assert!(
        claude.contains("crates/agent-artifact-admission"),
        "operator/developer guidance must include the shipped Agent Artifact Admission workspace member"
    );
    assert!(
        !claude.contains("Root Cargo workspace with two members"),
        "workspace guidance must not claim two members after Agent Artifact Admission is present"
    );
    assert!(
        !claude.contains("Both workspace crates use `edition = \"2024\"`"),
        "toolchain guidance must not retain the pre-admission two-crate statement"
    );

    let agents = read_repo_file("AGENTS.md");
    assert!(
        agents.contains("Agent Artifact Admission"),
        "canonical agent guidance must retain Wardnet's Agent Artifact Admission ownership boundary"
    );
}
