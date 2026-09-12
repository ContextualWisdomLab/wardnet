use std::path::Path;

const PRD: &str = include_str!("../docs/product/PRD.md");
const TRD: &str = include_str!("../docs/architecture/TRD.md");
const UML: &str = include_str!("../docs/architecture/wardnet-control-plane.puml");

fn assert_markers(name: &str, document: &str, markers: &[&str]) {
    for marker in markers {
        assert!(
            document.contains(marker),
            "{name} must retain the code-current marker {marker:?}"
        );
    }
}

#[test]
fn canonical_commercial_architecture_documents_are_present_and_owner_bounded() {
    assert!(Path::new("docs/product/PRD.md").is_relative());
    assert!(Path::new("docs/architecture/TRD.md").is_relative());
    assert!(Path::new("docs/architecture/wardnet-control-plane.puml").is_relative());

    assert_markers(
        "PRD",
        PRD,
        &[
            "Gateway and SOC Control Plane",
            "Agent Artifact Admission",
            "security evidence and policy",
            "quarantine-sandbox-runtime",
            "EgressWeave",
            "contextual-orchestrator",
            "appguardrail",
        ],
    );
    assert_markers(
        "TRD",
        TRD,
        &[
            "Rust-first",
            "released contracts only",
            "p95 <= 20 ms",
            "CredentialRegistry",
            "RuntimeConfiguration",
            "SBOM",
            "provenance",
        ],
    );
    assert_markers(
        "UML",
        UML,
        &[
            "@startuml",
            "Wardnet",
            "Agent Artifact Admission",
            "quarantine-sandbox-runtime",
            "EgressWeave",
            "contextual-orchestrator",
            "appguardrail",
            "@enduml",
        ],
    );
}
