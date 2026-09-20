use std::fs;

fn threat_model() -> String {
    fs::read_to_string("docs/security/threat-model.md")
        .unwrap_or_else(|error| panic!("failed to read threat model: {error}"))
}

#[test]
fn agent_artifact_admission_threats_and_foreign_owner_boundaries_remain_explicit() {
    let threat_model = threat_model();

    for marker in [
        "Agent Artifact Admission",
        "artifact digest",
        "admission receipt",
        "quarantine-sandbox-runtime",
        "EgressWeave",
        "contextual-orchestrator",
        "appguardrail",
        "fail closed",
        "mutable branch",
    ] {
        assert!(
            threat_model.contains(marker),
            "threat model must retain the code-current security marker {marker:?}"
        );
    }

    for threat in [
        "Artifact identity substitution",
        "Forged or stale foreign-owner evidence",
        "Admission-authority confusion",
    ] {
        assert!(
            threat_model.contains(threat),
            "threat model must retain the Agent Artifact Admission threat {threat:?}"
        );
    }
}
